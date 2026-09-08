package main

// upstream_backup_strip.go — backup secret stripping + restore reporting
// for the Upstream v2 sealed credentials (2F-D, contract C5/C12).
//
// admin_settings.json is the ONLY portable artifact that carries the sealed
// upstream credentials, and its node-local key (.upstream_cred_key) is
// never archived — so an archived copy of the sealed record would be
// ciphertext nobody can unwrap on a restored node and key material the
// operator would have to protect for nothing. Both backup modes (plain and
// encrypted) therefore archive a SANITIZED representation of the settings
// file: every `credential` record under upstream_proxies_v2.entries[] is
// removed and the entry is marked `requiresReplacement: true`, so a restore
// boots each formerly credentialed entry into the DISTINCT durable
// CredentialRequiresReplacement state (ineligible, never sent
// unauthenticated) instead of `none` or `configured`. The manifest records
// `credentialsOmitted: true` unconditionally (the archive never carries
// material). The live file and the live pool are untouched — the sanitizer
// works on the bytes read for packing, never on disk.
//
// The rewrite is a generic-JSON transform (json.Number preserved, every
// other key carried verbatim) so it needs no knowledge of the rest of the
// settings schema and can never drop an unrelated section.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// upstreamSettingsCredentialKeys are the keys a sealed record carries; none
// may survive in an archived settings file (pinned by the RED matrix).
var upstreamSettingsCredentialKeys = []string{`"ciphertext"`, `"keyId"`, `"authorityHash"`}

// stripUpstreamCredentialsFromSettings returns the sanitized representation
// of an admin_settings.json body and the number of credentials removed. A
// body without an upstream_proxies_v2 document is returned unchanged (0).
// A body that is not a JSON object is an error (a corrupt settings file
// must not be archived as if it were sound).
func stripUpstreamCredentialsFromSettings(body []byte) (sanitized []byte, stripped int, err error) {
	// PR-C20 R11-A: a repeated key is refused BEFORE the body is decoded
	// into a map. encoding/json keeps only the LAST value of a repeated
	// key, so a settings object that repeats `upstream_proxies` (a
	// credential-bearing list first, an empty list last), a repeated
	// nested `url`, or a repeated `upstream_proxies_v2` document had the
	// credential gate inspect only the surviving value while the no-op
	// path handed back the ORIGINAL bytes, secret included. A sound
	// settings file never repeats a key at any nesting level.
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, 0, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, 0, fmt.Errorf("admin_settings.json is not a JSON object: %w", err)
	}
	// PR-C19 R10-A: ONE settings object and nothing after it but
	// whitespace. Decode reads a single value and never looks at the
	// remaining bytes, so a credential-free leading object followed by a
	// second value or trailing garbage carrying a plaintext legacy
	// upstream URL was returned unchanged (the no-op path hands back the
	// ORIGINAL body) and packed verbatim while the manifest asserted
	// credentialsOmitted. A body with trailing data is not a sound
	// settings file and is refused before any of it is inspected.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, 0, errors.New("admin_settings.json carries data after the settings object; a backup archives only a sound settings file")
	}
	// PR-C17 R8-A: a settings file in the prepared-downgrade state (after
	// `--prepare-downgrade`, before the next boot re-migrates) carries NO v2
	// document and the UNSEALED passwords in the legacy `upstream_proxies`
	// URLs by design — a pre-v2 file never booted on this binary can carry
	// them too. An archive never carries material and the manifest asserts
	// credentialsOmitted unconditionally, so such a body is REFUSED rather
	// than packed verbatim: the operator boots this binary once (it
	// re-migrates and seals the credentials) or completes the downgrade
	// before taking a backup. Counts only — never a URL or a password.
	if err := refuseCredentialBearingLegacyUpstreams(root); err != nil {
		return nil, 0, err
	}
	doc, ok := root["upstream_proxies_v2"].(map[string]any)
	if !ok {
		return body, 0, nil
	}
	entries, ok := doc["entries"].([]any)
	if !ok {
		return body, 0, nil
	}
	for i := range entries {
		e, ok := entries[i].(map[string]any)
		if !ok {
			continue
		}
		if _, has := e["credential"]; has {
			delete(e, "credential")
			e["requiresReplacement"] = true
			stripped++
		}
	}
	if stripped == 0 {
		return body, 0, nil
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("re-serialize sanitized admin_settings.json: %w", err)
	}
	for _, k := range upstreamSettingsCredentialKeys {
		if bytes.Contains(out, []byte(k)) {
			return nil, 0, fmt.Errorf("sanitized admin_settings.json still carries %s", strings.Trim(k, `"`))
		}
	}
	return out, stripped, nil
}

// errUpstreamSettingsDuplicateKey is the refusal for a settings body that
// repeats a key inside one JSON object — exactly, or differing only by
// case (see rejectDuplicateJSONKeys).
var errUpstreamSettingsDuplicateKey = errors.New("admin_settings.json repeats a key inside one JSON object; a backup archives only a sound settings file")

// errUpstreamSettingsKeyCase is the refusal for a settings body that spells
// a key the sanitizer reads in a case variant the settings loader would
// still accept (see sanitizerReadKeys).
var errUpstreamSettingsKeyCase = errors.New("admin_settings.json spells an upstream key in a case variant; a backup archives only a sound settings file")

// sanitizerReadKeys are the keys the sanitizer reads by exact spelling.
// PR-C22 R13-A: encoding/json matches struct fields CASE-INSENSITIVELY, so
// the settings loader reads `UPSTREAM_PROXIES` or `Upstream_Proxies_V2`
// exactly as the canonical spelling while an exact map lookup treats the
// variant as absent — a credential-bearing list under a variant bypassed
// the gate, a sealed record under a variant was never stripped, and a
// variant prepared-downgrade marker never refused. Any key, at any depth,
// that equals one of these under case folding without being its exact
// spelling refuses the archive: the appliance never writes a variant, so
// one is a hand-edited file the sanitizer cannot read as the loader does.
var sanitizerReadKeys = []string{
	"upstream_proxies", "upstream_proxies_v2", "upstream_prepared_downgrade",
	"entries", "credential", "url", "requiresReplacement",
	"ciphertext", "keyId", "authorityHash",
}

// rejectDuplicateJSONKeys walks the raw token stream of body and refuses
// any JSON object that carries the same key twice, at every nesting level
// (an object inside an array inside an object included), and any key that
// is a case variant of one the sanitizer reads. Two keys that differ only
// by case are a collision too: encoding/json resolves one to the struct
// field by a preference rule the sanitizer cannot see. It reports nothing
// about VALUES — the same key in two different objects is normal — and
// never decodes into a map, which is exactly the representation that
// discards the earlier value. Syntax errors are left to the decoder that
// follows.
func rejectDuplicateJSONKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var w jsonKeyWalker
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil // io.EOF, or a syntax error the decoder that follows reports
		}
		if err := w.step(tok); err != nil {
			return err
		}
	}
}

// jsonObjectFrame is one open JSON container on the walker's stack: for an
// object, the keys seen so far and whether the next token is a key.
type jsonObjectFrame struct {
	object    bool
	keys      []string
	expectKey bool
}

// jsonKeyWalker tracks the open containers of a token stream and reports a
// key repeated inside one object.
type jsonKeyWalker struct {
	stack []*jsonObjectFrame
}

// step consumes one token and reports a duplicate or case-variant key.
func (w *jsonKeyWalker) step(tok json.Token) error {
	if top := w.top(); top != nil && top.object && top.expectKey {
		return w.stepKeyPosition(top, tok)
	}
	if top := w.top(); top != nil && top.object {
		top.expectKey = true // the value has been consumed, or begins below
	}
	w.stepDelim(tok)
	return nil
}

// stepKeyPosition handles a token where an object expects a key: the closing
// brace, or the key itself (a duplicate under case folding, or a case
// variant of a key the sanitizer reads, is refused).
func (w *jsonKeyWalker) stepKeyPosition(top *jsonObjectFrame, tok json.Token) error {
	if d, ok := tok.(json.Delim); ok && d == '}' {
		w.pop()
		return nil
	}
	key, ok := tok.(string)
	if !ok {
		return nil // not a key where one is required: a syntax error
	}
	for _, seen := range top.keys {
		if strings.EqualFold(seen, key) {
			return errUpstreamSettingsDuplicateKey
		}
	}
	for _, name := range sanitizerReadKeys {
		if key != name && strings.EqualFold(key, name) {
			return errUpstreamSettingsKeyCase
		}
	}
	top.keys = append(top.keys, key)
	top.expectKey = false
	return nil
}

// stepDelim opens or closes a container for a delimiter token.
func (w *jsonKeyWalker) stepDelim(tok json.Token) {
	d, ok := tok.(json.Delim)
	if !ok {
		return
	}
	switch d {
	case '{':
		w.stack = append(w.stack, &jsonObjectFrame{object: true, expectKey: true})
	case '[':
		w.stack = append(w.stack, &jsonObjectFrame{})
	case '}', ']':
		w.pop()
	}
}

func (w *jsonKeyWalker) top() *jsonObjectFrame {
	if len(w.stack) == 0 {
		return nil
	}
	return w.stack[len(w.stack)-1]
}

func (w *jsonKeyWalker) pop() {
	if len(w.stack) > 0 {
		w.stack = w.stack[:len(w.stack)-1]
	}
}

// countUpstreamCredentialsRequiringReplacement counts the entries an
// archived admin_settings.json would boot into requiresReplacement (the
// restore dry-run's exact count). A body without the document counts 0.
func countUpstreamCredentialsRequiringReplacement(body []byte) int {
	var s struct {
		V2 *struct {
			Entries []struct {
				RequiresReplacement bool `json:"requiresReplacement"`
			} `json:"entries"`
		} `json:"upstream_proxies_v2"`
	}
	if err := json.Unmarshal(body, &s); err != nil || s.V2 == nil {
		return 0
	}
	n := 0
	for _, e := range s.V2.Entries {
		if e.RequiresReplacement {
			n++
		}
	}
	return n
}

// errUpstreamBackupPreparedDowngrade is the refusal for a settings file that
// holds credential material in its legacy upstream list (see
// refuseCredentialBearingLegacyUpstreams).
var errUpstreamBackupPreparedDowngrade = errors.New("admin_settings.json carries upstream credential material in its legacy upstream_proxies list (prepared-downgrade state, or a pre-v2 file never booted on this binary); an archive never carries credential material — boot this binary once so the credentials are re-migrated and sealed, or complete the downgrade, then back up")

// refuseCredentialBearingLegacyUpstreams refuses a settings body whose
// legacy upstream_proxies list carries a password in any URL, or that
// carries the prepared-downgrade marker (the mid-transition predecessor
// shape). The message carries counts only.
//
// PR-C18 R9-A: a legacy URL the sanitizer cannot READ is refused too. The
// only question this gate answers is "does this URL carry a password?",
// and an unparseable URL (a malformed escape in the password itself, a
// scheme-less `user:pw@host` spelling that parses as an OPAQUE URL with no
// host) cannot answer it — treating a parse failure as "no password" let
// the material through verbatim while the manifest asserted
// credentialsOmitted. Fail CLOSED: every URL in the list must parse to an
// absolute URL with a host, and none may carry a password; anything else
// is counted as unparseable and refuses the archive.
//
// PR-C21 R12-A: the CONTAINER shape is part of what the gate reads. The
// persisted shape of AdminSettings.UpstreamProxies is an array of objects
// each carrying a `url` string, and the settings loader can read nothing
// else — so a present `upstream_proxies` that is not an array, an item
// that is not an object, an object with no `url`, or a `url` that is not
// a non-empty string is a settings file the gate cannot inspect, and it
// used to be SKIPPED (a type assertion that silently failed) with the
// material inside it archived verbatim. Every such shape now fails the
// backup closed, counted as malformed.
func refuseCredentialBearingLegacyUpstreams(root map[string]any) error {
	_, prepared := root["upstream_prepared_downgrade"]
	withPassword, unparseable, malformed := 0, 0, 0
	if rawList, present := root["upstream_proxies"]; present {
		list, ok := rawList.([]any)
		if !ok {
			malformed++
		}
		for _, item := range list {
			raw, ok := legacyUpstreamItemURL(item)
			if !ok {
				malformed++
				continue
			}
			u, err := url.Parse(strings.TrimSpace(raw))
			switch {
			case err != nil, u.Opaque != "", u.Host == "":
				unparseable++
			case u.User != nil:
				if _, has := u.User.Password(); has {
					withPassword++
				}
			}
		}
	}
	if prepared || withPassword > 0 || unparseable > 0 || malformed > 0 {
		return fmt.Errorf("%w (prepared_downgrade=%t, legacy_urls_with_password=%d, legacy_urls_unparseable=%d, legacy_items_malformed=%d)", errUpstreamBackupPreparedDowngrade, prepared, withPassword, unparseable, malformed)
	}
	return nil
}

// legacyUpstreamItemURL returns the `url` of one persisted legacy upstream
// item — an object whose `url` is a non-empty string — and false for every
// other shape.
func legacyUpstreamItemURL(item any) (string, bool) {
	obj, ok := item.(map[string]any)
	if !ok {
		return "", false
	}
	raw, ok := obj["url"].(string)
	if !ok || raw == "" {
		return "", false
	}
	return raw, true
}
