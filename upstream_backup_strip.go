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
// repeats a key inside one JSON object (see rejectDuplicateJSONKeys).
var errUpstreamSettingsDuplicateKey = errors.New("admin_settings.json repeats a key inside one JSON object; a backup archives only a sound settings file")

// rejectDuplicateJSONKeys walks the raw token stream of body and refuses
// any JSON object that carries the same key twice, at every nesting level
// (an object inside an array inside an object included). It reports
// nothing about VALUES — the same key in two different objects is normal —
// and never decodes into a map, which is exactly the representation that
// discards the earlier value. Syntax errors are left to the decoder that
// follows; only a duplicate is refused here.
func rejectDuplicateJSONKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var w jsonKeyWalker
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil // io.EOF, or a syntax error the decoder that follows reports
		}
		if dup := w.step(tok); dup {
			return errUpstreamSettingsDuplicateKey
		}
	}
}

// jsonObjectFrame is one open JSON container on the walker's stack: for an
// object, the keys seen so far and whether the next token is a key.
type jsonObjectFrame struct {
	object    bool
	keys      map[string]struct{}
	expectKey bool
}

// jsonKeyWalker tracks the open containers of a token stream and reports a
// key repeated inside one object.
type jsonKeyWalker struct {
	stack []*jsonObjectFrame
}

// step consumes one token and reports true when it is a duplicate key.
func (w *jsonKeyWalker) step(tok json.Token) bool {
	if top := w.top(); top != nil && top.object && top.expectKey {
		return w.stepKeyPosition(top, tok)
	}
	if top := w.top(); top != nil && top.object {
		top.expectKey = true // the value has been consumed, or begins below
	}
	w.stepDelim(tok)
	return false
}

// stepKeyPosition handles a token where an object expects a key: the closing
// brace, or the key itself (a duplicate reports true).
func (w *jsonKeyWalker) stepKeyPosition(top *jsonObjectFrame, tok json.Token) bool {
	if d, ok := tok.(json.Delim); ok && d == '}' {
		w.pop()
		return false
	}
	key, ok := tok.(string)
	if !ok {
		return false // not a key where one is required: a syntax error
	}
	if _, dup := top.keys[key]; dup {
		return true
	}
	top.keys[key] = struct{}{}
	top.expectKey = false
	return false
}

// stepDelim opens or closes a container for a delimiter token.
func (w *jsonKeyWalker) stepDelim(tok json.Token) {
	d, ok := tok.(json.Delim)
	if !ok {
		return
	}
	switch d {
	case '{':
		w.stack = append(w.stack, &jsonObjectFrame{object: true, keys: map[string]struct{}{}, expectKey: true})
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
func refuseCredentialBearingLegacyUpstreams(root map[string]any) error {
	_, prepared := root["upstream_prepared_downgrade"]
	withPassword, unparseable := 0, 0
	if list, ok := root["upstream_proxies"].([]any); ok {
		for _, item := range list {
			raw := ""
			switch v := item.(type) {
			case string:
				raw = v
			case map[string]any:
				raw, _ = v["url"].(string)
			}
			if raw == "" {
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
	if prepared || withPassword > 0 || unparseable > 0 {
		return fmt.Errorf("%w (prepared_downgrade=%t, legacy_urls_with_password=%d, legacy_urls_unparseable=%d)", errUpstreamBackupPreparedDowngrade, prepared, withPassword, unparseable)
	}
	return nil
}
