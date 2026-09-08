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
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, 0, fmt.Errorf("admin_settings.json is not a JSON object: %w", err)
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
func refuseCredentialBearingLegacyUpstreams(root map[string]any) error {
	_, prepared := root["upstream_prepared_downgrade"]
	withPassword := 0
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
			if err != nil || u.User == nil {
				continue
			}
			if _, has := u.User.Password(); has {
				withPassword++
			}
		}
	}
	if prepared || withPassword > 0 {
		return fmt.Errorf("%w (prepared_downgrade=%t, legacy_urls_with_password=%d)", errUpstreamBackupPreparedDowngrade, prepared, withPassword)
	}
	return nil
}
