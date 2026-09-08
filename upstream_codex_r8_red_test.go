package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

// PR-C17 RED matrix — the eighth Codex round on the Batch 2 PR head
// (c17789bc), written against that tree BEFORE any correction.
//
//   R8-A  a backup taken in the prepared-downgrade state (after
//         `--prepare-downgrade`, before the next boot re-migrates) packs the
//         legacy `upstream_proxies` URLs — which then carry the unsealed
//         passwords by design — VERBATIM, while the manifest asserts
//         credentialsOmitted: true. The same holds for any settings file
//         whose legacy list carries a password (a pre-v2 file never booted
//         on this binary). An archive must never carry material: the
//         sanitizer must refuse such a body.
//   R8-B  validateHostLabels checked emptiness only: a label longer than
//         63 octets, or a name longer than 253, is accepted by the IDNA
//         Lookup profile (no DNS-length verification) and was persisted and
//         published as an eligible parent that standard DNS cannot resolve.

const r8Canary = "hunter2-R8-canary"

func r8PreparedDowngradeSettings() []byte {
	return []byte(`{
  "upstream_proxies": [{"url": "http://svc:` + r8Canary + `@parent-a.example:3128"}],
  "upstream_proxies_saved": true,
  "upstream_prepared_downgrade": {"at": "2026-09-08T20:00:00Z", "targetSchema": 1, "fromSchema": 2, "credentials": 1}
}`)
}

func TestUpstreamR8_BackupStripRefusesPreparedDowngradeCredentials(t *testing.T) {
	out, stripped, err := stripUpstreamCredentialsFromSettings(r8PreparedDowngradeSettings())
	if err == nil {
		t.Fatalf("prepared-downgrade settings with a legacy password were accepted for archiving (stripped=%d)", stripped)
	}
	if bytes.Contains(out, []byte(r8Canary)) {
		t.Fatalf("the password survived into the archive body")
	}
}

func TestUpstreamR8_BackupStripRefusesLegacyPasswordWithoutMarker(t *testing.T) {
	body := []byte(`{"upstream_proxies": [{"url": "http://svc:` + r8Canary + `@parent-a.example:3128"}], "upstream_proxies_saved": true}`)
	out, _, err := stripUpstreamCredentialsFromSettings(body)
	if err == nil {
		t.Fatalf("a legacy list carrying a password was accepted for archiving")
	}
	if bytes.Contains(out, []byte(r8Canary)) {
		t.Fatalf("the password survived into the archive body")
	}
}

func TestUpstreamR8_BackupStripKeepsPasswordFreeLegacyList(t *testing.T) {
	body := []byte(`{"upstream_proxies": [{"url": "http://svc@parent-a.example:3128"}], "upstream_proxies_saved": true}`)
	out, stripped, err := stripUpstreamCredentialsFromSettings(body)
	if err != nil || stripped != 0 || !bytes.Equal(out, body) {
		t.Fatalf("a password-free legacy list must archive unchanged: err=%v stripped=%d", err, stripped)
	}
}

func TestUpstreamR8_NormalizeEnforcesDNSLengths(t *testing.T) {
	long := strings.Repeat("a", 64) + ".example"
	if _, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: long, Port: 3128}); err == nil {
		t.Errorf("a 64-octet label was accepted")
	}
	okLabel := strings.Repeat("a", 63) + ".example"
	if _, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: okLabel, Port: 3128}); err != nil {
		t.Errorf("a 63-octet label was refused: %v", err)
	}
	// 4 x 63 + 3 dots = 255 octets: over the 253-octet name limit with every
	// label individually valid.
	tooLong := strings.Repeat(strings.Repeat("b", 63)+".", 3) + strings.Repeat("b", 63)
	if _, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: tooLong, Port: 3128}); err == nil {
		t.Errorf("a 255-octet name was accepted")
	}
	// 3 x 63 + 61 + 3 dots = 253 octets: the limit itself is fine.
	atLimit := strings.Repeat(strings.Repeat("c", 63)+".", 3) + strings.Repeat("c", 61)
	if _, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: atLimit, Port: 3128}); err != nil {
		t.Errorf("a 253-octet name was refused: %v", err)
	}
	// An IDNA label is judged on its A-label (post-mapping) length.
	uni := strings.Repeat("ü", 60) + ".example"
	if _, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: uni, Port: 3128}); err == nil {
		t.Errorf("an IDNA label whose A-label exceeds 63 octets was accepted")
	}
}

func TestUpstreamR8_CreateRefusesOverlongLabel(t *testing.T) {
	upEnv(t)
	long := strings.Repeat("a", 64) + ".example"
	rec := upReq(t, "POST", "/api/upstream/entries", `{"scheme":"http","host":"`+long+`","port":3128,"revision":1}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create answered %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := upJSON(t, rec)["code"]; got != "invalid_entry" {
		t.Fatalf("code %v, want invalid_entry", got)
	}
}
