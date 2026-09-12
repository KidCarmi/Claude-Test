package main

// ocsp_coverage_test.go — CHAOS-65 / OCSP-8.
//
// These gates pin the AGREEMENT between what ocspCoverage() claims and what
// the named code paths actually build. They deliberately do NOT pin the gap
// itself: whoever wires the revocation callbacks into the SSL-inspect origin
// handshake should find these tests failing and update the claim in the same
// change, rather than finding a test that demands the gap stay open.

import (
	"crypto/tls"
	"strings"
	"testing"
)

// TestOCSP8_InspectPathCoverageClaimMatchesTheCode is the structural half.
//
// upstreamInspectTLSConfigForMatch is what handleTunnelInspect and
// handleInspectNativeALPN hand to tls.Client for every inspected HTTPS origin
// handshake. If it carries no OCSP callbacks, ocspCoverage() must say the path
// is unchecked; if someone attaches them, it must say the opposite. The two
// answers are compared rather than asserted independently, so the claim cannot
// silently drift away from the wiring.
func TestOCSP8_InspectPathCoverageClaimMatchesTheCode(t *testing.T) {
	cfg := upstreamInspectTLSConfigForMatch("example.com", false, nil)
	if cfg == nil {
		t.Fatal("upstreamInspectTLSConfigForMatch returned nil")
	}
	actuallyChecked := cfg.VerifyPeerCertificate != nil || cfg.VerifyConnection != nil

	claimed, found := false, false
	for _, c := range ocspCoverage() {
		if c.Path == "ssl_inspect_origin" {
			claimed, found = c.Checked, true
		}
	}
	if !found {
		t.Fatal(`ocspCoverage() has no "ssl_inspect_origin" row — every TLS-handshake path must be accounted for`)
	}
	if claimed != actuallyChecked {
		t.Fatalf("coverage claim disagrees with the code: ocspCoverage() says checked=%v, "+
			"but the inspect path's tls.Config has callbacks=%v. Update ocsp_coverage.go "+
			"(and the OCSP-8 register row) in the same change that moves the wiring.",
			claimed, actuallyChecked)
	}
}

// TestOCSP8_UpstreamTransportCoverageClaimMatchesTheCode is the other half:
// ConfigureTLSConfigOCSP is what the two enable paths call, and it is the ONLY
// thing that makes any path checked. A claim of coverage must correspond to it
// actually installing both callbacks.
func TestOCSP8_UpstreamTransportCoverageClaimMatchesTheCode(t *testing.T) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	ConfigureTLSConfigOCSP(cfg)
	installed := cfg.VerifyPeerCertificate != nil && cfg.VerifyConnection != nil

	claimed, found := false, false
	for _, c := range ocspCoverage() {
		if c.Path == "upstream_transport" {
			claimed, found = c.Checked, true
		}
	}
	if !found {
		t.Fatal(`ocspCoverage() has no "upstream_transport" row`)
	}
	if claimed != installed {
		t.Fatalf("coverage claim disagrees with ConfigureTLSConfigOCSP: claimed=%v installed=%v",
			claimed, installed)
	}
}

// TestOCSP8_UncheckedEnforcingPathsExcludesBypass — a bypassed CONNECT tunnel
// is relayed raw, so this proxy never sees the origin certificate and there is
// nothing to revocation-check. Reporting it as a gap would be a false positive
// on a surface whose whole job is to be believed.
func TestOCSP8_UncheckedEnforcingPathsExcludesBypass(t *testing.T) {
	for _, p := range ocspUncheckedEnforcingPaths() {
		if p == "connect_bypass" {
			t.Fatal("connect_bypass must not be reported as a coverage gap — " +
				"a raw relay never terminates TLS, so there is no certificate to check")
		}
	}
}

// TestOCSP8_MetricsAreSilentUntilEnabled — the standing emission rule in this
// register: a flat zero from every appliance that never turned the feature on
// is indistinguishable from a broken one, and trains operators to ignore the
// series. Also asserts the coverage gauge IS emitted once enabled, since it is
// the only signal that separates "found nothing wrong" from "never consulted".
func TestOCSP8_MetricsAreSilentUntilEnabled(t *testing.T) {
	wasEnabled := globalOCSP.Enabled()
	t.Cleanup(func() {
		if wasEnabled {
			globalOCSP.Enable()
		} else {
			globalOCSP.Disable()
		}
	})

	globalOCSP.Disable()
	var off strings.Builder
	ocspWritePrometheus(&off)
	if off.Len() != 0 {
		t.Fatalf("culvert_ocsp_* emitted on a node with revocation checking OFF:\n%s", off.String())
	}

	globalOCSP.Enable()
	var on strings.Builder
	ocspWritePrometheus(&on)
	for _, want := range []string{
		"culvert_ocsp_enabled 1",
		"culvert_ocsp_fail_closed_total",
		`culvert_ocsp_response_rejected_total{reason="not_for_certificate"}`,
		`culvert_ocsp_response_rejected_total{reason="unauthorized_responder"}`,
		`culvert_ocsp_response_rejected_total{reason="malformed"}`,
		`culvert_ocsp_path_checked{path="ssl_inspect_origin"} 0`,
	} {
		if !strings.Contains(on.String(), want) {
			t.Errorf("enabled exposition missing %q:\n%s", want, on.String())
		}
	}
}
