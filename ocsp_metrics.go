package main

// ocsp_metrics.go — CHAOS-65: the revocation checker's /metrics exposition.
//
// Before this, the ONLY surface for OCSP was `GET /api/ocsp`: an admin JSON
// blob nothing scrapes. Nothing an alerting rule could evaluate existed for a
// control whose failure mode is either "every HTTPS connection to an upstream
// is being refused" (a fail-closed storm) or "revoked certificates are being
// accepted" — the two outcomes that most deserve a page.
//
// Emission rule, per this register's standing convention (socks5_health.go,
// cluster_ca_health.go, dns_health.go): the series are written ONLY when the
// checker is enabled. A `culvert_ocsp_fail_closed_total 0` on a node that never
// turned revocation checking on is indistinguishable from a healthy one, and
// the useful alerting rules here are rate-based — so a permanent flat zero from
// every appliance in the fleet is noise that trains operators to ignore the
// series.

import (
	"fmt"
	"strings"
)

// ocspWritePrometheus appends the culvert_ocsp_* series. Reads live counters at
// scrape time; no hot-path cost.
func ocspWritePrometheus(w *strings.Builder) {
	if !globalOCSP.Enabled() {
		return
	}

	w.WriteString("\n# HELP culvert_ocsp_enabled Whether upstream certificate revocation checking is enabled (always 1 when any culvert_ocsp_* series is present)\n")
	w.WriteString("# TYPE culvert_ocsp_enabled gauge\nculvert_ocsp_enabled 1\n")

	w.WriteString("\n# HELP culvert_ocsp_revoked_total Peer certificates an OCSP responder confirmed as revoked\n")
	w.WriteString("# TYPE culvert_ocsp_revoked_total counter\n")
	fmt.Fprintf(w, "culvert_ocsp_revoked_total %d\n", globalOCSP.RevokedTotal())

	w.WriteString("\n# HELP culvert_ocsp_fail_closed_total Handshakes refused because no responder returned a usable, affirmative verdict. A sustained rate is a responder or egress outage, not a revocation wave\n")
	w.WriteString("# TYPE culvert_ocsp_fail_closed_total counter\n")
	fmt.Fprintf(w, "culvert_ocsp_fail_closed_total %d\n", globalOCSP.FailClosedTotal())

	w.WriteString("\n# HELP culvert_ocsp_cache_entries Verdicts currently cached, keyed by RFC 6960 CertID\n")
	w.WriteString("# TYPE culvert_ocsp_cache_entries gauge\n")
	fmt.Fprintf(w, "culvert_ocsp_cache_entries %d\n", globalOCSP.CacheLen())

	// One labelled series rather than four names: every value here is a
	// response that was DISCARDED, and the label is the bounded reason class.
	// `not_for_certificate` is the one to alert on — it means something is
	// answering with responses borrowed from other certificates, which is the
	// revocation-bypass shape CHAOS-65 closed.
	w.WriteString("\n# HELP culvert_ocsp_response_rejected_total OCSP responses discarded without producing a verdict, by reason\n")
	w.WriteString("# TYPE culvert_ocsp_response_rejected_total counter\n")
	fmt.Fprintf(w, "culvert_ocsp_response_rejected_total{reason=\"not_for_certificate\"} %d\n", globalOCSP.NotForCertificateTotal())
	fmt.Fprintf(w, "culvert_ocsp_response_rejected_total{reason=\"stale\"} %d\n", globalOCSP.StaleTotal())
	fmt.Fprintf(w, "culvert_ocsp_response_rejected_total{reason=\"unknown_status\"} %d\n", globalOCSP.UnknownTotal())
	fmt.Fprintf(w, "culvert_ocsp_response_rejected_total{reason=\"responder_blocked\"} %d\n", globalOCSP.ResponderBlockedTotal())

	w.WriteString("\n# HELP culvert_ocsp_responders_truncated_total Certificates whose AIA responder list exceeded the cap and was truncated. Sustained growth means something is presenting certificates built to amplify outbound requests\n")
	w.WriteString("# TYPE culvert_ocsp_responders_truncated_total counter\n")
	fmt.Fprintf(w, "culvert_ocsp_responders_truncated_total %d\n", globalOCSP.RespondersTruncatedTotal())

	w.WriteString("\n# HELP culvert_ocsp_singleflight_joined_total Handshakes that waited on another handshake's in-flight responder query instead of starting their own\n")
	w.WriteString("# TYPE culvert_ocsp_singleflight_joined_total counter\n")
	fmt.Fprintf(w, "culvert_ocsp_singleflight_joined_total %d\n", globalOCSP.SingleFlightJoinedTotal())

	// The coverage gauge is the point of CHAOS-65's OCSP-8 row: with the
	// counters alone, a checker that is never consulted and a checker that
	// finds nothing wrong produce identical scrapes. This one says which
	// handshake paths reach it at all. Label values are the fixed, bounded
	// set in ocspCoverage().
	w.WriteString("\n# HELP culvert_ocsp_path_checked Whether the named TLS-handshake path consults the revocation checker. ssl_inspect_origin reading 0 means inspected HTTPS is NOT revocation-checked (CHAOS-65 OCSP-8)\n")
	w.WriteString("# TYPE culvert_ocsp_path_checked gauge\n")
	for _, c := range ocspCoverage() {
		v := 0
		if c.Checked {
			v = 1
		}
		fmt.Fprintf(w, "culvert_ocsp_path_checked{path=%q} %d\n", c.Path, v)
	}
}
