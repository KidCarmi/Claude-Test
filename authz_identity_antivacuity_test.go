package main

// Controls for the identity-attribution gates in authz_identity_ingress_test.go.
//
// Those gates assert a NEGATIVE ("no log entry for this host carries an
// identity"). A negative assertion over a filtered window is vacuously true
// when the window holds nothing matching, so on its own it cannot distinguish
//
//	the spoofed identity never reached log attribution      (the property)
//
// from
//
//	the request under test produced no observation at all   (proves nothing)
//
// and it reports PASS for both. These controls pin the repair from both ends:
// a POSITIVE control proving the real fixture does emit the observation the
// gates depend on, and NEGATIVE controls proving the assertion FAILS when that
// observation is absent — driven through the assertion's own failure path, not
// re-implemented beside it.

import (
	"fmt"
	"net/url"
	"testing"
)

// recordingT captures what the assertion under test reports, so a control can
// require a FAILURE without failing itself.
type recordingT struct{ errs []string }

func (r *recordingT) Helper() {}
func (r *recordingT) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}
func (r *recordingT) failed() bool { return len(r.errs) > 0 }
func (r *recordingT) joined() string {
	out := ""
	for _, e := range r.errs {
		out += e + "\n"
	}
	return out
}

// TestAntiVacuity_FixtureReallyEmitsTheObservation is the POSITIVE control: it
// drives the same spoofed request the ingress gates drive and proves the
// request-log window actually contains an entry for the backend host. Without
// this, the anti-vacuity guard in assertNoIdentityAttributionIn would be an
// assertion about a fixture nobody had checked; with it, the guard is known to
// be satisfiable by the real path rather than merely strict.
func TestAntiVacuity_FixtureReallyEmitsTheObservation(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), []PolicyRule{{
		Priority: 1, Name: "alice-allow", DestFQDN: "*", SourceIdentity: "alice", Action: ActionAllow,
	}})
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })

	prev := logGet()
	spoofedGet(t, proxyURL, backend.URL+"/", "alice")
	if cb.hitCount() != 0 {
		t.Fatalf("spoofed-identity request reached upstream %d times, want 0", cb.hitCount())
	}

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	window := logEntriesSince(prev)
	observed := 0
	for i := range window { // index-based: LogEntry is a large struct (rangeValCopy)
		if window[i].Host == u.Host {
			observed++
		}
	}
	if observed == 0 {
		t.Fatalf("the ingress fixture produced NO request-log entry for %s — the identity-attribution gates would scan an empty window and pass vacuously", u.Host)
	}

	// The same window must also satisfy the real assertion, with no failures:
	// the fixture is both observable and correctly unattributed.
	rec := &recordingT{}
	assertNoIdentityAttributionIn(rec, u.Host, window)
	if rec.failed() {
		t.Fatalf("assertion failed on a healthy fixture window (%d entries for %s):\n%s", observed, u.Host, rec.joined())
	}
}

// TestAntiVacuity_AssertionFailsWhenTheObservationIsMissing is the NEGATIVE
// control: it suppresses the observation the gate depends on and requires the
// assertion to FAIL. Before the anti-vacuity guard this window passed, which is
// exactly the defect — an assertion that certifies "no forbidden attribution"
// after looking at nothing.
func TestAntiVacuity_AssertionFailsWhenTheObservationIsMissing(t *testing.T) {
	const dest = "backend.test:9999"

	cases := []struct {
		name   string
		window []LogEntry
	}{
		{"empty window", nil},
		{"observation deleted, unrelated hosts remain", []LogEntry{
			{Host: "other.test:1111", Identity: ""},
			{Host: "elsewhere.test:2222", Identity: "bob"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingT{}
			assertNoIdentityAttributionIn(rec, dest, tc.window)
			if !rec.failed() {
				t.Fatalf("assertion PASSED on a window carrying no observation for %s — it must not certify the absence of evidence as evidence of absence", dest)
			}
			if !containsAll(rec.joined(), []string{"no request-log entry", dest}) {
				t.Errorf("failure did not name the missing observation for %s:\n%s", dest, rec.joined())
			}
		})
	}
}

// TestAntiVacuity_AssertionStillCatchesForbiddenAttribution proves the guard
// did not replace the original property: an observation that IS present and
// carries a client-controlled identity must still fail, and must fail for the
// attribution reason rather than the anti-vacuity one.
func TestAntiVacuity_AssertionStillCatchesForbiddenAttribution(t *testing.T) {
	const dest = "backend.test:9999"

	rec := &recordingT{}
	assertNoIdentityAttributionIn(rec, dest, []LogEntry{
		{Host: dest, Identity: "alice"},
		{Host: "other.test:1111", Identity: ""},
	})
	if !rec.failed() {
		t.Fatalf("assertion PASSED on an entry for %s attributed to a spoofed identity", dest)
	}
	if !containsAll(rec.joined(), []string{"attributed to identity", "alice"}) {
		t.Errorf("failure did not name the forbidden attribution:\n%s", rec.joined())
	}
	if containsAll(rec.joined(), []string{"anti-vacuity"}) {
		t.Errorf("a present-but-attributed observation must not report the anti-vacuity failure:\n%s", rec.joined())
	}
}

// TestAntiVacuity_AssertionPassesOnAPresentUnattributedObservation is the
// pass-side control: the assertion must stay satisfiable, or the gates it
// backs would be unfailable in the opposite direction.
func TestAntiVacuity_AssertionPassesOnAPresentUnattributedObservation(t *testing.T) {
	const dest = "backend.test:9999"

	rec := &recordingT{}
	assertNoIdentityAttributionIn(rec, dest, []LogEntry{
		{Host: dest, Identity: ""},
		{Host: "other.test:1111", Identity: "bob"}, // a different host is not this gate's business
	})
	if rec.failed() {
		t.Fatalf("assertion failed on a present, unattributed observation for %s:\n%s", dest, rec.joined())
	}
}
