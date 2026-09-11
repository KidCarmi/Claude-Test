package rewrite

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ─── Benchmarks: the per-request header-rewrite path ──────────────────────────
//
// ApplyRequest and ApplyResponse both run on the plain-HTTP forward path
// (proxy_http.go prepareHTTPForward + handleHTTP), so a proxied HTTP request
// pays BOTH — twice per request, on 100% of plain-HTTP traffic.
//
// Two costs are measured separately because they have different shapes:
//
//   - The DISABLED posture (no rewrite rules configured — the default). Nothing
//     is applied, so everything measured here is pure overhead. The parallel
//     variants are the interesting ones: a shared RWMutex read lock is an atomic
//     read-modify-write on ONE word, so it is a throughput CEILING rather than a
//     constant cost, and it gets worse as cores are added.
//   - The ENABLED posture with rules that MISS. An operator writes host-scoped
//     rules and a given request matches at most one of them, so the miss is what
//     the path actually pays (the same reasoning as hostutil's MatchFQDNNorm
//     benchmark). This is where per-rule repeated work shows up.

// benchHeader builds a request header of the shape an ordinary browser sends.
func benchHeader() http.Header {
	h := make(http.Header, 8)
	h.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Accept-Encoding", "gzip, deflate, br")
	return h
}

// benchRules builds n host-scoped rules that never match benchHost, alternating
// exact and wildcard patterns so both matcher branches are exercised.
func benchRules(n int) []Rule {
	rules := make([]Rule, 0, n)
	for i := range n {
		host := fmt.Sprintf("service-%02d.internal.example-corporation.com", i)
		if i%2 == 1 {
			host = "*." + host
		}
		rules = append(rules, Rule{
			Host:       host,
			ReqSet:     map[string]string{"X-Forwarded-By": "Culvert"},
			RespRemove: []string{"Server"},
		})
	}
	return rules
}

const (
	benchHost      = "www.example.com"
	benchHostUpper = "WWW.Example.COM"
)

// ─── Disabled posture: no rules configured ────────────────────────────────────

func BenchmarkApplyRequest_NoRules(b *testing.B) {
	rw := NewRewriter()
	h := benchHeader()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rw.ApplyRequest(benchHost, h)
	}
}

// BenchmarkApplyRequest_NoRulesParallel is the scaling shape. Run it across
// -cpu=1,2,4: a per-op cost that RISES with core count means the path is
// serialising on a shared word rather than doing per-request work.
func BenchmarkApplyRequest_NoRulesParallel(b *testing.B) {
	rw := NewRewriter()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		h := benchHeader()
		for pb.Next() {
			rw.ApplyRequest(benchHost, h)
		}
	})
}

func BenchmarkApplyResponse_NoRulesParallel(b *testing.B) {
	rw := NewRewriter()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		resp := &http.Response{Header: benchHeader()}
		for pb.Next() {
			rw.ApplyResponse(benchHost, resp)
		}
	})
}

// ─── Enabled posture: rules that miss ─────────────────────────────────────────

func benchApplyRequestRules(b *testing.B, n int, host string) {
	rw := NewRewriter()
	rw.SetRules(benchRules(n))
	h := benchHeader()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rw.ApplyRequest(host, h)
	}
}

func BenchmarkApplyRequest_Rules1(b *testing.B)  { benchApplyRequestRules(b, 1, benchHost) }
func BenchmarkApplyRequest_Rules5(b *testing.B)  { benchApplyRequestRules(b, 5, benchHost) }
func BenchmarkApplyRequest_Rules20(b *testing.B) { benchApplyRequestRules(b, 20, benchHost) }
func BenchmarkApplyRequest_Rules50(b *testing.B) { benchApplyRequestRules(b, 50, benchHost) }

// BenchmarkApplyRequest_Rules20MixedCaseHost is the same shape with a host the
// client spelled with capitals — legal, and something a real client sends. It
// separates "scan every byte of the host once per rule" from "allocate a
// lowercased copy once per rule".
func BenchmarkApplyRequest_Rules20MixedCaseHost(b *testing.B) {
	benchApplyRequestRules(b, 20, benchHostUpper)
}

// BenchmarkApplyRequest_Rules20Parallel pins the enabled posture's scaling.
func BenchmarkApplyRequest_Rules20Parallel(b *testing.B) {
	rw := NewRewriter()
	rw.SetRules(benchRules(20))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		h := benchHeader()
		for pb.Next() {
			rw.ApplyRequest(benchHost, h)
		}
	})
}

// BenchmarkApplyRequest_Rules20Hit measures the cost when a rule DOES match, so
// the header mutations are included. Kept as the control for the miss-shaped
// benchmarks above: matching is what this change touches, applying is not.
func BenchmarkApplyRequest_Rules20Hit(b *testing.B) {
	rules := benchRules(20)
	rules = append(rules, Rule{
		Host:   benchHost,
		ReqSet: map[string]string{"X-Forwarded-By": "Culvert"},
	})
	rw := NewRewriter()
	rw.SetRules(rules)
	h := benchHeader()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rw.ApplyRequest(benchHost, h)
	}
}

// ─── Regression gates ─────────────────────────────────────────────────────────

// TestBenchGate_ApplyTakesNoRewriterLock is the hard gate on the lock-free read
// path, and it is deliberately STRUCTURAL rather than timing-based — the same
// choice, for the same reason, as internal/threatfeed's equivalent gate.
//
// The obvious gate is to measure serial vs parallel ns/op and require positive
// scaling; the numbers separate the two shapes cleanly (0.14x before, 3.9x
// after, recorded on BenchmarkApplyRequest_NoRulesParallel). But a ratio gate
// has a margin that erodes under -race on a shared CI runner, and a gate that
// can flake is worse than no gate: it gets muted.
//
// This form has no margin to erode. It holds the Rewriter's WRITE lock and then
// requires both per-request entry points to complete anyway. If either reverts
// to acquiring rw.mu — exactly the regression to catch — it blocks until the
// deadline and fails deterministically, on any hardware, at any load, with or
// without the race detector.
func TestBenchGate_ApplyTakesNoRewriterLock(t *testing.T) {
	rw := NewRewriter()
	rw.SetRules(benchRules(8)) // publish a view before taking the lock

	rw.mu.Lock()
	defer rw.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		rw.ApplyRequest(benchHost, benchHeader())
		rw.ApplyResponse(benchHost, &http.Response{Header: benchHeader()})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("REGRESSION: ApplyRequest/ApplyResponse blocked while the Rewriter write lock was " +
			"held — the per-request path is taking rw.mu again instead of reading the published view")
	}
}

// TestBenchGate_MutatorsStillTakeTheLock is the CONTROL for the gate above. A
// passing structural gate must not be reachable by the lock simply having
// stopped being taken at all: writers still serialise on rw.mu, and this fails
// if they stop.
func TestBenchGate_MutatorsStillTakeTheLock(t *testing.T) {
	rw := NewRewriter()

	rw.mu.Lock()

	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		rw.Add(Rule{Host: "late.example.com"})
	}()

	select {
	case <-blocked:
		rw.mu.Unlock()
		t.Fatal("CONTROL FAILED: Add completed while the write lock was held — writers are no " +
			"longer serialised, so the no-lock gate above proves nothing")
	case <-time.After(50 * time.Millisecond):
	}

	rw.mu.Unlock()
	<-blocked // Add must complete once the lock is released
}

// TestBenchGate_ApplyAllocsAreFlatInRuleCount pins the second half of the fix:
// the host is lowercased ONCE per call, not once per rule.
//
// A client may legally spell the Host header with capitals, and strings.ToLower
// allocates a copy when it does. Run per rule, that was one allocation per rule
// per request — measured at 20 allocs / 320 B on a 20-rule policy, scaling with
// the rulebase. This gate is deterministic (testing.AllocsPerRun, not a timing
// ratio), so it holds on any hardware.
func TestBenchGate_ApplyAllocsAreFlatInRuleCount(t *testing.T) {
	// Bound, not an exact count: at most one lowercased host copy per call. The
	// rules below deliberately MISS, so no header mutation allocates.
	const maxAllocsPerCall = 1

	for _, n := range []int{1, 5, 20, 50} {
		rw := NewRewriter()
		rw.SetRules(benchRules(n))
		h := benchHeader()

		got := testing.AllocsPerRun(200, func() {
			rw.ApplyRequest(benchHostUpper, h)
		})
		if got > maxAllocsPerCall {
			t.Errorf("REGRESSION: ApplyRequest with %d rules allocated %.0f times per call (bound %d) — "+
				"per-rule work is allocating again; the host must be lowercased once per call, not once per rule",
				n, got, maxAllocsPerCall)
		}
	}
}

// TestBenchGate_ApplyIsAllocationFreeWhenDisabled pins the default posture: no
// rules configured means one atomic pointer load and nothing else.
func TestBenchGate_ApplyIsAllocationFreeWhenDisabled(t *testing.T) {
	rw := NewRewriter()
	h := benchHeader()
	resp := &http.Response{Header: benchHeader()}

	if got := testing.AllocsPerRun(200, func() { rw.ApplyRequest(benchHostUpper, h) }); got != 0 {
		t.Errorf("ApplyRequest allocated %.0f times with no rules configured, want 0", got)
	}
	if got := testing.AllocsPerRun(200, func() { rw.ApplyResponse(benchHostUpper, resp) }); got != 0 {
		t.Errorf("ApplyResponse allocated %.0f times with no rules configured, want 0", got)
	}
}
