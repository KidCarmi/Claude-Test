package main

// proxy_decisionlog_bench_test.go — before/after evidence for the per-request
// policy-decision log lines in applyPolicyDecision (proxy.go).
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkDecisionLog' -benchmem -count=6 .
//
// WHY THIS PATH. applyPolicyDecision emits exactly one POLICY_* line per
// proxied request — HTTP, CONNECT and WebSocket alike, since handleRequest
// dispatches through it before the transport switch. Exact allocation
// profiling of the end-to-end proxy benchmark (BenchmarkPerfQual_ProxyHTTPForward,
// rules=100, -memprofilerate=1) put applyPolicyDecision at 8 allocs/op FLAT —
// the largest Culvert-owned allocation site on the request path by a factor of
// eight over the next one (PolicyStore.Evaluate, generateTraceparent and
// prepareHTTPForward are 1 alloc/op each), and all eight land on this one line.
//
// Two costs were pure waste, and removing them changes no output byte:
//
//  1. The format renders the rule name TWICE (rule=%q ... rule=%s) and the old
//     code called sanitizeLog on it once per occurrence — two identical scans
//     of the same string on 100% of proxied requests.
//  2. The priority was rendered with fmt.Sprintf("%d", ...), which boxes the
//     int into an interface and runs the reflection-based formatter.
//
// BenchmarkDecisionLog_LegacyOperands is the FROZEN pre-change shape, kept so
// the comparison stays reproducible in-tree rather than living only in a commit
// message. It is a verbatim copy of the code that was removed; it is not called
// by production and must NOT be "kept in sync" with applyPolicyDecision — its
// whole value is that it does not move.
//
// Measured on this machine (Go 1.26, linux/amd64, 4 vCPU, log.Logger over
// io.Discard so the measurement is the formatting cost, which is what the
// async sink in internal/logsink leaves on the caller's goroutine):
//
//	                              ns/op    B/op   allocs/op
//	legacy operands               506       98        7
//	current operands              377       96        6
//	                             -25.5%    -2%       -1
//
// Component isolation, same run:
//
//	fmt.Sprintf("%d") + ReplaceAll    68.1 ns    1 alloc
//	strconv.Itoa      + ReplaceAll    10.0 ns    0 allocs
//	sanitizeLog (clean 17-byte host)  48.6 ns    0 allocs   <- was paid twice
//
// The two component savings (58 ns + 49 ns = 107 ns) account for the measured
// 129 ns delta; the remainder is one fewer interface box reaching fmt.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Operands shaped like a real enterprise decision: a hyphenated rule name, an
// RFC 5737 client address, an ordinary FQDN, a two-condition match summary and
// a ULID request id.
const (
	benchDLRule       = "corp-allow-saas"
	benchDLClientIP   = "203.0.113.87"
	benchDLMethod     = http.MethodGet
	benchDLHost       = "files.example.com"
	benchDLConditions = "fqdn=*.example.com;group=engineering"
	benchDLReqID      = "01JC8ZQ4K7X2M9NRTVW6Y3B5AE"
	benchDLIdentity   = "alice@corp.example.com"
	benchDLPriority   = 42
)

// BenchmarkDecisionLog_LegacyOperands is the FROZEN pre-change shape: the rule
// name sanitised twice, the priority rendered through fmt.Sprintf. Do not
// modify it to match production.
func BenchmarkDecisionLog_LegacyOperands(b *testing.B) {
	b.Cleanup(benchSilenceLogger())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Printf("POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}",
			sanitizeLog(benchDLRule),
			strings.ReplaceAll(fmt.Sprintf("%d", benchDLPriority), "\n", ""),
			benchDLClientIP, benchDLMethod, sanitizeLog(benchDLHost), sanitizeLog(benchDLConditions),
			benchDLReqID, sanitizeLog(benchDLIdentity), sanitizeLog(benchDLRule))
	}
}

// BenchmarkDecisionLog_Operands is the shipped shape: one hoisted sanitised
// name, priority via strconv.Itoa behind the inline CodeQL sanitiser.
func BenchmarkDecisionLog_Operands(b *testing.B) {
	b.Cleanup(benchSilenceLogger())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := sanitizeLog(benchDLRule)
		logger.Printf("POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}",
			name,
			strings.ReplaceAll(strconv.Itoa(benchDLPriority), "\n", ""),
			benchDLClientIP, benchDLMethod, sanitizeLog(benchDLHost), sanitizeLog(benchDLConditions),
			benchDLReqID, sanitizeLog(benchDLIdentity), name)
	}
}

// ── Component isolation ───────────────────────────────────────────────────────

// BenchmarkDecisionLog_PrioritySprintf measures the pre-change priority render
// on its own: fmt.Sprintf boxes the int and runs the reflection formatter.
func BenchmarkDecisionLog_PrioritySprintf(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = strings.ReplaceAll(fmt.Sprintf("%d", benchDLPriority), "\n", "")
	}
	keepDecisionLogString(s)
}

// BenchmarkDecisionLog_PriorityItoa measures the shipped priority render: the
// same inline ReplaceAll sanitiser over strconv.Itoa instead of fmt.Sprintf.
func BenchmarkDecisionLog_PriorityItoa(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = strings.ReplaceAll(strconv.Itoa(benchDLPriority), "\n", "")
	}
	keepDecisionLogString(s)
}

// BenchmarkDecisionLog_SanitizeRuleName measures one sanitizeLog pass over a
// clean rule name — the cost the old line paid twice per request.
func BenchmarkDecisionLog_SanitizeRuleName(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = sanitizeLog(benchDLRule)
	}
	keepDecisionLogString(s)
}

// benchDecisionLogSink defeats dead-store elimination without allocating.
var benchDecisionLogSink string

func keepDecisionLogString(s string) { benchDecisionLogSink = s }

// ── Whole-branch, in context ─────────────────────────────────────────────────

// BenchmarkDecisionLog_ApplyAllow drives the REAL applyPolicyDecision allow
// branch, so the line's share is measured against the rest of the dispatch
// (rule-hit metering, the request-log fan-out) rather than in isolation.
func BenchmarkDecisionLog_ApplyAllow(b *testing.B) {
	b.Cleanup(benchSilenceLogger())
	logOff := false
	match := &PolicyMatch{
		Rule: &PolicyRule{
			Name:       benchDLRule,
			Priority:   benchDLPriority,
			Action:     ActionAllow,
			LogTraffic: &logOff, // stats-only: keeps the JSONL sink out of the measurement
		},
		Action:            ActionAllow,
		MatchedConditions: benchDLConditions,
	}
	r := httptest.NewRequestWithContext(context.Background(), benchDLMethod, "http://"+benchDLHost+"/a/b", http.NoBody)
	r.Host = benchDLHost
	w := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		applyPolicyDecision(w, r, benchDLClientIP, benchDLHost, benchDLReqID, benchDLIdentity, AuthLogFields{}, match)
	}
}

// BenchmarkDecisionLog_ApplyAllowParallel is the concurrency shape: a gateway
// runs this line on every core at once. It exists to show the change does not
// introduce shared state — the hoisted operands are per-call locals, so the
// per-op cost must stay flat in GOMAXPROCS rather than degrading the way a
// newly-shared cache line would.
//
//	go test -run '^$' -bench 'ApplyAllowParallel' -benchmem -cpu=1,2,4 -count=6 .
func BenchmarkDecisionLog_ApplyAllowParallel(b *testing.B) {
	b.Cleanup(benchSilenceLogger())
	logOff := false
	rule := &PolicyRule{
		Name:       benchDLRule,
		Priority:   benchDLPriority,
		Action:     ActionAllow,
		LogTraffic: &logOff,
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		match := &PolicyMatch{Rule: rule, Action: ActionAllow, MatchedConditions: benchDLConditions}
		r := httptest.NewRequestWithContext(context.Background(), benchDLMethod, "http://"+benchDLHost+"/a/b", http.NoBody)
		r.Host = benchDLHost
		w := httptest.NewRecorder()
		for pb.Next() {
			applyPolicyDecision(w, r, benchDLClientIP, benchDLHost, benchDLReqID, benchDLIdentity, AuthLogFields{}, match)
		}
	})
}
