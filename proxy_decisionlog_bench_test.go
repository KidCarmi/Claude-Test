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
// BenchmarkDecisionLog_Legacy* are the FROZEN pre-change shapes, kept so the
// comparison stays reproducible in-tree rather than living only in a commit
// message. They are verbatim copies of the code that was removed; they are not
// called by production and must NOT be "kept in sync" with applyPolicyDecision
// — their whole value is that they do not move.
//
// ── THE PRIORITY VALUE IS LOAD-BEARING, so both sides of it are measured ─────
//
// strconv.Itoa returns a slice of a package-level constant for 0 <= n < 100 and
// ALLOCATES at or above it. Rule priorities are auto-assigned by the admin UI
// as `max existing + 10` (static/index.html, nextAutoPriority), so the TENTH
// rule already gets priority 100 and every rule past it is outside the cached
// range. A benchmark pinned to a two-digit priority therefore reports a
// per-component allocation saving that most of a real rulebase never sees.
// (Caught in review by Codex on PR #1336; the first version of this file
// measured only 42 and claimed the render was allocation-free full stop.)
//
// So benchDLPriorityWide (1000, the 100th UI-created rule) is the
// REPRESENTATIVE case and carries the headline numbers; benchDLPrioritySmall
// (42) is kept to pin the boundary rather than to flatter the result.
//
// The priority is also passed as a PARAMETER rather than referenced as a
// package constant, and that is load-bearing too: from a constant the compiler
// can box the interface value into static data, so the fmt.Sprintf shape
// measures one allocation cheaper than it ever is in production, where the
// value is the runtime struct field match.Rule.Priority. The first version of
// this file used a constant and understated the legacy cost by exactly that
// allocation.
//
// Measured on this machine (Go 1.26, linux/amd64, 4 vCPU, median of 5, logger
// over io.Discard so the measurement is the formatting cost — which is what
// the async sink in internal/logsink leaves on the caller's goroutine):
//
//	applyPolicyDecision allow branch   ns/op   B/op   allocs/op
//	  priority 1000  legacy             881     160      11
//	  priority 1000  current            725     148      10   -17.7%  -1 alloc
//	  priority   42  legacy             846     146      10
//	  priority   42  current            683     144       9   -19.3%  -1 alloc
//
//	operand rendering alone
//	  priority 1000  legacy             528     112       8
//	  priority 1000  current            391     100       7
//	  priority   42  legacy             502      98       7
//	  priority   42  current            370      96       6
//
//	priority render alone            ns/op   allocs/op
//	  priority 1000  fmt.Sprintf       91.5       2   (boxing >=256 + result)
//	  priority 1000  strconv.Itoa      26.6       1
//	  priority   42  fmt.Sprintf       74.0       1
//	  priority   42  strconv.Itoa      10.1       0
//
//	sanitizeLog, one clean pass        51 ns      0   (paid twice before)
//
// Read that honestly: the saving is -1 allocation and ~18% CPU at BOTH
// priorities. What changes across the boundary is the absolute alloc count,
// not the delta — which is why the gates bound each priority separately
// instead of asserting one number.

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

	// benchDLPriorityWide is the representative priority: the admin UI's
	// max+10 allocator puts the 100th rule here, and everything from the 10th
	// rule on is already outside strconv.Itoa's cached range.
	benchDLPriorityWide = 1000
	// benchDLPrioritySmall sits inside that cached range, so the pair pins the
	// boundary instead of hiding it.
	benchDLPrioritySmall = 42
)

// ── Operand rendering: legacy vs current, at both priorities ─────────────────

// benchLegacyOperands is the FROZEN pre-change shape: the rule name sanitised
// twice, the priority rendered through fmt.Sprintf. Do not modify it to match
// production.
func benchLegacyOperands(b *testing.B, priority int) {
	b.Cleanup(benchSilenceLogger())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Printf("POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}",
			sanitizeLog(benchDLRule),
			strings.ReplaceAll(fmt.Sprintf("%d", priority), "\n", ""),
			benchDLClientIP, benchDLMethod, sanitizeLog(benchDLHost), sanitizeLog(benchDLConditions),
			benchDLReqID, sanitizeLog(benchDLIdentity), sanitizeLog(benchDLRule))
	}
}

// benchCurrentOperands is the shipped shape: one hoisted sanitised name, and
// the priority via strconv.Itoa behind the inline CodeQL sanitiser.
func benchCurrentOperands(b *testing.B, priority int) {
	b.Cleanup(benchSilenceLogger())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := sanitizeLog(benchDLRule)
		logger.Printf("POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}",
			name,
			strings.ReplaceAll(strconv.Itoa(priority), "\n", ""),
			benchDLClientIP, benchDLMethod, sanitizeLog(benchDLHost), sanitizeLog(benchDLConditions),
			benchDLReqID, sanitizeLog(benchDLIdentity), name)
	}
}

// BenchmarkDecisionLog_LegacyOperands is the pre-change shape at the
// representative priority.
func BenchmarkDecisionLog_LegacyOperands(b *testing.B) { benchLegacyOperands(b, benchDLPriorityWide) }

// BenchmarkDecisionLog_Operands is the shipped shape at the representative
// priority.
func BenchmarkDecisionLog_Operands(b *testing.B) { benchCurrentOperands(b, benchDLPriorityWide) }

// BenchmarkDecisionLog_LegacyOperandsSmallPriority is the pre-change shape
// inside Itoa's cached range.
func BenchmarkDecisionLog_LegacyOperandsSmallPriority(b *testing.B) {
	benchLegacyOperands(b, benchDLPrioritySmall)
}

// BenchmarkDecisionLog_OperandsSmallPriority is the shipped shape inside
// Itoa's cached range.
func BenchmarkDecisionLog_OperandsSmallPriority(b *testing.B) {
	benchCurrentOperands(b, benchDLPrioritySmall)
}

// ── Component isolation: the priority render alone ───────────────────────────

func benchPrioritySprintf(b *testing.B, priority int) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchDecisionLogSink = strings.ReplaceAll(fmt.Sprintf("%d", priority), "\n", "")
	}
}

func benchPriorityItoa(b *testing.B, priority int) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchDecisionLogSink = strings.ReplaceAll(strconv.Itoa(priority), "\n", "")
	}
}

// BenchmarkDecisionLog_PrioritySprintf measures the pre-change priority render
// at the representative priority: fmt.Sprintf boxes the int and runs the
// reflection formatter.
func BenchmarkDecisionLog_PrioritySprintf(b *testing.B) {
	benchPrioritySprintf(b, benchDLPriorityWide)
}

// BenchmarkDecisionLog_PriorityItoa measures the shipped priority render at the
// representative priority. Above 99 this allocates, exactly like the shape it
// replaced — here the win is CPU, not allocations.
func BenchmarkDecisionLog_PriorityItoa(b *testing.B) {
	benchPriorityItoa(b, benchDLPriorityWide)
}

// BenchmarkDecisionLog_PrioritySprintfSmall is the sub-100 control.
func BenchmarkDecisionLog_PrioritySprintfSmall(b *testing.B) {
	benchPrioritySprintf(b, benchDLPrioritySmall)
}

// BenchmarkDecisionLog_PriorityItoaSmall is the sub-100 case — the only range
// in which the priority render itself is allocation-free.
func BenchmarkDecisionLog_PriorityItoaSmall(b *testing.B) {
	benchPriorityItoa(b, benchDLPrioritySmall)
}

// BenchmarkDecisionLog_SanitizeRuleName measures one sanitizeLog pass over a
// clean rule name — the cost the old line paid twice per request, at every
// priority.
func BenchmarkDecisionLog_SanitizeRuleName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchDecisionLogSink = sanitizeLog(benchDLRule)
	}
}

// benchDecisionLogSink defeats dead-store elimination without allocating.
var benchDecisionLogSink string

// ── Whole-branch, in context ─────────────────────────────────────────────────

func benchApplyAllow(b *testing.B, priority int) {
	b.Cleanup(benchSilenceLogger())
	logOff := false
	match := &PolicyMatch{
		Rule: &PolicyRule{
			Name:       benchDLRule,
			Priority:   priority,
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

// BenchmarkDecisionLog_ApplyAllow drives the REAL applyPolicyDecision allow
// branch at the representative priority, so the line's share is measured
// against the rest of the dispatch (rule-hit metering, the request-log
// fan-out) rather than in isolation.
func BenchmarkDecisionLog_ApplyAllow(b *testing.B) { benchApplyAllow(b, benchDLPriorityWide) }

// BenchmarkDecisionLog_ApplyAllowSmallPriority is the same branch inside Itoa's
// cached range, so the gate can bound both sides of the boundary.
func BenchmarkDecisionLog_ApplyAllowSmallPriority(b *testing.B) {
	benchApplyAllow(b, benchDLPrioritySmall)
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
		Priority:   benchDLPriorityWide,
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
