//go:build benchgate

package main

// Allocation-regression gate for the per-request policy-decision log line
// (applyPolicyDecision, proxy.go).
//
// Output contracts for that line live in proxy_decisionlog_test.go and run in
// the normal suite; this file holds the PERFORMANCE contract only, in the
// repository's benchgate convention:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v .
//
// Keyed on allocations per op, which are deterministic and hardware
// independent, rather than ns/op, which is not. The ns/op saving is the larger
// half of this change (~18% on the branch) but it is measured, not gated.
//
// EVERY GATE HERE IS RUN AT TWO PRIORITIES. strconv.Itoa returns a slice of a
// package constant for 0 <= n < 100 and allocates at or above it, and the admin
// UI's max+10 priority allocator puts the tenth rule at 100 — so a gate pinned
// to a two-digit priority bounds a case most of a real rulebase never hits, and
// would read as "allocation-free" on a claim that is only true for the first
// nine rules. (Codex review, PR #1336.)

import (
	"testing"
)

// TestBenchGate_DecisionLogAllocs is the PRIMARY gate: it measures the real
// applyPolicyDecision allow branch, so reverting proxy.go fails here. The
// operand-shape comparison below is diagnostic — it names WHICH operand
// regressed — but it measures frozen copies, so it could not catch a revert on
// its own and is deliberately not the gate.
//
// Measured (Go 1.26, linux/amd64, 4 vCPU, median of 5):
//
//	priority 1000 (representative): 11 allocs before -> 10 after
//	priority   42 (Itoa cache):     10 allocs before ->  9 after
//
// Both bounds sit at the measured value with no headroom: the removed
// allocation is the only difference at each priority, and any slack would let
// it return unnoticed.
func TestBenchGate_DecisionLogAllocs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bench     func(*testing.B)
		maxAllocs int64
	}{
		{"representative-priority", BenchmarkDecisionLog_ApplyAllow, 10},
		{"cached-range-priority", BenchmarkDecisionLog_ApplyAllowSmallPriority, 9},
	} {
		res := testing.Benchmark(tc.bench)
		got := res.AllocsPerOp()
		t.Logf("applyPolicyDecision allow branch (%s): %d allocs/op, %d B/op, %d ns/op (bound %d)",
			tc.name, got, res.AllocedBytesPerOp(), res.NsPerOp(), tc.maxAllocs)

		if got > tc.maxAllocs {
			t.Errorf("applyPolicyDecision (%s) allocates %d/op, bound %d — the duplicated sanitizeLog or the fmt.Sprintf priority render is back on the request path",
				tc.name, got, tc.maxAllocs)
		}
	}
}

// TestBenchGate_DecisionLogOperandAllocs is the diagnostic half: it isolates
// the two operand savings on the line every proxied request emits — one
// hoisted rule-name sanitiser instead of two identical calls, and strconv.Itoa
// instead of fmt.Sprintf for the integer priority — so a failure names the
// operand rather than only the aggregate.
//
// It asserts the RELATIONSHIP rather than an absolute bound: both shapes are
// measured in the same run on the same machine, so a slow or differently-tuned
// runner cannot make the comparison lie, and a future Go release that moves
// fmt's or strconv's boxing behaviour moves both numbers together.
//
//	priority 1000: 8 allocs legacy -> 7 current
//	priority   42: 7 allocs legacy -> 6 current
func TestBenchGate_DecisionLogOperandAllocs(t *testing.T) {
	for _, tc := range []struct {
		name            string
		current, legacy func(*testing.B)
	}{
		{"representative-priority", BenchmarkDecisionLog_Operands, BenchmarkDecisionLog_LegacyOperands},
		{"cached-range-priority", BenchmarkDecisionLog_OperandsSmallPriority, BenchmarkDecisionLog_LegacyOperandsSmallPriority},
	} {
		current := testing.Benchmark(tc.current)
		legacy := testing.Benchmark(tc.legacy)

		curAllocs, legacyAllocs := current.AllocsPerOp(), legacy.AllocsPerOp()
		t.Logf("decision-log operands (%s): current %d allocs/op %d ns/op, legacy %d allocs/op %d ns/op",
			tc.name, curAllocs, current.NsPerOp(), legacyAllocs, legacy.NsPerOp())

		if curAllocs >= legacyAllocs {
			t.Errorf("current operand shape (%s) is %d allocs/op, no cheaper than the pre-change shape at %d allocs/op; the optimization has been undone",
				tc.name, curAllocs, legacyAllocs)
		}
	}
}

// TestBenchGate_DecisionLogPriorityRender pins the component that carries half
// the saving, so a regression report names the specific operand rather than
// only the aggregate line.
//
// The claim is NOT "the priority render is allocation-free" — that is true only
// below 100, and the first version of this gate asserted it against a hardcoded
// 42, which made a boundary case look like a general property. The real claim,
// which holds across the supported range, is that the Itoa form is strictly
// cheaper in allocations than the fmt.Sprintf form it replaced:
//
//	priority   42: 1 alloc (Sprintf) -> 0 allocs (Itoa)
//	priority 1000: 2 allocs (Sprintf: boxing an int >= 256, plus the result
//	               string) -> 1 alloc (Itoa)
//
// The boundary itself is pinned below, so a future strconv change that widens
// or narrows the cached range is a visible failure rather than a silent shift
// in what these numbers mean.
func TestBenchGate_DecisionLogPriorityRender(t *testing.T) {
	for _, tc := range []struct {
		name         string
		itoa, sprint func(*testing.B)
	}{
		{"representative-priority", BenchmarkDecisionLog_PriorityItoa, BenchmarkDecisionLog_PrioritySprintf},
		{"cached-range-priority", BenchmarkDecisionLog_PriorityItoaSmall, BenchmarkDecisionLog_PrioritySprintfSmall},
	} {
		itoa := testing.Benchmark(tc.itoa)
		sprintf := testing.Benchmark(tc.sprint)
		t.Logf("priority render (%s): itoa %d allocs/op %d ns/op, sprintf %d allocs/op %d ns/op",
			tc.name, itoa.AllocsPerOp(), itoa.NsPerOp(), sprintf.AllocsPerOp(), sprintf.NsPerOp())

		if itoa.AllocsPerOp() >= sprintf.AllocsPerOp() {
			t.Errorf("priority render (%s): itoa form allocates %d/op, not fewer than the fmt.Sprintf form's %d/op — the substitution no longer pays",
				tc.name, itoa.AllocsPerOp(), sprintf.AllocsPerOp())
		}
	}

	// Pin the cache boundary the two cases above straddle, so the numbers in
	// this file keep meaning what they say.
	small := testing.Benchmark(BenchmarkDecisionLog_PriorityItoaSmall)
	if got := small.AllocsPerOp(); got != 0 {
		t.Errorf("strconv.Itoa(%d) allocates %d/op, want 0 — it is meant to be inside the cached small-integer range",
			benchDLPrioritySmall, got)
	}
	wide := testing.Benchmark(BenchmarkDecisionLog_PriorityItoa)
	if got := wide.AllocsPerOp(); got == 0 {
		t.Errorf("strconv.Itoa(%d) no longer allocates; the representative case has drifted inside the cached range and this file's headline numbers understate the real cost",
			benchDLPriorityWide)
	}
}
