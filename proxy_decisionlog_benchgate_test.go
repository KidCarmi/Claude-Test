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
// independent, rather than ns/op, which is not.

import (
	"testing"
)

// TestBenchGate_DecisionLogAllocs is the PRIMARY gate: it measures the real
// applyPolicyDecision allow branch, so reverting proxy.go fails here. The
// operand-shape comparison below is diagnostic — it names WHICH operand
// regressed — but it measures frozen copies, so it could not catch a revert on
// its own and is deliberately not the gate.
//
// Measured (Go 1.26, linux/amd64, 4 vCPU): 9 allocs/op after, 10 before. The
// bound sits at 9 with no headroom, because the removed allocation is the only
// difference and any slack would let it return unnoticed.
func TestBenchGate_DecisionLogAllocs(t *testing.T) {
	const maxAllocs int64 = 9

	res := testing.Benchmark(BenchmarkDecisionLog_ApplyAllow)
	got := res.AllocsPerOp()
	t.Logf("applyPolicyDecision allow branch: %d allocs/op, %d B/op, %d ns/op (bound %d)",
		got, res.AllocedBytesPerOp(), res.NsPerOp(), maxAllocs)

	if got > maxAllocs {
		t.Errorf("applyPolicyDecision allocates %d/op, bound %d — the duplicated sanitizeLog or the fmt.Sprintf priority render is back on the request path",
			got, maxAllocs)
	}
}

// TestBenchGate_DecisionLogOperandAllocs is the diagnostic half: it isolates
// the two operand savings on the line every proxied request emits — one
// hoisted rule-name sanitiser instead of two identical calls, and strconv.Itoa
// instead of fmt.Sprintf for the integer priority — so a failure names the
// operand rather than only the aggregate.
//
// Measured: 6 allocs/op for the shipped operand shape, 7 for the frozen
// pre-change shape. If a future Go release changes fmt's boxing behaviour and
// moves both numbers, the relational assertion still holds and the bound is
// the part to re-measure.
//
// The gate deliberately asserts the RELATIONSHIP as well as the absolute
// bound: both shapes are measured in the same run on the same machine, so a
// slow or differently-tuned runner cannot make the comparison lie.
func TestBenchGate_DecisionLogOperandAllocs(t *testing.T) {
	const maxAllocs int64 = 6

	current := testing.Benchmark(BenchmarkDecisionLog_Operands)
	legacy := testing.Benchmark(BenchmarkDecisionLog_LegacyOperands)

	curAllocs, legacyAllocs := current.AllocsPerOp(), legacy.AllocsPerOp()
	t.Logf("decision-log operands current: %d allocs/op, %d B/op, %d ns/op (bound %d)",
		curAllocs, current.AllocedBytesPerOp(), current.NsPerOp(), maxAllocs)
	t.Logf("decision-log operands legacy:  %d allocs/op, %d B/op, %d ns/op",
		legacyAllocs, legacy.AllocedBytesPerOp(), legacy.NsPerOp())

	if curAllocs > maxAllocs {
		t.Errorf("decision-log operands allocate %d/op, bound %d — the duplicated sanitizeLog or the fmt.Sprintf priority render is back on the request path",
			curAllocs, maxAllocs)
	}
	if curAllocs >= legacyAllocs {
		t.Errorf("current operand shape (%d allocs/op) is no cheaper than the pre-change shape (%d allocs/op); the optimization has been undone",
			curAllocs, legacyAllocs)
	}
}

// TestBenchGate_DecisionLogPriorityIsAllocationFree pins the component that
// carries the saving on its own, so a regression report names the specific
// operand rather than only the aggregate line.
//
// A decimal integer render must reach the log sink without touching the heap.
// fmt.Sprintf("%d", n) cannot satisfy this — it boxes n into an interface —
// so this gate fails the moment the reflection-based formatter returns.
func TestBenchGate_DecisionLogPriorityIsAllocationFree(t *testing.T) {
	itoa := testing.Benchmark(BenchmarkDecisionLog_PriorityItoa)
	sprintf := testing.Benchmark(BenchmarkDecisionLog_PrioritySprintf)

	t.Logf("priority itoa:    %d allocs/op, %d B/op", itoa.AllocsPerOp(), itoa.AllocedBytesPerOp())
	t.Logf("priority sprintf: %d allocs/op, %d B/op", sprintf.AllocsPerOp(), sprintf.AllocedBytesPerOp())

	if got := itoa.AllocsPerOp(); got != 0 {
		t.Errorf("priority render allocates %d/op, want 0 — the strconv.Itoa form has been replaced", got)
	}
	// Control: if the pre-change form ever stops allocating, the gate above is
	// no longer proving anything and the whole comparison needs re-deriving.
	if got := sprintf.AllocsPerOp(); got == 0 {
		t.Errorf("the fmt.Sprintf control now allocates %d/op; this gate no longer distinguishes the two shapes and must be re-measured", got)
	}
}
