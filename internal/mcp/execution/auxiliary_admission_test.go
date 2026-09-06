package execution

// auxiliary_admission_test.go — §4 at the ADMISSION boundary.
//
// openAttempt has always refused to mint an attempt identity for lifecycle and
// discovery traffic, and its comment states the contract: such traffic "must never
// consume an execution reservation or inflate the physical-effect count".
//
// That contract is about METERING. It was briefly implemented by skipping the
// composition-layer gate entirely for those methods, which also dropped the gate's
// TIER-level admission checks — a different question with a different answer.
// `tools/list` is a client-reachable decision-point method that reaches this
// boundary on an EffectExecute disposition and makes a real, credentialed outbound
// call, so "may this tier make ANY outbound call right now" (armed, not quiescing,
// read-first) still has to be asked even when "charge it a reservation" must not be.
//
// These gates pin both halves of that split, with tools/call controls on every
// fixture so a passing gate can never mean the gate simply stopped being consulted.

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// auxiliaryMethods is every method the fail-closed classifier positively exempts
// from metering. Listed once so a class added to the classifier without a decision
// about its admission shows up as a missing case here.
var auxiliaryMethods = []string{"initialize", "notifications/initialized", "notifications/cancelled", "ping", "tools/list"}

// countingGate records every admission it is asked for, and what it was asked
// ABOUT. The COUNT alone is no longer the whole property: an admitting gate is
// indistinguishable from one that was never consulted if you only look at the
// outcome, and now that auxiliary traffic IS consulted, the metered flag is what
// separates "asked to admit" from "asked to charge a reservation".
type countingGate struct {
	calls int
	// meteredCalls counts only the admissions asked to charge a budget slot.
	meteredCalls int
	// sawMetered records the Metered flag of every admission, in order.
	sawMetered []bool
	admit      bool
	// refuseMeteredOnly makes the gate answer like the production one: a tool-level
	// refusal (trust/budget) applies only to a metered admission.
	refuseMeteredOnly bool
	reason            mcperr.Reason
}

func (g *countingGate) AdmitSideEffect(in LiveGateInput) LiveGateDecision {
	g.calls++
	g.sawMetered = append(g.sawMetered, in.Metered)
	if in.Metered {
		g.meteredCalls++
	}
	if !g.admit && (in.Metered || !g.refuseMeteredOnly) {
		return LiveGateDecision{Admit: false, Reason: g.reason}
	}
	if !in.Metered {
		// A non-metered admission names no slot and no generation — exactly what the
		// production gate returns, so openAttempt's identity gate is never reached.
		return LiveGateDecision{Admit: true, Release: func() {}}
	}
	return LiveGateDecision{
		Admit: true, Release: func() {},
		ReservationID: "rsv_counted", ActivationGeneration: 4,
	}
}

// TestAuxiliaryTraffic_IsAdmittedButNeverMetered is the accounting half. A
// reservation is the unit MaxTotalExecutions counts, so spending one on a call that
// can cause no side effect makes the budget stop measuring physical invocations —
// the exact property blocker #6 exists to establish. The gate is still CONSULTED;
// it is simply told this invocation is not metered.
func TestAuxiliaryTraffic_IsAdmittedButNeverMetered(t *testing.T) {
	for _, method := range auxiliaryMethods {
		t.Run(method, func(t *testing.T) {
			up := &fakeUpstream{}
			gate := &countingGate{admit: true}
			e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
			e.cfg.LiveGate = gate

			in := execInput(policy.ActionAllow, false)
			in.Method = method
			out := e.Execute(t.Context(), in, rollout.Resolution{Disposition: rollout.EffectExecute})

			if gate.calls != 1 {
				t.Fatalf("%s must still be admitted by the tier gate, got %d admission(s)", method, gate.calls)
			}
			if gate.meteredCalls != 0 {
				t.Fatalf("%s consumed %d metered admission(s); auxiliary traffic must reserve nothing",
					method, gate.meteredCalls)
			}
			if len(gate.sawMetered) != 1 || gate.sawMetered[0] {
				t.Fatalf("%s must be presented to the gate as non-metered, saw %v", method, gate.sawMetered)
			}
			if up.calls != 1 {
				t.Fatalf("%s must still reach the upstream, got %d calls; reason %v", method, up.calls, out.Reason)
			}
		})
	}
}

// TestAuxiliaryTraffic_SurvivesAToolLevelRefusal is the availability half, and it is
// the shape that actually bites in production: the real gate validates tool trust
// against the invocation's tool binding, which auxiliary traffic does not have, so a
// tool-level check would REFUSE. An armed Canary node must still be able to complete
// a session handshake and list tools.
//
// The refusal is now scoped where it belongs — inside the gate, keyed on Metered —
// rather than by not consulting the gate at all. The control below proves the same
// gate still refuses the metered call.
func TestAuxiliaryTraffic_SurvivesAToolLevelRefusal(t *testing.T) {
	for _, method := range []string{"initialize", "ping", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			up := &fakeUpstream{}
			gate := &countingGate{admit: false, refuseMeteredOnly: true, reason: mcperr.ReasonRolloutBudgetExhausted}
			e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
			e.cfg.LiveGate = gate

			in := execInput(policy.ActionAllow, false)
			in.Method = method
			out := e.Execute(t.Context(), in, rollout.Resolution{Disposition: rollout.EffectExecute})

			if up.calls != 1 {
				t.Fatalf("%s must not be refused by a tool-level check it has no binding for, got %d calls; reason %v",
					method, up.calls, out.Reason)
			}
		})
	}
	t.Run("control: the same gate still refuses tools/call", func(t *testing.T) {
		up := &fakeUpstream{}
		gate := &countingGate{admit: false, refuseMeteredOnly: true, reason: mcperr.ReasonRolloutBudgetExhausted}
		e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
		e.cfg.LiveGate = gate

		out := e.Execute(t.Context(), execInput(policy.ActionAllow, false), rollout.Resolution{Disposition: rollout.EffectExecute})

		if up.calls != 0 {
			t.Fatalf("control: a tool-level refusal must still block tools/call, got %d calls", up.calls)
		}
		if out.Executed {
			t.Fatal("control: a refused tools/call must not report Executed")
		}
	})
}

// TestAuxiliaryTraffic_IsRefusedByATierLevelDenial is the REGRESSION gate for the
// bypass this file's contract was rewritten to close.
//
// A tier-level denial — the tier is UNARMED (the deliberate fail-closed posture
// after a restart, where the rollout mode is still Canary but the live tier is never
// automatically re-armed) or has CLOSED admission mid-drain — is not a statement
// about tools. It says this node may make no live outbound call at all right now.
// Skipping the gate for auxiliary traffic silently exempted discovery from it, so an
// unarmed node kept forwarding credentialed `tools/list` calls upstream.
//
// The gate here refuses UNCONDITIONALLY, which is exactly how the tier-level checks
// answer: they do not consult the tool binding, so they cannot distinguish auxiliary
// traffic and must not be made to.
func TestAuxiliaryTraffic_IsRefusedByATierLevelDenial(t *testing.T) {
	for _, method := range auxiliaryMethods {
		t.Run(method, func(t *testing.T) {
			up := &fakeUpstream{}
			gate := &countingGate{admit: false, reason: mcperr.ReasonRolloutModeInvalid}
			e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
			e.cfg.LiveGate = gate

			in := execInput(policy.ActionAllow, false)
			in.Method = method
			out := e.Execute(t.Context(), in, rollout.Resolution{Disposition: rollout.EffectExecute})

			if gate.calls != 1 {
				t.Fatalf("%s must be presented to the tier gate, got %d admission(s)", method, gate.calls)
			}
			if up.calls != 0 {
				t.Fatalf("%s crossed the boundary of a tier that refused every call, got %d upstream call(s)",
					method, up.calls)
			}
			if out.Executed {
				t.Fatalf("%s reported Executed after a tier-level refusal", method)
			}
			if out.Reason != mcperr.ReasonRolloutModeInvalid {
				t.Fatalf("%s must surface the gate's bounded reason, got %v", method, out.Reason)
			}
		})
	}
}

// TestToolCallStillReachesTheSideEffectGate is the CONTROL for the gates above, on
// the same fixtures. Without it they would pass on an executor that had stopped
// consulting the gate at all — which is the failure this contract must never
// introduce, in either direction.
func TestToolCallStillReachesTheSideEffectGate(t *testing.T) {
	t.Run("admitting gate is consulted exactly once, and metered", func(t *testing.T) {
		up := &fakeUpstream{}
		gate := &countingGate{admit: true}
		e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
		e.cfg.LiveGate = gate

		out := e.Execute(t.Context(), execInput(policy.ActionAllow, false), rollout.Resolution{Disposition: rollout.EffectExecute})

		if gate.calls != 1 || gate.meteredCalls != 1 {
			t.Fatalf("tools/call must consume exactly one METERED admission, got calls=%d metered=%d",
				gate.calls, gate.meteredCalls)
		}
		if up.calls != 1 || !out.Executed {
			t.Fatalf("control: expected one executed upstream call, got calls=%d executed=%v reason=%v",
				up.calls, out.Executed, out.Reason)
		}
	})
	t.Run("refusing gate still blocks the side effect", func(t *testing.T) {
		up := &fakeUpstream{}
		gate := &countingGate{admit: false, reason: mcperr.ReasonRolloutBudgetExhausted}
		e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
		e.cfg.LiveGate = gate

		out := e.Execute(t.Context(), execInput(policy.ActionAllow, false), rollout.Resolution{Disposition: rollout.EffectExecute})

		if up.calls != 0 {
			t.Fatalf("control: a refused tools/call must never reach the upstream, got %d", up.calls)
		}
		if out.Executed {
			t.Fatal("control: a refused tools/call must not report Executed")
		}
	})
}

// TestUnclassifiedMethodIsStillMetered pins the fail-closed direction of the
// exemption. The classifier's default is side-effect-bearing, so a method nobody
// classified is metered like a tool call rather than being cheaper than one — an
// exemption keyed on a denylist would be a way to spend no budget by inventing a
// method name.
func TestUnclassifiedMethodIsStillMetered(t *testing.T) {
	up := &fakeUpstream{}
	gate := &countingGate{admit: false, refuseMeteredOnly: true, reason: mcperr.ReasonRolloutBudgetExhausted}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.LiveGate = gate

	in := execInput(policy.ActionAllow, false)
	in.Method = "resources/write"
	out := e.Execute(t.Context(), in, rollout.Resolution{Disposition: rollout.EffectExecute})

	if gate.meteredCalls != 1 {
		t.Fatalf("an unclassified method must be metered like a tool call, got %d metered admission(s)", gate.meteredCalls)
	}
	if up.calls != 0 {
		t.Fatalf("an unclassified method refused by the gate must not reach the upstream, got %d", up.calls)
	}
	if out.Executed {
		t.Fatal("an unclassified method refused by the gate must not report Executed")
	}
}
