package main

// mcp_live_gate_denial_exhaustive_test.go — the MCP live side-effect boundary
// must DENY what it cannot classify.
//
// AdmitSideEffect switched on canaryAdmission.Denial with a case per known
// class and no default, so any denial class added to canaryAdmissionDenial
// later would fall out of the switch onto the admit path and authorize an
// irreversible upstream tool call. Every class defined today is handled, so
// this was a latent fail-open rather than a live one — which is exactly the
// kind that survives review and ships.
//
// CWE-636 (not failing securely) / CWE-1071; OWASP A04:2021.

import (
	"math"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// gateWithAdmission builds a gate whose admission transaction returns exactly
// the supplied result, with every other seam permissive — so the ONLY thing
// under test is how the gate treats that denial class.
func gateWithAdmission(adm canaryAdmission) *mcpLiveSideEffectGate {
	return &mcpLiveSideEffectGate{
		capb:      rollout.CapabilityGateway,
		admit:     func() (func(), bool) { return func() {}, true },
		readFirst: func(policy.OperationClass) bool { return true },
		trustPrecheck: func(_, _, _, _ string) liveTrustPrecheck {
			return liveTrustPrecheck{Eligible: true}
		},
		approvalOK: func(canary.LiveTarget, time.Time) (bool, string) { return true, "" },
		admitUnderActivation: func(time.Time, canary.ExecutionIdentity, canaryTrustProbe) canaryAdmission {
			return adm
		},
		releaseBudget:     func(uint64) {},
		generationCurrent: func(uint64) bool { return true },
	}
}

func liveGateInput() execution.LiveGateInput {
	return execution.LiveGateInput{
		Tenant:      "t1",
		ServerID:    "s1",
		ToolName:    "tool",
		Principal:   "p1",
		Fingerprint: "fp",
		Now:         time.Unix(1_700_000_000, 0),
	}
}

// TestLiveGate_UnknownDenialClassFailsClosed is the regression gate: a denial
// class the gate does not recognise must NOT be admitted.
func TestLiveGate_UnknownDenialClassFailsClosed(t *testing.T) {
	// A value beyond every class defined today — what a future addition looks
	// like to this build.
	unknown := canaryAdmissionDenial(200)
	g := gateWithAdmission(canaryAdmission{Denial: unknown, Active: true, Generation: 7})

	got := g.AdmitSideEffect(liveGateInput())
	if got.Admit {
		t.Fatal("an unclassifiable admission result authorized a side effect")
	}
}

// TestLiveGate_EveryKnownDenialClassDenies pins that no defined non-granted
// class reaches the admit path, and that granted still does.
func TestLiveGate_EveryKnownDenialClassDenies(t *testing.T) {
	for _, tc := range []struct {
		name      string
		denial    canaryAdmissionDenial
		wantAdmit bool
	}{
		{"granted", canaryAdmitGranted, true},
		{"no activation", canaryAdmitNoActivation, false},
		{"aborted", canaryAdmitAborted, false},
		{"drift", canaryAdmitDrift, false},
		{"untrusted", canaryAdmitUntrusted, false},
		{"budget", canaryAdmitBudget, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gateWithAdmission(canaryAdmission{
				Denial: tc.denial, Active: true, Generation: 7, Trusted: true,
			})
			got := g.AdmitSideEffect(liveGateInput())
			if got.Admit != tc.wantAdmit {
				t.Fatalf("Admit = %v, want %v", got.Admit, tc.wantAdmit)
			}
		})
	}
}

// TestLiveGate_GrantedIsTheOnlyAdmittingClass sweeps the whole uint8 space:
// exactly one value may admit. A gate that admits on more than one value has
// a hole no per-class test would find.
func TestLiveGate_GrantedIsTheOnlyAdmittingClass(t *testing.T) {
	// Walk the domain in its OWN type so the sweep needs no int→uint8
	// conversion (gosec G115). canaryAdmissionDenial wraps at its maximum, so
	// the terminator is the last value rather than a bound on a counter.
	admitting := make([]canaryAdmissionDenial, 0, 1)
	for v := canaryAdmissionDenial(0); ; v++ {
		g := gateWithAdmission(canaryAdmission{
			Denial: v, Active: true, Generation: 7, Trusted: true,
		})
		if g.AdmitSideEffect(liveGateInput()).Admit {
			admitting = append(admitting, v)
		}
		if v == math.MaxUint8 {
			break
		}
	}
	if len(admitting) != 1 || admitting[0] != canaryAdmitGranted {
		t.Fatalf("admitting denial values = %v, want only canaryAdmitGranted (%d)", admitting, canaryAdmitGranted)
	}
}
