package main

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// stubAdmitUnderActivation builds an admitUnderActivation double for gate tests that are not about
// activation binding: it still EVALUATES the trust probe (so the trust seam those tests control
// keeps its meaning) and reports a fixed generation and budget outcome.
//
// It deliberately reproduces the real transaction's ordering — drift beats untrusted beats budget —
// so a test using it cannot pass against a gate that reads the result fields in the wrong order.
func stubAdmitUnderActivation(outcome canary.BudgetOutcome, gen uint64) func(time.Time, policy.OperationClass, canary.ExecutionIdentity, canaryTrustProbe) canaryAdmission {
	return func(_ time.Time, _ policy.OperationClass, _ canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission {
		trusted, drift := true, ""
		if trust != nil {
			obs := trust()
			trusted, drift = obs.Trusted, obs.DriftCode
			// The real transaction treats an unresolvable target as request-scoped; reproduce that
			// so a test using this double cannot pass against a gate that conflates the two.
			if drift == "" && !obs.Found {
				trusted = false
			}
		}
		switch {
		case drift != "":
			return canaryAdmission{Denial: canaryAdmitDrift, Active: true, Generation: gen, DriftCode: drift, Outcome: canary.BudgetDeniedInvalid, Latched: true}
		case !trusted:
			return canaryAdmission{Denial: canaryAdmitUntrusted, Active: true, Generation: gen, Outcome: canary.BudgetDeniedInvalid}
		default:
			denial := canaryAdmitGranted
			if !outcome.Granted() {
				denial = canaryAdmitBudget
			}
			return canaryAdmission{Denial: denial, Active: true, Generation: gen, Trusted: true, Outcome: outcome}
		}
	}
}

// ── activation test helpers ─────────────────────────────────────────────────────────────────
//
// An activation now REQUIRES an explicit reviewed-target set (§2): a set that cannot be produced
// is refused, and no production path may arm without one. Tests therefore construct EXPLICIT
// synthetic reviewed targets rather than getting an implicit default — a helper that quietly
// supplied one would let a production caller's omission go unnoticed, which is the failure mode
// the required field exists to prevent.

// testReviewedTarget is the canonical synthetic reviewed target used by activation tests that are
// not themselves about which target was reviewed. It is deliberately a complete, valid target:
// every field the canonicalizer requires is present, so a test that arms with it is exercising the
// activation, not the validator.
func testReviewedTarget() canary.ReviewedTarget {
	return canary.ReviewedTarget{
		Tenant:            "tenant-a",
		ServerID:          "server-a",
		ToolName:          "tool-a",
		Fingerprint:       tooltrust.FingerprintDigest{0xF1},
		FingerprintFormat: 1,
		ServerIdentity:    reviewedIdentity,
		// READ-ONLY: the canonical synthetic target stands in for THE First-Canary experiment, and
		// the only reviewed class that experiment can execute is read-only — a tool call reaches
		// the side-effect gate as OpRead or not at all. A test that needs a mutating target to be
		// refused states that explicitly rather than inheriting it here.
		OperationClass: policy.OpRead,
	}
}

// testActivationSpec builds an activation spec with explicit reviewed targets; with none supplied
// it uses the canonical synthetic one.
func testActivationSpec(b canary.Budget, now time.Time, targets ...canary.ReviewedTarget) canaryActivationSpec {
	if len(targets) == 0 {
		targets = []canary.ReviewedTarget{testReviewedTarget()}
	}
	return canaryActivationSpec{Budget: b, ReviewedTargets: targets, StartedAt: now}
}

// testBeginActivation arms an activation with the canonical synthetic reviewed target. It is the
// migration seam for tests whose subject is the budget/abort/generation machinery rather than the
// reviewed set; a test ABOUT reviewed targets calls beginCanaryActivation directly with its own.
func testBeginActivation(rt *canaryRuntime, capb rollout.Capability, b canary.Budget, now time.Time) (uint64, error) {
	return rt.beginCanaryActivation(capb, testActivationSpec(b, now))
}

// fpF1 / fpF2 are the reviewed and the post-rug-pull fingerprints used by the drift matrix.
var (
	fpF1 = tooltrust.FingerprintDigest{0xF1}
	fpF2 = tooltrust.FingerprintDigest{0xF2}
)

// reviewedIdentity is the canonical synthetic pinned server identity.
const reviewedIdentity = "spiffe://test/server-a"

// reviewedAt returns the canonical reviewed target bound to a specific fingerprint.
func reviewedAt(fp tooltrust.FingerprintDigest) canary.ReviewedTarget {
	t := testReviewedTarget()
	t.Fingerprint = fp
	return t
}
