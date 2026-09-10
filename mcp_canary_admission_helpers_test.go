package main

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
)

// stubAdmitUnderActivation builds an admitUnderActivation double for gate tests that are not about
// activation binding: it still EVALUATES the trust probe (so the trust seam those tests control
// keeps its meaning) and reports a fixed generation and budget outcome.
//
// It deliberately reproduces the real transaction's ordering — drift beats untrusted beats budget —
// so a test using it cannot pass against a gate that reads the result fields in the wrong order.
func stubAdmitUnderActivation(outcome canary.BudgetOutcome, gen uint64) func(time.Time, canary.ExecutionIdentity, canaryTrustProbe) canaryAdmission {
	return func(_ time.Time, _ canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission {
		trusted, drift := true, ""
		if trust != nil {
			trusted, drift = trust()
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
