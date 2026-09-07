package main

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// mcp_canary_preadmission_e2e_test.go — the pre-executor drift latch, driven through the REAL
// composition-root sink and the REAL live-trust revalidation.
//
// WHY THIS FILE IS SEPARATE FROM THE MATRIX. The §8 matrix drives
// canaryRuntime.latchDriftUnderActivation directly, which proves the PRIMITIVE is
// activation-bound. It does not prove the primitive is REACHED. Deleting the latch call out of
// canaryPreAdmissionDrift leaves every matrix case green while restoring exactly the defect Codex
// round 20 named: the pipeline observes an authoritative drift, counts it, and the experiment runs
// on. A gate that cannot see its own subject being removed is not a gate, so the wiring gets its
// own end-to-end case with no stubbed trust probe.

// TestPreAdmissionDrift_E2E_ServerIdentityDriftStopsTheActivation drives the whole path: a real
// approved live target, a real activation, a real revocation (the server is republished disabled),
// and then the sink the runtime pipeline actually calls.
func TestPreAdmissionDrift_E2E_ServerIdentityDriftStopsTheActivation(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	resetPreAdmissionDriftForTest(t)

	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, fn := liveFakeClock()
	composeToolTrust(t, fn)
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())

	r := newAtomicRig(t)
	g := r.arm(t, 4)

	// Precondition: with the approved target intact, the sink must latch NOTHING. Without this the
	// test could pass by latching unconditionally.
	canaryPreAdmissionDrift(rollout.CapabilityGateway.String(), mcpruntime.CanaryDriftTarget{
		Code: "server_identity_drift", Tenant: ttTenant,
		ServerID: sid, ToolName: tool, DecisionFP: fpHex,
	})
	if !r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatal("SECURITY: a healthy target latched the Canary — the sink is not re-deriving the " +
			"drift, it is trusting the caller's verdict")
	}

	// Now revoke for real: republish the SAME tool under a DISABLED server. This is the operator
	// action that says "stop calling this server", and it is authoritative drift.
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"id","enabled":false,
	   "tools":[{"name":"` + tool + `","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode disabled inventory: %v", err)
	}
	reg2, cat2, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed disabled inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg2, cat2)

	canaryPreAdmissionDrift(rollout.CapabilityGateway.String(), mcpruntime.CanaryDriftTarget{
		Code: "server_identity_drift", Tenant: ttTenant,
		ServerID: sid, ToolName: tool, DecisionFP: fpHex,
	})

	if r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatalf("SECURITY: activation %d is STILL execution-eligible after an authoritative "+
			"pre-executor drift. The breach condition is declared whole-Canary but stops nothing — "+
			"and no later request will latch it either, because later requests resolve against the "+
			"new target and are denied as request-scoped, not drift (Codex round 20)", g)
	}
	if adm := r.admit(probeTrusted()); adm.Denial != canaryAdmitAborted {
		t.Fatalf("a request after the pre-executor latch was denied %v, want canaryAdmitAborted", adm.Denial)
	}

	// The evidence half is independent of the latch and must be recorded for BOTH calls.
	if got := canaryPreAdmissionDriftCounts(rollout.CapabilityGateway.String()); got["server_identity_drift"] != 2 {
		t.Fatalf("server_identity_drift evidence = %d, want 2", got["server_identity_drift"])
	}
}

// TestPreAdmissionDrift_E2E_PublicationGapLatchesNothing pins §6 through the same real path: with no
// live activation, a genuine authoritative drift is counted and latches nothing, and the activation
// published afterwards is born healthy.
func TestPreAdmissionDrift_E2E_PublicationGapLatchesNothing(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	resetPreAdmissionDriftForTest(t)

	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, fn := liveFakeClock()
	composeToolTrust(t, fn)
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())

	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"id","enabled":false,
	   "tools":[{"name":"` + tool + `","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode disabled inventory: %v", err)
	}
	reg2, cat2, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed disabled inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg2, cat2)

	r := newAtomicRig(t) // deliberately NOT armed — the publication gap
	canaryPreAdmissionDrift(rollout.CapabilityGateway.String(), mcpruntime.CanaryDriftTarget{
		Code: "server_identity_drift", Tenant: ttTenant,
		ServerID: sid, ToolName: tool, DecisionFP: fpHex,
	})
	if got := canaryPreAdmissionDriftCounts(rollout.CapabilityGateway.String()); got["server_identity_drift"] != 1 {
		t.Fatalf("evidence must be recorded even with no activation: %v", got)
	}

	g := r.arm(t, 4)
	if !r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatalf("SECURITY: activation %d inherited a drift observed before it existed (§6)", g)
	}
}
