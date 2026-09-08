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
		Generation: g, Code: "server_identity_drift", Tenant: ttTenant,
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
		Generation: g, Code: "server_identity_drift", Tenant: ttTenant,
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
		Generation: 1, Code: "server_identity_drift", Tenant: ttTenant,
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

// TestPreAdmissionDrift_E2E_StaleObservationCannotStopTheReplacement is the round-22 scope gate.
//
// A request resolved under G1 can detect drift and then pause. If G1 is demoted and G2 activated
// with a scope that EXCLUDES this target, latching G2 stops an unrelated experiment for something
// outside its own blast radius — the round-15 lesson from the other side. The activation runtime
// holds no scope (scope is computed per request by the pipeline from rollout.State), so the latch
// cannot ask "is this target in G2's scope"; it asks the question it CAN answer exactly — is the
// activation still the one this observation was made under.
//
// Generations are strictly monotonic and never reused (TestAutoStop_ActivationGenerationIsStrictly-
// Monotonic), so a mismatch means an activation intervened. That is a statement about the window,
// not a counter-equality argument: the comparison value is captured before the resolution and the
// comparison itself happens inside the activation lock.
func TestPreAdmissionDrift_E2E_StaleObservationCannotStopTheReplacement(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	resetPreAdmissionDriftForTest(t)

	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, fn := liveFakeClock()
	composeToolTrust(t, fn)
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())

	r := newAtomicRig(t)
	g1 := r.arm(t, 4)

	// Real, authoritative drift: the server is republished disabled.
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

	// G1 goes away and G2 takes its place while the observation is in flight.
	r.rt.demoteCanary(r.capb)
	g2 := r.arm(t, 4)
	if g2 == g1 {
		t.Fatalf("premise: a re-activation must never reuse a generation (%d)", g1)
	}

	// The stale G1 observation arrives.
	canaryPreAdmissionDrift(rollout.CapabilityGateway.String(), mcpruntime.CanaryDriftTarget{
		Generation: g1, Code: "server_identity_drift", Tenant: ttTenant,
		ServerID: sid, ToolName: tool, DecisionFP: fpHex,
	})

	if !r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatalf("SECURITY: a drift observed under activation %d stopped activation %d, whose "+
			"scope may exclude this target entirely — a stale observation must never stop the "+
			"experiment that replaced the one it was made under (Codex round 22)", g1, g2)
	}
	// The evidence is still recorded: the operator learns the catalog moved either way.
	if got := canaryPreAdmissionDriftCounts(rollout.CapabilityGateway.String()); got["server_identity_drift"] != 1 {
		t.Fatalf("evidence must be recorded even when the latch is skipped: %v", got)
	}
	// And a fresh observation under G2 DOES stop it — the skip is not a silent hole.
	canaryPreAdmissionDrift(rollout.CapabilityGateway.String(), mcpruntime.CanaryDriftTarget{
		Generation: g2, Code: "server_identity_drift", Tenant: ttTenant,
		ServerID: sid, ToolName: tool, DecisionFP: fpHex,
	})
	if r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatalf("an in-generation observation failed to stop activation %d", g2)
	}
}

// TestPreAdmissionDrift_E2E_GenerationZeroLatchesNothing pins §7: 0 names no activation and is
// NEVER read as "whatever is current". That wildcard is how an earlier revision inverted its own
// fix into the defect it was closing.
func TestPreAdmissionDrift_E2E_GenerationZeroLatchesNothing(t *testing.T) {
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

	r := newAtomicRig(t)
	g := r.arm(t, 4)

	canaryPreAdmissionDrift(rollout.CapabilityGateway.String(), mcpruntime.CanaryDriftTarget{
		Generation: 0, Code: "server_identity_drift", Tenant: ttTenant,
		ServerID: sid, ToolName: tool, DecisionFP: fpHex,
	})
	if !r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatalf("SECURITY (§7): an observation naming NO activation stopped activation %d — "+
			"generation 0 is being read as \"whatever is current\"", g)
	}
}
