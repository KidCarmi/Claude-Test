package main

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// Codex round-4 P1 fixes: the runtime live-trust revalidation must bind to the DECISION's fingerprint
// (not merely the current one) and reject a server that is no longer usable at the boundary.

// liveTrustVerdict composes the two halves EXACTLY as mcpLiveSideEffectGate does, so these tests
// exercise the shipped path. A single convenience wrapper used to exist for this, but once the
// halves were split it had no production caller left — a function that only tests reach is not the
// live path, however faithfully it is written, and keeping it would have let these tests drift away
// from what the gate actually runs.
// The class is fixed at OpRead here because that is the ONLY class a First-Canary tool call can
// carry across the side-effect gate; these tests are about the fingerprint binding, not the class.
func liveTrustVerdict(tenant, serverID, toolName, decisionFP string, now time.Time) (trusted bool, driftCode string) {
	live := mcpLiveTrustPrecheck(tenant, serverID, toolName, decisionFP)
	if live.DriftCode != "" {
		return false, live.DriftCode
	}
	if !live.Eligible {
		return false, ""
	}
	return mcpLiveApprovalSatisfied(live.Target, policy.OpRead, now)
}

// P1a: live-trust revalidation binds trust to the decision fingerprint. A valid live approval for the
// CURRENT fingerprint must NOT authorize a request that was decided under a DIFFERENT fingerprint
// (the F1→F2→F1 catalog-flap class), and an empty decision fingerprint fails closed.
func TestLiveTrustRevalidate_BindsToDecisionFingerprint(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	clk, fn := liveFakeClock()
	composeToolTrust(t, fn)
	_ = clk
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	now := mcpToolTrust.now()

	// Baseline: the decision fingerprint equals the current target ⇒ a valid approval revalidates OK.
	if ok, _ := liveTrustVerdict(ttTenant, sid, tool, fpHex, now); !ok {
		t.Fatal("a valid live approval bound to the current fingerprint must revalidate OK")
	}
	// P1a: a decision fingerprint that does NOT match the current target is denied, even though a
	// valid approval exists for the current fingerprint (an F2 approval cannot authorize an F1 request).
	otherFP := "deadbeefdeadbeef" + fpHex[16:]
	if otherFP == fpHex {
		otherFP = "0123456789abcdef" + fpHex[16:]
	}
	if ok, _ := liveTrustVerdict(ttTenant, sid, tool, otherFP, now); ok {
		t.Fatal("P1a: a decision fingerprint that does not match the current target must be denied")
	}
	// An empty decision fingerprint fails closed.
	if ok, _ := liveTrustVerdict(ttTenant, sid, tool, "", now); ok {
		t.Fatal("an empty decision fingerprint must be denied")
	}
	// A DIFFERENT tenant naming the same server/tool is denied, and denied REQUEST-SCOPED rather
	// than as drift: a Canary correctly refusing another tenant's request is a Canary working, not
	// evidence the reviewed target changed, so it must never stop the experiment.
	ok, code := liveTrustVerdict("tenant-not-ours", sid, tool, fpHex, now)
	if ok {
		t.Fatal("a target that is not this tenant's reviewed one must be denied")
	}
	if code != "" {
		t.Fatalf("a cross-tenant denial reported drift code %q — it must be request-scoped, or one "+
			"tenant could stop another tenant's Canary by naming its server", code)
	}
}

// P1b: a server that is no longer usable at the boundary (disabled / lost identity verification after
// the decision snapshot) is denied, even though a valid live approval for the tool still exists.
func TestLiveTrustRevalidate_RejectsUnusableServer(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	clk, fn := liveFakeClock()
	composeToolTrust(t, fn)
	_ = clk
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	now := mcpToolTrust.now()
	if ok, _ := liveTrustVerdict(ttTenant, sid, tool, fpHex, now); !ok {
		t.Fatal("precondition: the valid approval must revalidate OK before the server is disabled")
	}

	// Re-publish the SAME tool under a DISABLED server (the approval is unchanged). The boundary must
	// now fail closed because the server is no longer usable.
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

	if ok, _ := liveTrustVerdict(ttTenant, sid, tool, fpHex, now); ok {
		t.Fatal("P1b: a request against a server that is no longer usable must be denied at the boundary")
	}
}

// TestLiveTrustRevalidate_RugPullIsRequestScopedNotDriftInference is the INVERSION of the test this
// replaced, and the inversion is the point.
//
// The superseded gate inferred whole-Canary drift inside the approval half: a live approval still
// pinned to the reviewed fingerprint, against a request decided under a NEW one, was read as
// "the reviewed tool moved". That inference used approval LIFETIME as drift memory, so it evaporated
// the moment the approval expired — the exact window a patient attacker waits for, and the reason
// the activation now carries its own immutable reviewed-target snapshot instead.
//
// So the approval half must NOT classify this any more. A rug-pulled target is still DENIED here
// (nothing approves F2), request-scoped and with no drift code; the authoritative drift verdict is
// produced by comparing the activation's reviewed snapshot against the current target under the
// activation lock, and is proven in the reviewed-binding matrix
// (mcp_canary_reviewed_binding_test.go), where it survives approval expiry.
func TestLiveTrustRevalidate_RugPullIsRequestScopedNotDriftInference(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, fn := liveFakeClock()
	composeToolTrust(t, fn)
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	now := mcpToolTrust.now()

	if ok, code := liveTrustVerdict(ttTenant, sid, tool, fpHex, now); !ok || code != "" {
		t.Fatalf("premise: the approved target must revalidate OK, got ok=%v code=%q", ok, code)
	}

	// The rug-pull: the SAME tool, republished with a different schema, so its composite
	// fingerprint changes. The approval is untouched and still names the reviewed fingerprint.
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"` + tool + `","input_schema":{"type":"object","properties":{"rug":{"type":"string"}}}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode rug-pulled inventory: %v", err)
	}
	reg2, cat2, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed rug-pulled inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg2, cat2)

	rec, ok := cat2.Current().Get(catalog.ToolKey{Server: registry.ServerID(sid), Name: tool})
	if !ok {
		t.Fatal("the rug-pulled tool is not in the catalog")
	}
	sum := rec.Fingerprint.Sum()
	newFP := hexOf(sum[:])
	if newFP == fpHex {
		t.Fatal("premise: the republished tool must carry a DIFFERENT fingerprint")
	}

	// A request decided against the NEW fingerprint is denied — nothing approves F2.
	gotOK, gotCode := liveTrustVerdict(ttTenant, sid, tool, newFP, now)
	if gotOK {
		t.Fatal("a rug-pulled target must not be trusted")
	}
	if gotCode != "" {
		t.Fatalf("drift code = %q, want empty: the approval half must not infer drift from an "+
			"approval still pinned to the superseded fingerprint. Inferring it here makes drift "+
			"detection expire with the approval, which is the defect the activation-bound "+
			"reviewed-target snapshot exists to close", gotCode)
	}

	// And the inference must not reappear once the approval is gone: an EXPIRED approval leaves
	// the approval half with nothing to read, yet the drift is real. Only the activation snapshot
	// can still see it — the matrix proves it does.
	if ok, code := liveTrustVerdict(ttTenant, sid, tool, newFP, now.Add(48*time.Hour)); ok || code != "" {
		t.Fatalf("after approval expiry the approval half must stay a plain denial, got ok=%v code=%q", ok, code)
	}
}

// TestLiveTrustRevalidate_UnapprovedIsNotDrift is the control for the rug-pull classification, and
// it drives the REAL approval store rather than a stub: a gate that only ever sees a stubbed
// verdict cannot notice the classifier becoming indiscriminate.
//
// Without this, "report drift whenever the approval check fails" would satisfy the rug-pull test
// while turning every unauthorized request into a kill switch for the whole experiment — the
// direction a safety control must never err in.
func TestLiveTrustRevalidate_UnapprovedIsNotDrift(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, fn := liveFakeClock()
	composeToolTrust(t, fn)
	grant := requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	now := mcpToolTrust.now()

	if ok, code := liveTrustVerdict(ttTenant, sid, tool, fpHex, now); !ok || code != "" {
		t.Fatalf("premise: the approved target must revalidate OK, got ok=%v code=%q", ok, code)
	}

	// Revoked: the tool is unchanged, so nothing says the reviewed target moved. This is an
	// ordinary unauthorized request.
	if _, err := mcpToolTrust.Revoke(grant.ApprovalID, "admin2", ttTenant, "no longer needed"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	ok, code := liveTrustVerdict(ttTenant, sid, tool, fpHex, now)
	if ok {
		t.Fatal("a revoked approval must not authorize live execution")
	}
	if code != "" {
		t.Fatalf("drift code = %q, want empty — a revoked or missing approval is REQUEST-SCOPED, "+
			"and classifying it as drift makes every unauthorized caller able to stop the Canary", code)
	}
}
