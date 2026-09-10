package runtime

// canary_drift_breach_test.go — a tool rug-pull refused BEFORE the executor is an authoritative
// whole-Canary breach, not merely a stale decision (First Controlled Canary review, blocker #7;
// Codex round 14).

import (
	"encoding/hex"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// breachRecorder captures what the pipeline recorded through the optional drift-EVIDENCE seam.
//
// It no longer records a generation, and the absence is the contract: this observation happens
// before any reservation, so there is no activation it belongs to and none is offered. A seam that
// still carried one would invite the caller to attribute an unattributable fact.
type breachRecorder struct {
	mu      sync.Mutex
	seen    []string
	targets []CanaryDriftTarget
}

func (r *breachRecorder) report(_ string, obs CanaryDriftTarget) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, obs.Code)
	r.targets = append(r.targets, obs)
}

func (r *breachRecorder) observations() []CanaryDriftTarget {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]CanaryDriftTarget(nil), r.targets...)
}

func (r *breachRecorder) codes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// driftFixture ingests one tool and returns a pipeline plus a DecisionInput whose fingerprint no
// longer matches the live catalog — the exact shape refuseOnToolDrift exists to refuse.
func driftFixture(t *testing.T, rec *breachRecorder) (p *pipeline, stale, fresh policy.DecisionInput) {
	t.Helper()
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	live := ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)
	if rec != nil {
		deps.CanaryDriftObserved = rec.report
	}
	pl := newGatewayPipeline(t, deps)

	liveRec, ok := deps.Catalog.Current().Get(catalog.ToolKey{
		Server: registry.ServerID(testServerID), Name: "x",
	})
	if !ok {
		t.Fatal("the ingested tool is not in the catalog")
	}
	disp, drift := policyDisposition(liveRec.Eligibility)
	mk := func(fp string) policy.DecisionInput {
		return policy.DecisionInput{
			Capability: policy.CapGateway,
			Principal:  policy.Principal{Tenant: driftTenant},
			Tool: &policy.Tool{
				Name: "x", ServerID: testServerID, FingerprintHash: fp,
				Disposition: disp, Drift: drift,
			},
		}
	}
	return pl, mk("stale" + live), mk(live)
}

// TestCanaryBreach_PreExecutorToolDriftIsReported pins the PRE-EXECUTOR half of the drift funnel.
//
// This refusal happens before the composition-layer admission gate is ever reached, so the gate's
// own drift classifier cannot see it. Left unreported, a rug-pull landing in that window failed the
// request and left the Canary holding execution authority — and every later request against the new
// fingerprint then merely failed approval validation, which looks like ordinary denial rather than
// proof the experiment's premise no longer holds (Codex round 14).
func TestCanaryBreach_PreExecutorToolDriftIsReported(t *testing.T) {
	rec := &breachRecorder{}
	p, stale, _ := driftFixture(t, rec)

	rb := p.newRecord(Request{}, fixedClock())
	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}, true, driftTestGen); !refused {
		t.Fatal("premise: a stale fingerprint must be refused here")
	}

	got := rec.codes()
	if len(got) != 1 || got[0] != "tool_fingerprint_drift" {
		t.Fatalf("SECURITY: a rug-pull refused before the executor must also stop the whole "+
			"Canary — the request failing is not the same as the experiment stopping; reported=%v", got)
	}
}

// THE CONTROL: a CURRENT fingerprint reports nothing. Without it the fix is satisfiable by
// reporting a breach on every request, which would stop a healthy Canary immediately.
func TestCanaryBreach_CurrentFingerprintReportsNothing(t *testing.T) {
	rec := &breachRecorder{}
	p, _, fresh := driftFixture(t, rec)

	rb := p.newRecord(Request{}, fixedClock())
	if _, refused := p.refuseOnToolDrift(rb, fresh, jsonrpc.ID{}, true, driftTestGen); refused {
		t.Fatal("premise: a current fingerprint must not be refused")
	}
	if got := rec.codes(); len(got) != 0 {
		t.Fatalf("an undrifted decision must report no breach, got %v", got)
	}
}

// A pipeline with NO seam composed — every non-Canary posture, including the shipped default —
// behaves exactly as before: it refuses, and reports nowhere. The nil check is the disabled-by-
// default guarantee, so it gets its own gate rather than being assumed.
func TestCanaryBreach_NoSeamComposedIsAPlainRefusal(t *testing.T) {
	p, stale, _ := driftFixture(t, nil)

	rb := p.newRecord(Request{}, fixedClock())
	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}, true, driftTestGen); !refused {
		t.Fatal("a stale fingerprint must still be refused with no seam composed")
	}
}

// TestCanaryBreach_ShadowEvaluationDoesNotStopTheCanary pins the SCOPE binding, and it guards the
// direction a safety control must never err in.
//
// With Shadow fallback enabled, an OUT-OF-SCOPE request under Canary mode resolves to a shadow
// evaluation and still reaches this refusal. Reported unconditionally, a catalog change for a tool
// the experiment never reviewed would abort the whole Canary — and to an operator, a healthy
// experiment stopped for something outside its own blast radius is indistinguishable from the
// control being broken (Codex round 15).
func TestCanaryBreach_ShadowEvaluationDoesNotStopTheCanary(t *testing.T) {
	rec := &breachRecorder{}
	p, stale, _ := driftFixture(t, rec)

	rb := p.newRecord(Request{}, fixedClock())
	// canaryScoped=false is what dispatchExecute passes for a shadow evaluation.
	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}, false, driftTestGen); !refused {
		t.Fatal("premise: the request must still be REFUSED — only the whole-Canary stop is scoped")
	}
	if got := rec.codes(); len(got) != 0 {
		t.Fatalf("SECURITY: drift on traffic outside the Canary's reviewed scope stopped the whole "+
			"experiment, reported=%v", got)
	}
}

// TestCanaryBreach_EligibilityDriftIsNotCalledFingerprintDrift pins the drift CLASS.
//
// toolHasDrifted is true for two different facts: the fingerprint moved, and the eligibility moved
// with the fingerprint unchanged (catalog.DisableServer, a quarantine, a review requirement).
// Hard-coding tool_fingerprint_drift told an operator the tool's SHAPE changed when what happened
// was their own DisableServer — and because the admission-time classifier calls that same condition
// server_identity_drift, the immutable first cause depended on which detection window won the race
// (Codex round 15). Two windows must not disagree about what one fact is called.
func TestCanaryBreach_EligibilityDriftIsNotCalledFingerprintDrift(t *testing.T) {
	rec := &breachRecorder{}
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	live := ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)
	deps.CanaryDriftObserved = rec.report
	p := newGatewayPipeline(t, deps)

	liveRec, ok := deps.Catalog.Current().Get(catalog.ToolKey{
		Server: registry.ServerID(testServerID), Name: "x",
	})
	if !ok {
		t.Fatal("the ingested tool is not in the catalog")
	}
	disp, drift := policyDisposition(liveRec.Eligibility)

	// The decision carries the CURRENT fingerprint; only the eligibility axis will move.
	in := policy.DecisionInput{
		Capability: policy.CapGateway,
		Tool: &policy.Tool{
			Name: "x", ServerID: testServerID, FingerprintHash: live,
			Disposition: disp, Drift: drift,
		},
	}
	rb := p.newRecord(Request{}, fixedClock())
	if _, refused := p.refuseOnToolDrift(rb, in, jsonrpc.ID{}, true, driftTestGen); refused {
		t.Fatal("premise: nothing has drifted yet")
	}

	// The operator disables the server. The fingerprint is deliberately preserved by the catalog.
	deps.Catalog.DisableServer(registry.ServerID(testServerID))
	after, ok := deps.Catalog.Current().Get(catalog.ToolKey{
		Server: registry.ServerID(testServerID), Name: "x",
	})
	if !ok {
		t.Fatal("premise: the record must still exist, only its eligibility changes")
	}
	sum := after.Fingerprint.Sum()
	if hex.EncodeToString(sum[:]) != live {
		t.Fatal("premise: DisableServer must preserve the fingerprint, or this test proves nothing")
	}

	if _, refused := p.refuseOnToolDrift(rb, in, jsonrpc.ID{}, true, driftTestGen); !refused {
		t.Fatal("an eligibility change must still be refused")
	}
	got := rec.codes()
	if len(got) != 1 || got[0] != "server_identity_drift" {
		t.Fatalf("SECURITY: an eligibility change must be reported as server_identity_drift — the "+
			"fingerprint did not move, and the admission-time classifier calls this same condition "+
			"by that name; reported=%v", got)
	}
}

const driftTenant = "tenant-drift-fixture"

// TestCanaryBreach_PreExecutorDriftCarriesItsTarget pins that the observation reaches the root with
// the identity of the target it was made against.
//
// This is not bookkeeping. The root does NOT trust the verdict computed here — it re-derives the
// drift live inside the activation critical section, and it can only do that if it knows which
// tenant/server/tool/fingerprint to re-check. Drop any of those fields and the re-derivation looks
// up a target it cannot match, which mcpLiveTrustRevalidate correctly classifies as request-scoped
// rather than drift — so the whole-Canary latch silently never fires and the failure looks exactly
// like a healthy Canary. An empty target is therefore a security defect that is invisible at every
// other surface, which is why it is pinned at the seam.
func TestCanaryBreach_PreExecutorDriftCarriesItsTarget(t *testing.T) {
	rec := &breachRecorder{}
	p, stale, _ := driftFixture(t, rec)

	rb := p.newRecord(Request{}, fixedClock())
	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}, true, driftTestGen); !refused {
		t.Fatal("the fixture must produce an authoritative drift refusal")
	}

	obs := rec.observations()
	if len(obs) != 1 {
		t.Fatalf("want exactly one observation, got %d", len(obs))
	}
	got := obs[0]
	if got.Code == "" {
		t.Fatal("the drift code is empty")
	}
	if got.Generation != driftTestGen {
		t.Fatalf("Generation = %d, want %d — the root refuses to latch an observation that names "+
			"no activation, so reporting 0 here silently disables the whole-Canary latch for "+
			"every pre-executor drift", got.Generation, driftTestGen)
	}
	if got.Tenant != driftTenant {
		t.Fatalf("Tenant = %q, want %q — the root cannot re-derive a drift for an unnamed tenant", got.Tenant, driftTenant)
	}
	if got.ServerID != testServerID {
		t.Fatalf("ServerID = %q, want %q", got.ServerID, testServerID)
	}
	if got.ToolName != "x" {
		t.Fatalf("ToolName = %q, want %q", got.ToolName, "x")
	}
	if got.DecisionFP != stale.Tool.FingerprintHash {
		t.Fatalf("DecisionFP = %q, want the DECISION's fingerprint %q — re-deriving against the "+
			"live fingerprint instead of the decision's would compare a value to itself and never "+
			"report drift", got.DecisionFP, stale.Tool.FingerprintHash)
	}
}

// TestCanaryBreach_PreExecutorDriftToleratesAMissingTool pins that a malformed input cannot panic
// the refusal path. It yields an unmatchable target, which fails closed to "no latch".
func TestCanaryBreach_PreExecutorDriftToleratesAMissingTool(t *testing.T) {
	if got := toolServerID(policy.DecisionInput{}); got != "" {
		t.Fatalf("toolServerID = %q, want empty", got)
	}
	if got := toolName(policy.DecisionInput{}); got != "" {
		t.Fatalf("toolName = %q, want empty", got)
	}
	if got := toolFingerprint(policy.DecisionInput{}); got != "" {
		t.Fatalf("toolFingerprint = %q, want empty", got)
	}
}

// driftTestGen is a non-zero activation generation for the refusal fixtures. It must be non-zero:
// the root refuses to latch on generation 0, so a fixture passing 0 would exercise the
// fail-closed branch rather than the path under test.
const driftTestGen uint64 = 7
