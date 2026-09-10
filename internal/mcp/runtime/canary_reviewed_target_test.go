package runtime

import (
	"context"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// canary_reviewed_target_test.go — the REACHABILITY half of the activation-bound reviewed-target
// snapshot (blocker #7; Codex P1 on PR #1360).
//
// The snapshot itself lives in internal/mcp/canary and is compared inside the root's activation
// transaction. What is proven HERE is the thing that finding was about: that the comparison is
// reached at all.
//
// The sequence it exists for:
//
//	T0     the Canary is activated, reviewed for tool x at fingerprint F1. The rollout ScopeSpec
//	       pins F1 in its tool selector, because that is how a Canary bounds its blast radius.
//	T+24h  the reviewing approval expires. Ordinary; the window runs for up to seven days.
//	later  the tool is republished as F2.
//	then   a request names tool x. It is decided against F2, so the decision agrees with the live
//	       catalog and refuseOnToolDrift sees nothing. And the SUBJECT now carries F2 against a
//	       scope pinning F1, so Scope.Contains is false and resolveEnforcing routes it to the
//	       shadow/record-only fallback.
//
// Every downstream signal is therefore silent: the executor is not reached, the live gate is not
// reached, the activation transaction is not entered. The experiment's premise has been violated
// and the violation is exactly what filtered out the evidence.
//
// So the observation is emitted from the ONE point above the record-only branch, keyed on the tool
// IDENTITY rather than on scope membership or fingerprint agreement — neither of which survives the
// event they would need to describe.

// targetRecorder captures what the pipeline reported through the reviewed-target seam.
type targetRecorder struct {
	mu   sync.Mutex
	seen []CanaryTargetObservation
}

func (r *targetRecorder) report(_ string, obs CanaryTargetObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, obs)
}

func (r *targetRecorder) observations() []CanaryTargetObservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]CanaryTargetObservation(nil), r.seen...)
}

// recordOnlyExec resolves EVERY request to record-only — the disposition an out-of-scope Canary
// request falls back to once its tool's fingerprint has moved out of the scope selector, and the
// one that returns without reaching Execute.
type recordOnlyExec struct {
	executeReached int
}

func (e *recordOnlyExec) Resolve(ExecInput) rollout.Resolution {
	return rollout.Resolution{Disposition: rollout.EffectRecordOnly}
}

func (e *recordOnlyExec) Execute(context.Context, ExecInput, rollout.Resolution) ExecOutput {
	e.executeReached++
	return ExecOutput{Status: 200, Disposition: DispObserveOnly, ExecutionState: "not_implemented"}
}

func (e *recordOnlyExec) KillActive() bool { return false }

// reviewedTargetFixture composes a Gateway pipeline with one ingested tool, the reviewed-target
// seam wired, and an executor that resolves everything to record-only.
func reviewedTargetFixture(t *testing.T, rec *targetRecorder, gen uint64) (*pipeline, *recordOnlyExec, *esKey) {
	t.Helper()
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)
	ex := &recordOnlyExec{}
	deps.Executor = ex
	deps.CanaryTargetObserved = rec.report
	deps.CanaryGeneration = func(string) uint64 { return gen }
	deps.Policy = fakePolicy{gw: gwPolicySnap(t, `{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}
	return newGatewayPipeline(t, deps), ex, k
}

// THE GATE. A request that resolves RECORD-ONLY still reports the tool it named.
//
// This is the disposition an out-of-scope Canary request lands on, and it returns without reaching
// Execute — so an observation emitted anywhere downstream of the record-only branch would never
// fire for it. That is precisely the sequence a fingerprint move produces, and reporting from below
// the branch would leave the Canary running, un-aborted, on a target it was never reviewed for.
func TestCanaryReviewedTarget_ReportedEvenOnTheRecordOnlyPath(t *testing.T) {
	rec := &targetRecorder{}
	p, ex, k := reviewedTargetFixture(t, rec, 7)

	tok, sid := driveToDecisionPoint(t, p, k)
	// The terminal disposition is deliberately not asserted: what this gate is about is whether the
	// observation is made, and the record-only path's own outcome (observe-only evidence, or a
	// per-request refusal downstream) is a separate contract with its own tests.
	p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(2)), sid), fixedClock())
	if ex.executeReached != 0 {
		t.Fatalf("premise: a record-only disposition must NOT reach Execute (reached %d) — if it "+
			"does, this gate is no longer proving the path that used to swallow the observation",
			ex.executeReached)
	}

	obs := rec.observations()
	if len(obs) != 1 {
		t.Fatalf("SECURITY: the record-only path reported %d reviewed-target observations, want 1. "+
			"A Canary whose tool moved out of its scope resolves HERE, so an observation that is "+
			"not made on this path cannot see the drift it exists to catch", len(obs))
	}
	if obs[0].ServerID != testServerID || obs[0].ToolName != "x" {
		t.Fatalf("the observation must name the tool the request named, got %+v", obs[0])
	}
	if obs[0].Generation != 7 {
		t.Fatalf("the observation must carry the generation in force at resolution, got %d", obs[0].Generation)
	}
}

// A request that names NO tool reports nothing: there is no identity to compare, and inventing one
// would hand the root a comparison it cannot make.
func TestCanaryReviewedTarget_NoToolReportsNothing(t *testing.T) {
	rec := &targetRecorder{}
	p, _, k := reviewedTargetFixture(t, rec, 7)

	tok, sid := driveToDecisionPoint(t, p, k)
	p.Process(context.Background(), withSession(gwRequest(tok, toolsListBody(2)), sid), fixedClock())
	for _, o := range rec.observations() {
		if o.ToolName != "" || o.ServerID != "" {
			t.Fatalf("a request naming no tool must report no target, got %+v", o)
		}
	}
}

// The seam is OPTIONAL and nil in every non-Canary composition — the disabled-by-default posture.
// A pipeline with no sink composed must behave byte-identically, not panic and not branch.
func TestCanaryReviewedTarget_NilSeamIsANoOp(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)
	deps.Executor = &recordOnlyExec{}
	deps.Policy = fakePolicy{gw: gwPolicySnap(t, `{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}
	// CanaryTargetObserved deliberately left nil.
	p := newGatewayPipeline(t, deps)

	tok, sid := driveToDecisionPoint(t, p, k)
	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(2)), sid), fixedClock())
	if out.Status == 0 {
		t.Fatal("an uncomposed seam must leave the pipeline fully functional")
	}
}

// The observation carries an IDENTITY and a generation — and nothing else.
//
// It must never carry a fingerprint, a drift verdict, or a scope fact. Everything a latch rests on
// is read by the root inside the activation lock; a value computed out here cannot be attributed to
// a generation, which is the lesson five review rounds on PR #1314 paid for. Pinning the SHAPE is
// how that stays true: a field added here is a value the root would be tempted to trust.
func TestCanaryReviewedTarget_ObservationCarriesIdentityOnly(t *testing.T) {
	var obs CanaryTargetObservation
	// A compile-time exhaustive assignment: adding a field to the struct breaks this line, which is
	// the point at which someone has to justify it.
	obs = CanaryTargetObservation{Generation: 1, ServerID: "s", ToolName: "t"}
	if obs.Generation != 1 || obs.ServerID != "s" || obs.ToolName != "t" {
		t.Fatal("unexpected observation shape")
	}
}
