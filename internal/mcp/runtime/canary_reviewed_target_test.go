package runtime

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
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
	seen           []policy.DecisionInput
}

func (e *recordOnlyExec) Resolve(in ExecInput) rollout.Resolution {
	e.seen = append(e.seen, in.Input)
	return rollout.Resolution{Disposition: rollout.EffectRecordOnly}
}

func (e *recordOnlyExec) Execute(context.Context, ExecInput, rollout.Resolution) ExecOutput {
	e.executeReached++
	return ExecOutput{Status: 200, Disposition: DispObserveOnly, ExecutionState: "not_implemented"}
}

func (e *recordOnlyExec) KillActive() bool { return false }

// resolvedInputs records the DecisionInput the executor was handed, so a gate can compare the
// identity REPORTED to the sink against the identity the policy path actually decided about.
func (e *recordOnlyExec) resolvedInputs() []policy.DecisionInput {
	return append([]policy.DecisionInput(nil), e.seen...)
}

// reviewedTargetFixture composes a Gateway pipeline with one ingested tool, the reviewed-target
// seam wired, and an executor that resolves everything to record-only. Each opt may further shape
// the deps BEFORE the pipeline is built — used to drive the early-return paths that return above
// the executor entirely.
func reviewedTargetFixture(t *testing.T, rec *targetRecorder, gen uint64, opts ...func(*Deps)) (*pipeline, *recordOnlyExec, *esKey) {
	t.Helper()
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)
	ex := &recordOnlyExec{}
	deps.Executor = ex
	deps.CanaryTargetObserved = rec.report
	deps.CanaryGeneration = func(string) uint64 { return gen }
	deps.Policy = fakePolicy{gw: gwPolicySnap(t, `{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}
	for _, o := range opts {
		o(&deps)
	}
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
//
// This is done by REFLECTION rather than by an exhaustive struct literal, because a literal proves
// nothing — Go does not require one to be exhaustive, so adding a field leaves it compiling and the
// gate silently stops guarding anything. (The literal form was written first and staticcheck's
// S1021 is what sent it back for a second look; the lint was cosmetic, the defect underneath was
// not.)
func TestCanaryReviewedTarget_ObservationCarriesIdentityOnly(t *testing.T) {
	want := map[string]string{
		"Generation": "uint64",
		"ServerID":   "string",
		"ToolName":   "string",
	}
	typ := reflect.TypeOf(CanaryTargetObservation{})
	if typ.NumField() != len(want) {
		t.Fatalf("CanaryTargetObservation has %d fields, want %d: a field added here is a value the "+
			"root would be tempted to trust, and anything a latch rests on must be read inside the "+
			"activation lock instead", typ.NumField(), len(want))
	}
	for i := range typ.NumField() {
		f := typ.Field(i)
		kind, ok := want[f.Name]
		if !ok {
			t.Fatalf("unexpected field %q on CanaryTargetObservation", f.Name)
		}
		if f.Type.String() != kind {
			t.Fatalf("field %q is %s, want %s", f.Name, f.Type, kind)
		}
	}
}

// --- the early-return half (Codex P1, PR #1360, round 2) --------------------
//
// The record-only gate above proves the observation survives the disposition an out-of-scope
// Canary request falls back to. It does NOT prove the observation is reached at all, because
// dispatchPolicy returns from three places ABOVE the executor:
//
//	no published policy snapshot   → fail-closed rejection
//	semantic inspection hard-fail  → BLOCKED_BY_INSPECTION
//	request budget expired         → the deadline outcome
//
// The middle one is not a hypothetical. The F1→F2 republish this whole mechanism exists to catch
// is, very often, a SCHEMA change — and a new schema that rejects arguments the old one accepted
// hard-fails inspection for every request from the clients still sending the old shape. So the
// exact event that moves the reviewed target is also an event that stops those requests above the
// executor, and an observation emitted below inspection would report nothing for precisely the
// population that proves the target moved. The Canary would keep running, un-aborted, on a target
// nobody reviewed.
//
// These gates therefore pin the PLACEMENT, not the outcome. None of them asserts that the request
// succeeded — every one of them is about a request that FAILED, and the claim is that a failed
// request still tells the truth about which tool it named.

// THE GATE for the finding. A request that inspection hard-blocks still reports its target.
func TestCanaryReviewedTarget_ReportedWhenInspectionHardFails(t *testing.T) {
	rec := &targetRecorder{}
	p, ex, k := reviewedTargetFixture(t, rec, 11, func(d *Deps) {
		d.Inspection = fakeInspection{gw: gwInspectionProfile(t)}
	})

	tok, sid := driveToDecisionPoint(t, p, k)
	// A private destination in the args: a hard SSRF block, which returns from dispatchPolicy
	// above the executor. Any hard-fail reason would do — what is being driven is the RETURN.
	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsCallArgs(3, "x", `{"url":"https://10.0.0.1/x"}`)), sid), fixedClock())

	if out.Reason != mcperr.ReasonSSRFBlocked || out.Record.PolicyAction != "BLOCKED_BY_INSPECTION" {
		t.Fatalf("premise: this request must hard-fail inspection, got reason=%v action=%q — if it "+
			"no longer does, this gate is not exercising the early return it exists for",
			out.Reason.Code(), out.Record.PolicyAction)
	}
	if ex.executeReached != 0 || len(ex.resolvedInputs()) != 0 {
		t.Fatalf("premise: an inspection hard-fail must return ABOVE the executor (Resolve=%d "+
			"Execute=%d)", len(ex.resolvedInputs()), ex.executeReached)
	}

	obs := rec.observations()
	if len(obs) != 1 {
		t.Fatalf("SECURITY: an inspection-hard-failed request reported %d reviewed-target "+
			"observations, want 1. A tool republished with a stricter schema hard-fails every "+
			"request still sending the old argument shape, so a Canary whose reviewed target moved "+
			"that way would produce ONLY these requests — and reporting nothing for them leaves the "+
			"experiment recorded as healthy on a target it was never reviewed for", len(obs))
	}
	if obs[0].ServerID != testServerID || obs[0].ToolName != "x" {
		t.Fatalf("the observation must name the tool the request named, got %+v", obs[0])
	}
	if obs[0].Generation != 11 {
		t.Fatalf("the observation must carry the live generation, got %d", obs[0].Generation)
	}
}

// A request rejected because NO policy snapshot is published still reports its target.
//
// That return is the very first one in dispatchPolicy — above even the DecisionInput the identity
// used to be read from — so it is the one that decides whether the identity may be derived from the
// snapshot at all. It may not.
func TestCanaryReviewedTarget_ReportedWhenNoPolicySnapshotIsPublished(t *testing.T) {
	rec := &targetRecorder{}
	p, ex, k := reviewedTargetFixture(t, rec, 5, func(d *Deps) {
		d.Policy = fakePolicy{} // no gateway snapshot ⇒ fail-closed rejection
	})

	tok, sid := driveToDecisionPoint(t, p, k)
	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(2)), sid), fixedClock())

	if out.Reason != mcperr.ReasonPolicySnapshotInvalid {
		t.Fatalf("premise: an unpublished snapshot must fail closed, got %v", out.Reason.Code())
	}
	if len(ex.resolvedInputs()) != 0 {
		t.Fatalf("premise: this return is above the executor, got %d resolutions", len(ex.resolvedInputs()))
	}
	obs := rec.observations()
	if len(obs) != 1 || obs[0].ServerID != testServerID || obs[0].ToolName != "x" {
		t.Fatalf("SECURITY: a snapshot-unavailable rejection must still report the tool it named, got %+v", obs)
	}
}

// The identity reported to the sink is EXACTLY the identity the policy path decides about.
//
// canaryObservedTarget derives (server, tool) from the request and the JSON-RPC message alone so it
// can run above every early return; buildPolicyInput derives the same pair, later, from the same
// two values. Two derivations of one fact is a drift hazard — a gate on placement alone would keep
// passing while the hoisted one quietly reported something else — so this pins them equal on the
// path where BOTH are observable.
func TestCanaryReviewedTarget_IdentityMatchesTheDecisionInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"tools/call names an ingested tool", toolsCallBody(2)},
		{"tools/call names a tool with no catalog record", toolsCallArgs(2, "not-ingested", `{}`)},
		{"tools/list names no tool", toolsListBody(2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &targetRecorder{}
			p, ex, k := reviewedTargetFixture(t, rec, 3)
			tok, sid := driveToDecisionPoint(t, p, k)
			p.Process(context.Background(), withSession(gwRequest(tok, tc.body), sid), fixedClock())

			ins := ex.resolvedInputs()
			if len(ins) != 1 {
				t.Fatalf("premise: expected exactly one resolution to compare against, got %d", len(ins))
			}
			wantS, wantT := toolServerID(ins[0]), toolName(ins[0])
			obs := rec.observations()
			if wantS == "" || wantT == "" {
				// An incomplete identity is not reportable: the seam drops it rather than handing
				// the root a comparison it cannot make. Pinned here too, so the parity claim covers
				// the "nothing to say" case instead of stepping around it.
				if len(obs) != 0 {
					t.Fatalf("the decided identity is (%q,%q) — incomplete — so nothing may be "+
						"reported, got %+v", wantS, wantT, obs)
				}
				return
			}
			if len(obs) != 1 {
				t.Fatalf("expected exactly one observation, got %d", len(obs))
			}
			if obs[0].ServerID != wantS || obs[0].ToolName != wantT {
				t.Fatalf("SECURITY: reported identity (%q,%q) diverges from the decided identity "+
					"(%q,%q). The hoisted derivation must reproduce buildPolicyInput's gate exactly, "+
					"or the root compares the reviewed snapshot against the wrong target",
					obs[0].ServerID, obs[0].ToolName, wantS, wantT)
			}
		})
	}
}

// STRUCTURAL gate: the emission is above EVERY return in dispatchPolicy.
//
// The three gates above each drive one early return. This one needs no traffic and covers the
// returns nothing drives — today the expired-budget path, tomorrow whatever return is added next.
// It is an AST assertion rather than a timing or coverage argument, so it is deterministic on any
// hardware, under -race, at any load: a future edit that moves the emission below a return, or adds
// a return above it, fails here rather than silently narrowing the population that reports drift.
func TestCanaryReviewedTarget_EmissionIsAboveEveryReturnInDispatchPolicy(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "policy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse policy.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if ok && fd.Name.Name == "dispatchPolicy" && fd.Recv != nil {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("dispatchPolicy not found in policy.go — the gate's selector is stale, not the code")
	}

	emit := token.NoPos
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if ok && sel.Sel.Name == "observeCanaryReviewedTarget" {
			if emit.IsValid() {
				t.Fatal("dispatchPolicy emits the reviewed-target observation more than once: the " +
					"root attributes an observation to a generation, and two emissions per request " +
					"make that attribution ambiguous")
			}
			emit = call.Pos()
		}
		return true
	})
	if !emit.IsValid() {
		t.Fatal("SECURITY: dispatchPolicy makes no reviewed-target observation at all — a Canary " +
			"whose reviewed target moved would then be recorded as healthy indefinitely")
	}

	var returns int
	ast.Inspect(fn, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		returns++
		if ret.Pos() < emit {
			t.Fatalf("SECURITY: dispatchPolicy returns at %s, ABOVE the reviewed-target emission at "+
				"%s. Every request taking that return reports no target, and the tool republish "+
				"this mechanism exists to catch is itself a common cause of early returns — so the "+
				"change hides its own evidence (Codex P1, PR #1360, round 2)",
				fset.Position(ret.Pos()), fset.Position(emit))
		}
		return true
	})
	// CONTROL: a selector that matched nothing would pass the ordering check forever.
	if returns < 5 {
		t.Fatalf("the gate found only %d returns in dispatchPolicy — too few for the function it "+
			"claims to be checking, so its walk is broken rather than its subject clean", returns)
	}

	// And the emission cannot be smuggled back inline. dispatchPolicy calls the wrapper, which is
	// the ONLY place in this file that reaches the seam — so a second, lower call to
	// noteCanaryTargetObserved cannot be added below a return while this gate still points at the
	// wrapper above it.
	var seam int
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "noteCanaryTargetObserved" {
			seam++
		}
		return true
	})
	if seam != 1 {
		t.Fatalf("policy.go reaches noteCanaryTargetObserved %d times, want exactly 1 (inside "+
			"observeCanaryReviewedTarget). More than one emission point makes the placement gate "+
			"above prove less than it claims", seam)
	}
}

// THE GATE THE ROUND-3 FIX LACKED. A request for a server that is no longer USABLE still reports
// its target — and it is driven through the REAL pipeline, not through the sink.
//
// This is the failure that made the previous round's anchor-loss latch dead code. identity.Resolve
// performs the registry existence + Usable() check and fails with ReasonRegistryServerUnavailable
// (identity/context.go, resolveCapabilityRefs), so for the entire time a reviewed server is
// disabled, EVERY request for it ends inside authenticate and dispatchPolicy never runs. The
// observation at the top of that function, and the !obs.Usable latch behind it, were both
// unreachable on production traffic — while the tests for them passed, because they called the sink
// directly. A gate that exercises the sink proves the sink; only a gate that exercises the PIPELINE
// proves the sink is reached (Codex P1, PR #1360, round 4).
//
// So this test disables the server in the shared registry and drives p.Process, asserting both that
// the request really does fail at authentication (the premise — if it ever stops doing so, this
// gate has stopped exercising the path it exists for) and that the target was reported anyway.
func TestCanaryReviewedTarget_ReportedWhenTheServerIsNoLongerUsable(t *testing.T) {
	rec := &targetRecorder{}
	p, ex, k := reviewedTargetFixture(t, rec, 13)
	tok, sid := driveToDecisionPoint(t, p, k)

	// Disable the reviewed server. Nothing else changes.
	disableRegistryServer(t, p, testServerID)

	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(2)), sid), fixedClock())
	if out.Reason != mcperr.ReasonRegistryServerUnavailable {
		t.Fatalf("premise: a disabled server must be refused by identity.Resolve with "+
			"registry_server_unavailable, got %v. If this changed, the emission point this gate "+
			"guards may no longer be the one real traffic takes", out.Reason.Code())
	}
	if len(ex.resolvedInputs()) != 0 {
		t.Fatalf("premise: the request must fail ABOVE dispatchPolicy (got %d resolutions) — that "+
			"is precisely why the observation cannot live only inside it", len(ex.resolvedInputs()))
	}

	obs := rec.observations()
	if len(obs) != 1 {
		t.Fatalf("SECURITY: a request for an unusable reviewed server reported %d observations, "+
			"want 1. While the server is disabled EVERY request ends here, so reporting nothing "+
			"means the anchor loss is never recorded and re-enabling resumes the activation", len(obs))
	}
	if obs[0].ServerID != testServerID || obs[0].ToolName != "x" || obs[0].Generation != 13 {
		t.Fatalf("the observation must name the tool and generation, got %+v", obs[0])
	}
}

// CONTROL: an ordinary authentication failure — an attacker-mintable one — reports NOTHING.
//
// The emission above is gated on ReasonRegistryServerUnavailable precisely because that reason can
// only be produced after the credential is validated (the pre-auth step does not consult the
// registry, OVN-08). Emitting on every auth failure would hand an UNAUTHENTICATED caller a way to
// drive observations against the activation — enumeration, and a lever on the experiment.
func TestCanaryReviewedTarget_UnauthenticatedFailureReportsNothing(t *testing.T) {
	rec := &targetRecorder{}
	p, _, k := reviewedTargetFixture(t, rec, 13)
	_, sid := driveToDecisionPoint(t, p, k)

	// A syntactically plausible but invalid credential: rejected before any identity exists.
	out := p.Process(context.Background(), withSession(gwRequest("not-a-valid-token", toolsCallBody(2)), sid), fixedClock())
	if out.Status != 401 {
		t.Fatalf("premise: an invalid credential must be rejected 401, got %d", out.Status)
	}
	if got := rec.observations(); len(got) != 0 {
		t.Fatalf("SECURITY: an unauthenticated request reported %d reviewed-target observations, "+
			"want 0 — an emission reachable without credentials is a lever on the experiment "+
			"for anyone who can reach the port", len(got))
	}
}

// disableRegistryServer disables a server in the pipeline's shared registry, leaving everything
// else — the catalog record, the tool, its fingerprint — untouched.
func disableRegistryServer(t *testing.T, p *pipeline, serverID string) {
	t.Helper()
	reg := p.deps.Registry
	if reg == nil {
		t.Fatal("fixture: the pipeline must carry a registry to disable a server in")
	}
	if _, ok := reg.Current().Get(registry.ServerID(serverID)); !ok {
		t.Fatalf("fixture: server %q is not registered", serverID)
	}
	if _, err := reg.SetEnabled(registry.ServerID(serverID), false); err != nil {
		t.Fatalf("disable server: %v", err)
	}
	if srv, ok := reg.Current().Get(registry.ServerID(serverID)); !ok || srv.Usable() {
		t.Fatal("fixture: the server must be unusable after the disable")
	}
}
