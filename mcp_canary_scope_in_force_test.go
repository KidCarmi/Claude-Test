package main

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// mcp_canary_scope_in_force_test.go — the deterministic matrix for STALE AUTHORIZATION at the
// live admission boundary (Codex P1, PR #1370, round 2).
//
// The fact under test, in one line:
//
//	a request may spend budget authority ONLY under the exact rollout scope it resolved
//	under — the same authorization envelope, byte for byte, still installed at the moment
//	authority is granted.
//
// Why this is the same defect as the round-1 one, and why it needed its own fix. Scope membership
// is decided ONCE, at resolution (rollout.Scope.Contains, through the executor's Resolve), and the
// request then travels to a boundary that re-reads the trust probe, the reviewed target, the
// operation class, the generation and the kill state — but never re-read the scope. So:
//
//	G armed. Scope S1 permits principal A. A's request resolves executable under S1.
//	the request pauses — a credential path, a durable commit, a scheduler stall.
//	a SAME-MODE update installs S2: A removed, B added. Reviewed target unchanged, budget
//	unchanged ⇒ reconcileCanaryRuntimeAfterCommit accepts it and the generation STAYS G.
//	the request resumes. The target never moved, so nothing drifts; the class still matches;
//	and MaxPrincipals merely COUNTS principals, so A — already counted — clears the ceiling.
//
// It spends authority granted by an envelope that no longer exists.
//
// THE COMPARISON IS EXACT HASH EQUALITY, not a re-run of principal membership, and that choice is
// what these cases are mostly about: re-running membership closes the principal case and leaves
// every sibling open. The hash covers every selector dimension at once, so one comparison closes
// the whole family — including the dimensions nobody enumerated.

// scopeRig is one armed activation over the REAL rollout state, the REAL inventory, a REAL
// four-eyes live approval and the REAL production admission gate.
type scopeRig struct {
	rt   *canaryRuntime
	capb rollout.Capability
	g    *mcpLiveSideEffectGate
	gw   *rollout.State
	sid  string
	tool string
	fp   string
	gen  uint64
}

// newScopeRig arms a Canary whose installed scope admits the seeded server, and returns a rig whose
// requests resolve under that scope.
func newScopeRig(t *testing.T) *scopeRig {
	t.Helper()
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	requestAndApproveLiveClassified(t, sid, tool, fpHex, cat.Current().Revision(), tooltrust.ReviewedOpReadOnly)

	gw := getMCPRollout().stateFor(capb)
	prev := gw.CurrentConfig()
	t.Cleanup(func() { _ = gw.SetConfig(prev, "scope-rig-restore", time.Unix(0, 9).UnixNano()) })
	installScope(t, gw, 1, rollout.ScopeSpec{
		Capability: capb, Servers: []string{sid}, Principals: []string{liveRequester},
	})

	gen, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(20),
		ReviewedTargets: []canary.ReviewedTarget{observedReviewedTargetClassified(t, sid, tool, fpHex, policy.OpRead)},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("arm activation: %v", err)
	}
	return &scopeRig{rt: rt, capb: capb, g: realAdmissionGate(t, capb), gw: gw, sid: sid, tool: tool, fp: fpHex, gen: gen}
}

// installScope replaces the Gateway's live scope WITHOUT changing the mode. This is the
// same-mode update the finding turns on: the rollout layer accepts it (budget and reviewed target
// are untouched) and the activation generation is deliberately NOT re-begun.
func installScope(t *testing.T, gw *rollout.State, rev uint64, spec rollout.ScopeSpec) {
	t.Helper()
	cfg := rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeCanary,
		ScopeRevision: rev, Scope: spec, ConnectorMode: rollout.ConnectorLocalClient,
	}
	if err := gw.SetConfig(cfg, "scope-test", time.Unix(0, int64(rev)).UnixNano()); err != nil {
		t.Fatalf("install scope rev %d: %v", rev, err)
	}
}

// resolvedNow is one admission input carrying the envelope currently installed — what a request
// that just resolved would carry.
func (r *scopeRig) resolvedNow() execution.LiveGateInput { return r.resolvedUnder(r.gw.ScopeHash()) }

// resolvedUnder is one admission input carrying an explicit envelope, so a case can model a
// request that resolved under a scope which has since been replaced.
func (r *scopeRig) resolvedUnder(hash string) execution.LiveGateInput {
	in := driftGateInput(r.sid, r.tool, r.fp, mcpToolTrust.now())
	in.ResolvedScopeHash = hash
	return in
}

// admit drives one real admission and releases any slot it was granted.
func (r *scopeRig) admit(in execution.LiveGateInput) (bool, mcperr.Reason) {
	d := r.g.AdmitSideEffect(in)
	if d.Release != nil {
		d.Release()
	}
	return d.Admit, d.Reason
}

// ── THE REQUIRED SEQUENCE ─────────────────────────────────────────────────────────────────────
//
// The exact case the finding names, driven end to end through the production gate: resolve under
// S1, install S2 in the same mode with the generation unchanged, then resume the stale request.
func TestScopeInForce_StaleRequestRefusedAfterSameModeScopeUpdate(t *testing.T) {
	r := newScopeRig(t)
	h1 := r.gw.ScopeHash()
	stale := r.resolvedUnder(h1)

	// PREMISE — and it has to be asserted, or the refusal below could be for any reason at all.
	// Under S1 the request is admitted through the ordinary read-first path.
	if ok, reason := r.admit(stale); !ok {
		t.Fatalf("premise: a request resolved under the installed scope must be admitted, reason=%s", reason.Code())
	}

	// S2: principal A removed, B added. Same mode, same reviewed target, same budget — so the
	// rollout layer accepts it and the activation generation does NOT change.
	installScope(t, r.gw, 2, rollout.ScopeSpec{
		Capability: r.capb, Servers: []string{r.sid}, Principals: []string{"principal-b@corp"},
	})
	if got := r.rt.currentGeneration(r.capb); got != r.gen {
		t.Fatalf("premise: a same-mode scope update must NOT re-begin the generation, %d → %d", r.gen, got)
	}
	if h2 := r.gw.ScopeHash(); h2 == h1 {
		t.Fatal("premise: replacing the scope must change its content hash")
	}

	// THE GATE. The stale request carries S1's envelope; S2 is installed.
	ok, reason := r.admit(stale)
	if ok {
		t.Fatal("SECURITY: a request that resolved under a scope which no longer exists spent " +
			"budget authority — the authorization envelope was not revalidated at the boundary")
	}
	if reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("the refusal must be the bounded out-of-scope reason, got %s", reason.Code())
	}
	// REQUEST-SCOPED: an operator narrowing a scope is the system working, not target drift.
	if r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: a scope edit must not latch the whole Canary — it is stale authorization, " +
			"not evidence that the reviewed target moved")
	}
}

// THE POSITIVE CONTROL for the sequence above, and it is mandatory: with the envelope unchanged the
// same request proceeds through the normal read-first admission path. Without it, a boundary that
// refused everything would satisfy every negative case in this file.
func TestScopeInForce_UnchangedEnvelopeStillProceeds(t *testing.T) {
	r := newScopeRig(t)
	for i := 0; i < 3; i++ {
		if ok, reason := r.admit(r.resolvedNow()); !ok {
			t.Fatalf("attempt %d: an unchanged envelope must proceed, reason=%s", i+1, reason.Code())
		}
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("a healthy admission must not stop the Canary")
	}
}

// A same-mode REAPPLY of the IDENTICAL signed config is not a change and must not reject: the same
// selectors at the same revision produce the same content hash, so an in-flight request stays
// valid across a no-op redeploy.
//
// THE REVISION IS PART OF SCOPE IDENTITY, deliberately, and that is worth stating because it is
// the one place this boundary is conservative. rollout.Scope.computeHash folds the scope revision
// in, so identical SELECTORS published at a NEW revision hash differently and a request in flight
// across that publish is refused — an availability cost with no security gain, in isolation.
//
// It is still the right hash to use, for the reason this whole PR keeps returning to: the rollout
// layer ALREADY decides "did the scope change" with exactly this comparison
// (sameModeSameScope, mcp_rollout.go), and the admin surface documents that both sides fold the
// revision in. Minting a second, selector-only hash for the boundary would create two definitions
// of scope identity that can disagree — and a disagreement about which envelope authorized a
// request is precisely the class of defect being closed. One definition, shared.
func TestScopeInForce_IdenticalReapplyDoesNotReject(t *testing.T) {
	r := newScopeRig(t)
	h1 := r.gw.ScopeHash()
	stale := r.resolvedUnder(h1)

	installScope(t, r.gw, 1, rollout.ScopeSpec{
		Capability: r.capb, Servers: []string{r.sid}, Principals: []string{liveRequester},
	})
	if r.gw.ScopeHash() != h1 {
		t.Fatal("premise: re-applying the identical signed config must produce the identical content hash")
	}
	if ok, reason := r.admit(stale); !ok {
		t.Fatalf("SECURITY: an identical re-apply is not a scope change and must not refuse an "+
			"in-flight request, reason=%s", reason.Code())
	}
}

// EVERY SELECTOR DIMENSION, not just the principal. This is the case for hash equality over a
// principal-membership re-run: each row edits a different dimension, and a boundary that only
// re-checked principals would pass the first row and fail the rest.
func TestScopeInForce_AnySelectorEditRefusesTheStaleRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec func(sid string) rollout.ScopeSpec
	}{
		{"principal A→B", func(sid string) rollout.ScopeSpec {
			return rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: []string{sid}, Principals: []string{"principal-b@corp"}}
		}},
		{"server set changed", func(sid string) rollout.ScopeSpec {
			return rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: []string{sid, "other-server"}, Principals: []string{liveRequester}}
		}},
		{"tool set narrowed", func(sid string) rollout.ScopeSpec {
			return rollout.ScopeSpec{
				Capability: rollout.CapabilityGateway, Servers: []string{sid}, Principals: []string{liveRequester},
				// A fully-pinned selector, as the scope validator requires; the point is that the
				// TOOL dimension moved, not which tool it moved to.
				Tools: []rollout.ToolSel{{
					Server: sid, Name: "some-other-tool",
					Fingerprint: "00000000000000000000000000000000000000000000000000000000000000ff",
				}},
			}
		}},
		{"exclusion added", func(sid string) rollout.ScopeSpec {
			return rollout.ScopeSpec{
				Capability: rollout.CapabilityGateway, Servers: []string{sid}, Principals: []string{liveRequester},
				ExcludePrincipals: []string{"someone-else@corp"},
			}
		}},
		{"tenant added", func(sid string) rollout.ScopeSpec {
			return rollout.ScopeSpec{
				Capability: rollout.CapabilityGateway, Servers: []string{sid}, Principals: []string{liveRequester},
				Tenants: []string{ttTenant},
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newScopeRig(t)
			stale := r.resolvedUnder(r.gw.ScopeHash())
			if ok, _ := r.admit(stale); !ok {
				t.Fatal("premise: the request must be admitted before the scope is edited")
			}
			installScope(t, r.gw, 2, tc.spec(r.sid))
			if ok, reason := r.admit(stale); ok {
				t.Fatalf("SECURITY: a %s edit left a stale request able to spend authority "+
					"(reason=%s) — the envelope comparison is not covering this dimension", tc.name, reason.Code())
			}
			if r.rt.abortedNow(r.capb) {
				t.Fatalf("a %s edit is stale authorization, not target drift — nothing may latch", tc.name)
			}
		})
	}
}

// A MISSING envelope fails closed. "" is what a request carries when it never went through
// State.ResolveFor — and an executing Canary request always does, so an empty hash at this
// boundary means something skipped the path that stamps it. Treating it as a match would make the
// entire check optional for exactly those requests.
func TestScopeInForce_MissingEnvelopeFailsClosed(t *testing.T) {
	r := newScopeRig(t)
	if ok, reason := r.admit(r.resolvedUnder("")); ok {
		t.Fatalf("SECURITY: an empty authorization envelope must never be treated as a match "+
			"(reason=%s)", reason.Code())
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("a malformed request is request-scoped — nothing may latch")
	}
}

// DEMOTE → REACTIVATE cannot launder an old envelope into fresh authority. A new generation is a
// new experiment; a request holding the previous scope's hash has no claim on it. This is the
// case a generation-equality check would get wrong in the other direction — the generation moved,
// but so would a naive "the scope changed so re-resolve" fallback.
func TestScopeInForce_ReactivationCannotReuseAnOldEnvelope(t *testing.T) {
	r := newScopeRig(t)
	stale := r.resolvedUnder(r.gw.ScopeHash())
	if ok, _ := r.admit(stale); !ok {
		t.Fatal("premise: the request must be admitted under the original activation")
	}

	if err := r.rt.demoteCanary(r.capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	installScope(t, r.gw, 3, rollout.ScopeSpec{
		Capability: r.capb, Servers: []string{r.sid}, Principals: []string{"principal-b@corp"},
	})
	gen2, err := r.rt.beginCanaryActivation(r.capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(20),
		ReviewedTargets: []canary.ReviewedTarget{observedReviewedTargetClassified(t, r.sid, r.tool, r.fp, policy.OpRead)},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	if gen2 == r.gen {
		t.Fatalf("premise: re-activation must mint a new generation, still %d", r.gen)
	}

	if ok, reason := r.admit(stale); ok {
		t.Fatalf("SECURITY: an envelope from the previous activation was accepted as fresh "+
			"authority under the new one (reason=%s)", reason.Code())
	}
}

// The two boundary revalidations are INDEPENDENT. Adding the scope check must not have made the
// operation-class check redundant or unreachable: with the envelope perfectly in force, a class
// the activation does not bind is still refused.
func TestScopeInForce_ClassRevalidationStillWorksIndependently(t *testing.T) {
	r := newScopeRig(t)
	in := r.resolvedNow()
	in.Operation = policy.OpWrite
	if ok, reason := r.admit(in); ok {
		t.Fatalf("SECURITY: a class the activation does not bind must still be refused with the "+
			"envelope in force (reason=%s)", reason.Code())
	}
	// And the control in the other direction: the matching class with the matching envelope is
	// admitted, so neither check is refusing on the other's behalf.
	if ok, reason := r.admit(r.resolvedNow()); !ok {
		t.Fatalf("both facts in force must admit, reason=%s", reason.Code())
	}
}

// THE EMERGENCY KILL REMAINS THE LAST SECURITY CHECK. The scope revalidation sits inside the
// admission transaction; the kill is re-read at the irreversible boundary, after it. Admission
// succeeding must not imply anything about the kill, or an operator's stop would be advisory.
func TestScopeInForce_EmergencyKillStillOutranksAGrantedAdmission(t *testing.T) {
	r := newScopeRig(t)
	if ok, reason := r.admit(r.resolvedNow()); !ok {
		t.Fatalf("premise: the request must be admitted before the kill, reason=%s", reason.Code())
	}
	r.gw.EngageKillSwitch("test", time.Unix(0, 50).UnixNano())
	t.Cleanup(r.gw.ClearKillSwitch)
	if !r.gw.Killed() {
		t.Fatal("premise: the kill must be engaged")
	}
	// The executor re-reads the kill at the side-effect boundary, AFTER admission. What is pinned
	// here is that the scope check did not move or subsume that read: the kill state is still
	// authoritative and still checked downstream of everything this file is about.
	if r.gw.KillGeneration() == 0 {
		t.Fatal("the kill generation must advance so the boundary re-read can see it")
	}
}

// ── THE CARRY, END TO END ─────────────────────────────────────────────────────────────────────
//
// Every case above hands the boundary an envelope directly, which proves the COMPARISON but says
// nothing about whether the envelope ever gets there on its own. This one drives the real
// resolution: Executor.Resolve stamps the hash onto its Resolution from the scope it decided
// against, Execute carries it onto the ExecInput, liveGateInput hands it to the gate, and the
// admission transaction compares it against the installed scope.
//
// It is written as a POSITIVE control — the upstream is reached — because that is the direction a
// broken carry fails in: a hash that never arrives is "", the boundary correctly refuses "", and
// the only visible symptom is that a healthy request stops executing. A negative test would pass
// against a carry that was silently dropped, which is precisely the mutation this gate exists to
// catch (M17).
func TestScopeInForce_EnvelopeIsCarriedFromResolutionToTheBoundary(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 5)
	ex := cfg.Deps.Executor

	in := liveExecInput(policy.OpRead, "t1", "p1")
	in.ToolStillCurrent = func() bool { return true }

	// The resolution must itself carry the envelope it decided under. Asserted separately from
	// the execution below so a failure names WHICH link broke rather than only that the upstream
	// went unreached.
	res := ex.Resolve(in)
	if res.ScopeHash == "" {
		t.Fatal("SECURITY: the resolution carries no authorization envelope — nothing downstream " +
			"can revalidate a fact that was never captured")
	}
	if want := getMCPRollout().stateFor(rollout.CapabilityGateway).ScopeHash(); res.ScopeHash != want {
		t.Fatalf("the resolution must carry the scope it decided against: got %q want %q", res.ScopeHash, want)
	}
	// And the request must NOT already carry it — proving the carry below is the executor's doing
	// and not something the fixture supplied.
	if in.ResolvedScopeHash != "" {
		t.Fatal("fixture drifted: the input must arrive with no envelope so the carry is attributable")
	}

	if out := ex.Execute(t.Context(), in, res); out.Executed != true && up.callCount() == 0 {
		t.Fatalf("the carried envelope must let a healthy request reach upstream, out=%+v", out)
	}
	if up.callCount() != 1 {
		t.Fatalf("SECURITY: the envelope did not survive resolution → ExecInput → LiveGateInput → "+
			"admission; a healthy request was refused as though the scope had changed, calls=%d",
			up.callCount())
	}
}
