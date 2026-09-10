package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// mcp_canary_reviewed_binding_test.go — the §12 deterministic matrix for the ACTIVATION-BOUND
// REVIEWED TARGET SNAPSHOT (blocker #7, Round-24 P1).
//
// The fact under test, in one line:
//
//	an activation carries immutable durable evidence of the exact targets it was reviewed and
//	authorized to execute, and drift is decided against THAT — never against whether the original
//	approval happens to still be unexpired.
//
// Why the distinction is the whole point. A first Canary window may run for
// canary.FirstCanaryMaxWindowCeiling (7 days); a live-execution approval may live for at most
// canary.MaxInitialCanaryApprovalTTL (24 hours). For six of those seven days the approval store
// can no longer say what this activation was reviewed against. The superseded design inferred
// drift from an approval still pinned to the reviewed fingerprint, so drift detection expired
// with the approval — an attacker who waits out 24 hours and then republishes the tool faced an
// ordinary "not approved" denial instead of a whole-experiment abort. Case 4 is that sequence.
//
// Every case here uses explicit clock seams (the tool-trust fake clock, and the instant passed
// into the gate input). There are no sleeps.
//
// The cases, in the order the specification enumerates them:
//
//	 1  F1 healthy, approval alive                     → admitted
//	 2  F1 healthy, approval expired                   → request-scoped denial, NO drift
//	 3  F1→F2 while the approval is alive              → drift + whole-Canary latch
//	 4  approval expires, THEN F1→F2                   → drift + latch (the headline case)
//	 5  F1→F2, then F2 separately approved             → old G STILL drifts and latches
//	 6  a NEW activation explicitly against F2         → healthy control
//	 7  restart between approval expiry and F1→F2      → drift still detectable
//	 8  empty reviewed-target set                      → activation refused
//	 9  persisted active state missing the reviewed set → restore is NOT executable
//	10  same-generation reviewed-set mutation attempt  → refused
//	11  server identity change                         → server_identity_drift + latch
//	12  demote G, activate G+1 against F2              → the old snapshot cannot affect G+1

// reviewedRig is one armed activation over the REAL inventory, the REAL approval store and the
// REAL admission gate. Everything the matrix asserts flows through production code.
type reviewedRig struct {
	rt   *canaryRuntime
	capb rollout.Capability
	g    *mcpLiveSideEffectGate
	clk  *liveTrustClock
	sid  string
	tool string
	fp1  string    // the reviewed (F1) fingerprint, hex
	now  time.Time // the instant the approval is alive at
	gen  uint64
}

// newReviewedRig seeds the controlled inventory, grants a real four-eyes live approval for it, and
// arms an activation whose reviewed-target snapshot is the target that was actually approved.
func newReviewedRig(t *testing.T) *reviewedRig {
	t.Helper()
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	clk, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())

	gen := armReviewedActivation(t, rt, capb, sid, tool, fpHex)
	return &reviewedRig{
		rt: rt, capb: capb, g: realAdmissionGate(t, capb), clk: clk,
		sid: sid, tool: tool, fp1: fpHex, now: mcpToolTrust.now(), gen: gen,
	}
}

// armReviewedActivation arms an activation bound to the CURRENT authoritative target for
// (sid, tool), read through the same precheck the gate uses. This is the test-side stand-in for
// the production projection (reviewedTargetsFromBindings): an explicit reviewed set, never an
// implicit one, because an activation with none must fail closed.
func armReviewedActivation(t *testing.T, rt *canaryRuntime, capb rollout.Capability, sid, tool, fpHex string) uint64 {
	t.Helper()
	gen, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(20),
		ReviewedTargets: []canary.ReviewedTarget{observedReviewedTarget(t, sid, tool, fpHex)},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("begin activation: %v", err)
	}
	return gen
}

// observedReviewedTarget reads the current authoritative target for (sid, tool) as the admission
// probe would, and shapes it as a reviewed record.
func observedReviewedTarget(t *testing.T, sid, tool, fpHex string) canary.ReviewedTarget {
	t.Helper()
	live := mcpLiveTrustPrecheck(ttTenant, sid, tool, fpHex)
	if !live.Eligible {
		t.Fatalf("fixture: %s/%s must resolve to an eligible target, got %+v", sid, tool, live)
	}
	return canary.ReviewedTarget{
		Tenant: live.Target.Tenant, ServerID: live.Target.ServerID, ToolName: live.Target.ToolName,
		Fingerprint: live.Target.Fingerprint, FingerprintFormat: live.Target.FingerprintFormat,
		ServerIdentity: live.ServerIdentity,
	}
}

// request drives one admission through the production gate at an explicit instant, naming an
// explicit decision fingerprint, and releases any slot it was granted.
func (r *reviewedRig) request(fp string, at time.Time) bool {
	d := r.g.AdmitSideEffect(driftGateInput(r.sid, r.tool, fp, at))
	if d.Release != nil {
		d.Release()
	}
	return d.Admit
}

// republishWithIdentity re-publishes the SAME server/tool under an explicit pinned identity and
// input schema, and returns the tool's new fingerprint. It is how the matrix moves a target: a
// changed schema moves the fingerprint, a changed identity moves the server binding.
func republishWithIdentity(t *testing.T, sid, tool, identity, schema string) string {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"` + identity + `","enabled":true,
	   "tools":[{"name":"` + tool + `","input_schema":` + schema + `}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: registry.ServerID(sid), Name: tool})
	if !ok {
		t.Fatalf("republished tool %s/%s is not in the catalog", sid, tool)
	}
	sum := rec.Fingerprint.Sum()
	return hex.EncodeToString(sum[:])
}

// moveToF2 republishes the reviewed tool with a different schema, so its fingerprint moves while
// its identity and server binding stay exactly as reviewed. It returns the NEW fingerprint, which
// later requests are decided against — so the precheck sees F2 == F2 and reports no drift of its
// own. Only the activation's reviewed snapshot can still tell that the target moved.
func (r *reviewedRig) moveToF2(t *testing.T) string {
	t.Helper()
	fp2 := republishWithIdentity(t, r.sid, r.tool, "id", `{"type":"object","properties":{"moved":{"type":"string"}}}`)
	if fp2 == r.fp1 {
		t.Fatal("premise: the republished tool must carry a DIFFERENT fingerprint")
	}
	// The precheck itself must be blind to this, or the matrix would be proving the OLD mechanism.
	if live := mcpLiveTrustPrecheck(ttTenant, r.sid, r.tool, fp2); live.DriftCode != "" {
		t.Fatalf("premise: a request decided against F2 must show no precheck drift, got %q", live.DriftCode)
	}
	return fp2
}

// assertLatched proves the whole Canary stopped with the named first cause.
func (r *reviewedRig) assertLatched(t *testing.T, wantCode string) {
	t.Helper()
	if !r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: %s is a breach of the experiment's premise — the whole Canary must stop", wantCode)
	}
	if code := r.rt.abortCodeNow(r.capb); code != wantCode {
		t.Fatalf("first cause = %q, want %q", code, wantCode)
	}
	// A latched Canary admits nothing further, whatever it is asked.
	if r.request(r.fp1, r.now) {
		t.Fatal("SECURITY: a latched Canary must admit nothing further")
	}
}

// ── 1 ────────────────────────────────────────────────────────────────────────────────────────
// The healthy baseline, and the control that keeps every refusal below honest: a gate that
// refused everything would satisfy cases 2–5 and 11 while being useless.
func TestReviewedBinding_C01_ReviewedTargetWithLiveApprovalIsAdmitted(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("the exact reviewed target, with a valid live approval, must be admitted")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("control: an admitted, authorized request must not stop the Canary")
	}
	if r.rt.currentGeneration(r.capb) != r.gen {
		t.Fatal("an admitted request must not change the activation generation")
	}
}

// ── 2 ────────────────────────────────────────────────────────────────────────────────────────
// The target has NOT moved; only the approval has expired. That is an ordinary unauthorized
// request, and classifying it as drift would let any caller stop the experiment simply by waiting
// out the TTL. Request-scoped, nothing latched.
func TestReviewedBinding_C02_ExpiredApprovalOnTheReviewedTargetIsRequestScoped(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("premise: the reviewed target must be admitted while the approval is alive")
	}
	expired := r.now.Add(48 * time.Hour) // past MaxInitialCanaryApprovalTTL
	if r.request(r.fp1, expired) {
		t.Fatal("an expired approval must not authorize live execution")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: an expired approval on an UNCHANGED target must not stop the Canary "+
			"(abort code %q) — nothing about it says the reviewed target moved", r.rt.abortCodeNow(r.capb))
	}
}

// ── 3 ────────────────────────────────────────────────────────────────────────────────────────
// The reviewed tool moved while the approval was still alive. Whole-Canary breach.
func TestReviewedBinding_C03_FingerprintDriftWithLiveApprovalLatches(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("premise: the reviewed target must be admitted first")
	}
	fp2 := r.moveToF2(t)
	if r.request(fp2, r.now) {
		t.Fatal("a target that is no longer the reviewed one must fail closed")
	}
	r.assertLatched(t, "tool_fingerprint_drift")
}

// ── 4 ────────────────────────────────────────────────────────────────────────────────────────
// THE HEADLINE CASE (§7). T0: activate against F1. T+24h: the approval expires. Then the tool is
// republished as F2 and a request arrives decided against F2.
//
// At that instant NOTHING in the approval store mentions F1 any more, and the precheck sees
// F2 == F2. The superseded design had no evidence left and answered "missing approval", so a
// patient rug-pull cost the attacker nothing but a day. The activation's own reviewed snapshot is
// unaffected by approval lifetime, so the drift is still authoritative — and still stops the
// whole experiment.
func TestReviewedBinding_C04_DriftAfterApprovalExpiryStillLatches(t *testing.T) {
	r := newReviewedRig(t)
	expired := r.now.Add(48 * time.Hour)

	// Establish that the approval really is gone: on the UNCHANGED target this is a plain denial.
	if r.request(r.fp1, expired) {
		t.Fatal("premise: the approval must have expired")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("premise: expiry alone must not have latched anything")
	}

	fp2 := r.moveToF2(t)
	if r.request(fp2, expired) {
		t.Fatal("a drifted target must fail closed")
	}
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: drift detection must NOT expire with the approval. An activation that " +
			"can run for 7 days while its approval lives 24 hours would be blind to a rug-pull for " +
			"six of them — the exact window this snapshot exists to close")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "tool_fingerprint_drift" {
		t.Fatalf("first cause = %q, want tool_fingerprint_drift — reported as an ordinary missing "+
			"approval, a rug-pull stops nothing", code)
	}
}

// ── 5 ────────────────────────────────────────────────────────────────────────────────────────
// §8, "the most important Round-24 gate": after the tool moves to F2, someone grants a perfectly
// valid four-eyes approval FOR F2. Generation G was reviewed against F1 and must not be
// resurrected by it — a new approval authorizes a new experiment, it does not rewrite what an
// existing one was reviewed to do.
func TestReviewedBinding_C05_ALaterApprovalForF2DoesNotResurrectG(t *testing.T) {
	r := newReviewedRig(t)
	fp2 := r.moveToF2(t)

	// A genuine, current, four-eyes live approval for the NEW fingerprint.
	reg2, cat2 := mcpInventory.sharedInventory()
	_ = reg2
	requestAndApproveLive(t, r.sid, r.tool, fp2, cat2.Current().Revision())
	if ok, _ := mcpLiveApprovalSatisfied(canary.LiveTarget{
		Tenant: ttTenant, ServerID: r.sid, ToolName: r.tool,
		Fingerprint: mustDigest(t, fp2), FingerprintFormat: 1,
	}, r.now); !ok {
		t.Fatal("premise: the F2 approval must itself be valid — otherwise this proves nothing")
	}

	if r.request(fp2, r.now) {
		t.Fatal("SECURITY: an approval granted AFTER the activation must not authorize a target " +
			"generation G was never reviewed for")
	}
	r.assertLatched(t, "tool_fingerprint_drift")
}

// ── 6 ────────────────────────────────────────────────────────────────────────────────────────
// The healthy control for case 5: a NEW activation, explicitly reviewed against F2, executes F2
// normally. The refusal above is about WHICH activation was reviewed for what, not about F2 being
// untouchable.
func TestReviewedBinding_C06_NewActivationExplicitlyAgainstF2IsHealthy(t *testing.T) {
	r := newReviewedRig(t)
	fp2 := r.moveToF2(t)
	_, cat2 := mcpInventory.sharedInventory()
	requestAndApproveLive(t, r.sid, r.tool, fp2, cat2.Current().Revision())

	// Demote G and activate a fresh generation bound to F2 — the demote → re-activate cycle §10
	// requires for any change to what an activation may execute.
	if err := r.rt.demoteCanary(r.capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	genNew := armReviewedActivation(t, r.rt, r.capb, r.sid, r.tool, fp2)
	if genNew <= r.gen {
		t.Fatalf("a re-activation must begin a strictly newer generation, got %d after %d", genNew, r.gen)
	}
	r.g = realAdmissionGate(t, r.capb)
	if !r.request(fp2, r.now) {
		t.Fatal("an activation explicitly reviewed against F2 must execute F2")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("control: the fresh activation must not inherit the old snapshot's verdict")
	}
}

// ── 7 ────────────────────────────────────────────────────────────────────────────────────────
// The node restarts in the window between the approval expiring and the tool moving. The reviewed
// set is durable, so the restored activation can still tell F2 from what it was reviewed for.
func TestReviewedBinding_C07_RestartBetweenExpiryAndDriftStillDetects(t *testing.T) {
	r := newReviewedRig(t)
	expired := r.now.Add(48 * time.Hour)
	if r.request(r.fp1, expired) {
		t.Fatal("premise: the approval must have expired")
	}

	// Restart: a fresh runtime object restores from the durable record alone.
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if !fresh.armed(r.capb) {
		t.Fatal("premise: an active durable record must come back armed")
	}
	set, ok := fresh.activeReviewedTargets(r.capb)
	if !ok || set.Len() != 1 {
		t.Fatalf("the restored activation must carry its reviewed set, got ok=%v n=%d", ok, set.Len())
	}
	r.rt = fresh
	r.g = realAdmissionGate(t, r.capb)

	fp2 := r.moveToF2(t)
	if r.request(fp2, expired) {
		t.Fatal("a drifted target must fail closed after a restart")
	}
	r.assertLatched(t, "tool_fingerprint_drift")
}

// ── 8 ────────────────────────────────────────────────────────────────────────────────────────
// §2: production activation MUST supply reviewed targets, and an empty set fails CLOSED. An
// activation that cannot say what it was reviewed for cannot detect drift for its whole window,
// so it must not exist at all.
func TestReviewedBinding_C08_EmptyReviewedTargetSetRefusesActivation(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	for _, tc := range []struct {
		name    string
		targets []canary.ReviewedTarget
	}{
		{"nil", nil},
		{"empty", []canary.ReviewedTarget{}},
		{"zero fingerprint", []canary.ReviewedTarget{func() canary.ReviewedTarget {
			x := testReviewedTarget()
			x.Fingerprint = tooltrustZeroDigest()
			return x
		}()}},
		{"no server identity", []canary.ReviewedTarget{func() canary.ReviewedTarget {
			x := testReviewedTarget()
			x.ServerIdentity = ""
			return x
		}()}},
		{"incomplete identity", []canary.ReviewedTarget{func() canary.ReviewedTarget {
			x := testReviewedTarget()
			x.ToolName = ""
			return x
		}()}},
		{"ambiguous duplicate", []canary.ReviewedTarget{reviewedAt(fpF1), reviewedAt(fpF2)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gen, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
				Budget: runtimeTestBudget(5), ReviewedTargets: tc.targets, StartedAt: canaryRuntimeTestNow,
			})
			if !errors.Is(err, errCanaryReviewedTargetsInvalid) {
				t.Fatalf("activation must fail closed, got gen=%d err=%v", gen, err)
			}
			if rt.armed(capb) || rt.executionEligible(capb, canaryRuntimeTestNow) {
				t.Fatal("SECURITY: a refused activation must leave nothing armed")
			}
		})
	}
}

// ── 9 ────────────────────────────────────────────────────────────────────────────────────────
// §5/§11: a durable ACTIVE record that cannot prove what it was reviewed for does not come back
// executable — including an old record written by a build that had no such field at all.
func TestReviewedBinding_C09_ActiveRecordWithoutReviewedSetIsNotExecutable(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("premise: the activation must be executable before the record is damaged")
	}
	stripReviewedTargetsFromDurableRecord(t, r.capb)

	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.armed(r.capb) || fresh.executionEligible(r.capb, r.now) {
		t.Fatal("SECURITY: an active record with no reviewed-target set must NOT restore executable " +
			"authority — it could not distinguish a drifted target from an unauthorized one for the " +
			"rest of its window")
	}
	if fresh.currentGeneration(r.capb) < r.gen {
		t.Fatal("the monotonic generation must be preserved so a fresh activation bumps past it")
	}
	r.rt = fresh
	r.g = realAdmissionGate(t, r.capb)
	if r.request(r.fp1, r.now) {
		t.Fatal("SECURITY: nothing may be admitted under a non-restorable activation")
	}
}

// ── 10 ───────────────────────────────────────────────────────────────────────────────────────
// §10: generation G's reviewed set is immutable for its whole life. A same-mode control-plane
// update that would bind a different set is refused — otherwise the control plane itself performs
// the drift the runtime exists to catch, and G evolves from F1 into F2 without anyone reviewing it.
func TestReviewedBinding_C10_SameGenerationReviewedSetMutationIsRefused(t *testing.T) {
	resetLiveTierGlobals(t)
	setDataDirForTest(t, t.TempDir())
	capb := rollout.CapabilityGateway
	budget := runtimeTestBudget(10)
	if _, err := globalCanaryRuntime.beginCanaryActivation(capb, canaryActivationSpec{
		Budget: budget, ReviewedTargets: []canary.ReviewedTarget{reviewedAt(fpF1)}, StartedAt: time.Unix(0, 1),
	}); err != nil {
		t.Fatalf("begin: %v", err)
	}
	r := newTestRollout()
	st := r.gateway
	prevCfg := *gwCanaryCfg(1)
	if err := st.SetConfig(prevCfg, "prev", time.Unix(0, 1).UnixNano()); err != nil {
		t.Fatalf("install prev canary: %v", err)
	}
	cfg := gwCanaryCfg(2) // SAME mode, new scope revision
	if err := st.SetConfig(*cfg, "new", time.Unix(0, 2).UnixNano()); err != nil {
		t.Fatalf("install new canary: %v", err)
	}
	tgt := commitTransitionTarget{
		st: st, persist: func(*rollout.State) error { return nil },
		setStatus: func(string) {}, countTransition: func() {}, reconcileRuntime: true,
	}

	// A DIFFERENT reviewed set on a same-mode update ⇒ refused, state rolled back.
	err := r.reconcileCanaryRuntimeAfterCommit(tgt, cfg, prevCfg.Mode, prevCfg, st.Evidence(),
		canaryActivationSpec{Budget: budget, ReviewedTargets: []canary.ReviewedTarget{reviewedAt(fpF2)}, StartedAt: time.Unix(0, 2)},
		"new", time.Unix(0, 2))
	if !errors.Is(err, errRolloutCanaryReviewedTargetsChanged) {
		t.Fatalf("a same-mode update that rebinds the reviewed set must be refused, got %v", err)
	}
	if st.CurrentMode() != prevCfg.Mode {
		t.Fatalf("state must roll back to the prior live mode, got %v", st.CurrentMode())
	}
	// The running generation kept the set it was armed with.
	set, ok := globalCanaryRuntime.activeReviewedTargets(capb)
	if !ok || !set.Equal(mustCanonical(t, reviewedAt(fpF1))) {
		t.Fatal("SECURITY: the refused update must not have mutated the active reviewed set")
	}
	// The IDENTICAL set is not a change and proceeds (a scope revision that renames nothing
	// re-supplies the same targets).
	if err := r.reconcileCanaryRuntimeAfterCommit(tgt, cfg, prevCfg.Mode, prevCfg, st.Evidence(),
		canaryActivationSpec{Budget: budget, ReviewedTargets: []canary.ReviewedTarget{reviewedAt(fpF1)}, StartedAt: time.Unix(0, 3)},
		"same", time.Unix(0, 3)); err != nil {
		t.Fatalf("a same-mode update re-supplying the SAME reviewed set must proceed, got %v", err)
	}
}

// ── 11 ───────────────────────────────────────────────────────────────────────────────────────
// §9: the same principle for the server the tool lives on.
//
// The catalog's composite fingerprint already folds the server's pinned identity in, so an
// identity rotation moves the fingerprint too — this test asserts that coupling rather than
// assuming it. What the reviewed snapshot's own ServerIdentity field buys is the CLASSIFICATION:
// the first cause reported is server_identity_drift, not tool_fingerprint_drift, because the tool
// definition is byte-identical and it is the workload serving it that changed. An operator
// reading "the tool schema moved" would look in the wrong place, and the field keeps the verdict
// correct even if the digest's composition later changes.
func TestReviewedBinding_C11_ServerIdentityChangeLatchesServerDrift(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("premise: the reviewed target must be admitted first")
	}
	// Byte-identical tool definition; different pinned identity.
	fpRotated := republishWithIdentity(t, r.sid, r.tool, "id-rotated-by-an-attacker", `{"type":"object"}`)
	if fpRotated == r.fp1 {
		t.Fatal("premise: the composite fingerprint is expected to fold the pinned identity in, " +
			"so this republication should have moved it")
	}
	// The request is decided against the CURRENT fingerprint, so the precheck sees no drift of its
	// own and the verdict comes entirely from the activation's reviewed snapshot.
	if live := mcpLiveTrustPrecheck(ttTenant, r.sid, r.tool, fpRotated); live.DriftCode != "" {
		t.Fatalf("premise: a request decided against the current fingerprint must show no precheck "+
			"drift, got %q", live.DriftCode)
	}
	if r.request(fpRotated, r.now) {
		t.Fatal("a tool served under an identity the activation never reviewed must fail closed")
	}
	r.assertLatched(t, "server_identity_drift")
}

// ── 12 ───────────────────────────────────────────────────────────────────────────────────────
// The demoted generation's snapshot is inert: it can neither authorize nor stop G+1. Generation
// binding is what keeps one experiment's evidence from governing another's.
func TestReviewedBinding_C12_DemotedGenerationSnapshotCannotAffectTheNext(t *testing.T) {
	r := newReviewedRig(t)
	if err := r.rt.demoteCanary(r.capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if r.rt.armed(r.capb) {
		t.Fatal("premise: a demoted runtime must be disarmed")
	}
	// After the demotion the tool moves. Nothing is armed, so nothing may latch.
	fp2 := r.moveToF2(t)
	_, cat2 := mcpInventory.sharedInventory()
	requestAndApproveLive(t, r.sid, r.tool, fp2, cat2.Current().Revision())
	if r.request(fp2, r.now) {
		t.Fatal("a demoted runtime must admit nothing")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("a request against a demoted runtime must not latch an abort — there is no " +
			"generation to attribute it to")
	}

	// G+1, explicitly reviewed against F2, is unaffected by G's snapshot.
	genNew := armReviewedActivation(t, r.rt, r.capb, r.sid, r.tool, fp2)
	if genNew <= r.gen {
		t.Fatalf("a re-activation must begin a strictly newer generation, got %d after %d", genNew, r.gen)
	}
	r.g = realAdmissionGate(t, r.capb)
	if !r.request(fp2, r.now) {
		t.Fatal("G+1 reviewed against F2 must execute F2")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: G's superseded reviewed set must not stop G+1")
	}
	// And G+1 refuses what IT was not reviewed for: the old F1 is now out of scope, request-scoped.
	if r.request(r.fp1, r.now) {
		t.Fatal("G+1 must refuse a target it was not reviewed for")
	}
}

// ── matrix helpers ───────────────────────────────────────────────────────────────────────────

// mustDigest parses a hex fingerprint into the 32-byte digest the trust firewall compares.
func mustDigest(t *testing.T, fpHex string) tooltrust.FingerprintDigest {
	t.Helper()
	raw, err := hex.DecodeString(fpHex)
	if err != nil {
		t.Fatalf("decode fingerprint %q: %v", fpHex, err)
	}
	var d tooltrust.FingerprintDigest
	if len(raw) != len(d) {
		t.Fatalf("fingerprint %q is %d bytes, want %d", fpHex, len(raw), len(d))
	}
	copy(d[:], raw)
	return d
}

// tooltrustZeroDigest is the all-zero digest — never a real fingerprint, and rejected as one.
func tooltrustZeroDigest() tooltrust.FingerprintDigest { return tooltrust.FingerprintDigest{} }

// mustCanonical canonicalizes targets the way an activation does, for comparing sets in a test.
func mustCanonical(t *testing.T, targets ...canary.ReviewedTarget) canary.ReviewedTargetSet {
	t.Helper()
	set, reason := canary.CanonicalizeReviewedTargets(targets)
	if reason != canary.ReviewedOK {
		t.Fatalf("fixture targets must canonicalize, got %s", reason)
	}
	return set
}

// stripReviewedTargetsFromDurableRecord rewrites the on-disk activation record with its
// reviewed-target set removed, leaving every other field byte-identical. That is exactly the
// shape a record written by a build predating this field has, which is why §11 requires it to be
// non-executable rather than merely unusual.
func stripReviewedTargetsFromDurableRecord(t *testing.T, capb rollout.Capability) {
	t.Helper()
	path := canaryRuntimeStatePath(capb)
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read durable record: %v", err)
	}
	var st canaryRuntimeState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("decode durable record: %v", err)
	}
	if len(st.ReviewedTargets) == 0 {
		t.Fatal("premise: the record under test must have carried a reviewed set")
	}
	st.ReviewedTargets = nil
	out, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("re-encode durable record: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write durable record: %v", err)
	}
}

// ── two gates the mutation campaign demanded ─────────────────────────────────────────────────
//
// Both of these were added because a mutation SURVIVED the matrix above: the campaign found
// behaviour the twelve cases assert nothing about. A surviving mutation is a hole in the test
// set, not a harmless edit, and closing it here is the whole point of running the campaign.

// A fresh activation binds the set it was GIVEN, unconditionally — it never inherits the previous
// generation's.
//
// Every case above reaches a new generation through demote → re-activate, and `demoteCanary`
// clears the reviewed set, so an "assign only if empty" mutation was inert against all twelve.
// `beginCanaryActivation` is reachable without that demotion, and there the difference is the
// whole security property: generation G+1 would silently enforce what G was reviewed for, so a
// re-activation deliberately narrowed to a new target would keep executing the old one.
func TestReviewedBinding_ReactivationWithoutDemoteBindsTheNewSet(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway

	genOld, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(10),
		ReviewedTargets: []canary.ReviewedTarget{reviewedAt(fpF1)},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("first activation: %v", err)
	}
	// NO demotion: begin again directly on the armed runtime.
	genNew, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(10),
		ReviewedTargets: []canary.ReviewedTarget{reviewedAt(fpF2)},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("re-activation: %v", err)
	}
	if genNew <= genOld {
		t.Fatalf("generations must be strictly monotonic, got %d after %d", genNew, genOld)
	}
	set, ok := rt.activeReviewedTargets(capb)
	if !ok {
		t.Fatal("the re-activated runtime must expose a reviewed set")
	}
	if !set.Equal(mustCanonical(t, reviewedAt(fpF2))) {
		t.Fatalf("SECURITY: the new generation is bound to %+v, not the set it was activated with. "+
			"An activation that inherits its predecessor's reviewed targets enforces a review nobody "+
			"performed for it", set.Targets())
	}
	if v := set.Compare(reviewedAt(fpF1)); v != canary.ReviewedFingerprintDrift {
		t.Fatalf("the SUPERSEDED target must now read as drift, got %q", v)
	}
}

// The live gate admits ONLY an explicit grant.
//
// The denial switch in AdmitSideEffect once listed the known denials and let everything else fall
// through to the admitted path, so adding `canaryAdmitNotReviewed` to the transaction ADMITTED the
// requests it was written to refuse — an unauthorized request was handed a reservation. The switch
// is now exhaustive by construction, and this pins that: a denial class the gate does not
// recognise must fail CLOSED, because the direction this boundary must never fail in is a new
// refusal reason arriving as a grant.
func TestReviewedBinding_AnUnrecognisedDenialClassFailsClosed(t *testing.T) {
	capb := rollout.CapabilityGateway
	g := realAdmissionGate(t, capb)

	// A denial class from the future: past every constant this build knows.
	const unknownDenial = canaryAdmissionDenial(200)
	if unknownDenial == canaryAdmitGranted {
		t.Fatal("premise: the injected class must not be the grant")
	}
	g.admitUnderActivation = func(time.Time, canary.ExecutionIdentity, canaryTrustProbe) canaryAdmission {
		return canaryAdmission{Denial: unknownDenial, Active: true, Generation: 7}
	}
	d := g.AdmitSideEffect(driftGateInput("s", "t", "fp", canaryRuntimeTestNow))
	if d.Release != nil {
		d.Release()
	}
	if d.Admit {
		t.Fatal("SECURITY: a denial class the gate cannot name must fail CLOSED. Falling through to " +
			"the admitted path means every denial added to the admission transaction in future " +
			"silently grants the requests it was written to refuse")
	}
	if d.ReservationID != "" || d.ActivationGeneration != 0 {
		t.Fatalf("a refused request must carry no reservation (id=%q gen=%d)", d.ReservationID, d.ActivationGeneration)
	}

	// Control: the SAME harness admits an explicit grant, so the assertion above cannot be
	// satisfied by a gate that refuses everything.
	g.admitUnderActivation = func(time.Time, canary.ExecutionIdentity, canaryTrustProbe) canaryAdmission {
		return canaryAdmission{Denial: canaryAdmitGranted, Active: true, Generation: 7, Trusted: true, Outcome: canary.BudgetGranted}
	}
	ok := g.AdmitSideEffect(driftGateInput("s", "t", "fp", canaryRuntimeTestNow))
	if ok.Release != nil {
		ok.Release()
	}
	if !ok.Admit {
		t.Fatalf("control: an explicit grant must be admitted, reason=%s", ok.Reason.Code())
	}
}

// ── the scope-independent path (Codex P1, PR #1360) ──────────────────────────────────────────
//
// The twelve cases above drive the admission gate directly, which proves the COMPARISON. They do
// not prove it is REACHED, and in the sequence that matters most it was not: a Canary ScopeSpec
// pins the reviewed fingerprint in its tool selector, so a tool that moves F1→F2 puts every later
// request out of scope, `resolveEnforcing` routes them to the shadow/record-only fallback, and the
// activation transaction is never entered. The premise of the experiment is violated and the
// violation is exactly what hides the evidence.
//
// `canaryReviewedTargetObserved` is the path that cannot be hidden that way: it is keyed on the
// tool IDENTITY, reported for every dispatched request whatever disposition it resolved to (proven
// reachable in internal/mcp/runtime/canary_reviewed_target_test.go), and it compares against the
// activation's reviewed snapshot inside the activation lock.

// observeTarget drives the production sink for one tool identity at the activation's generation.
func (r *reviewedRig) observeTarget(gen uint64) {
	canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
		Generation: gen, ServerID: r.sid, ToolName: r.tool,
	})
}

// THE GATE. The reviewed tool moves; no request ever reaches the admission transaction; the
// experiment still stops.
func TestReviewedBinding_ScopeIndependentPathLatchesDriftWithoutAdmission(t *testing.T) {
	r := newReviewedRig(t)
	// Control first: while the target is the reviewed one, observing it stops nothing. Without
	// this, "the drift latched" below could mean the sink latches on everything.
	r.observeTarget(r.gen)
	if r.rt.abortedNow(r.capb) {
		t.Fatal("control: observing the UNCHANGED reviewed target must not stop the Canary")
	}

	r.moveToF2(t)
	r.observeTarget(r.gen)
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: the reviewed tool moved and the whole Canary must stop — even though no " +
			"request reached the admission transaction, because a fingerprint move puts every " +
			"request out of the Canary scope and the scope-gated paths can no longer see it")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "tool_fingerprint_drift" {
		t.Fatalf("first cause = %q, want tool_fingerprint_drift", code)
	}
}

// The same path, after the reviewing approval has expired — the full §7 sequence with nothing in
// the approval store left to consult and nothing in scope to route the request through.
func TestReviewedBinding_ScopeIndependentPathSurvivesApprovalExpiry(t *testing.T) {
	r := newReviewedRig(t)
	expired := r.now.Add(48 * time.Hour)
	if r.request(r.fp1, expired) {
		t.Fatal("premise: the approval must have expired")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("premise: expiry alone must not have latched anything")
	}

	r.moveToF2(t)
	r.observeTarget(r.gen)
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: drift detection must survive BOTH the approval expiring and the target " +
			"falling out of scope — the two conditions that arrive together in the sequence this " +
			"whole change exists for")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "tool_fingerprint_drift" {
		t.Fatalf("first cause = %q, want tool_fingerprint_drift", code)
	}
}

// A server identity rotation is caught on the same path, and classified as itself.
func TestReviewedBinding_ScopeIndependentPathLatchesServerIdentityDrift(t *testing.T) {
	r := newReviewedRig(t)
	republishWithIdentity(t, r.sid, r.tool, "id-rotated-by-an-attacker", `{"type":"object"}`)
	r.observeTarget(r.gen)
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: a rotated server identity must stop the Canary on this path too")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "server_identity_drift" {
		t.Fatalf("first cause = %q, want server_identity_drift", code)
	}
}

// THE COUNTERWEIGHT, and it is the reason this path may fire for every request at all.
//
// The sink is called for tools the experiment never reviewed. Latching for one of those would let
// any unrelated catalog change stop the Canary — the direction a safety control must never err in,
// and the exact hazard the previous design avoided only by the `canaryScoped` proxy that a
// fingerprint move defeats. The reviewed set decides it EXACTLY: an unreviewed key is out of scope,
// request-scoped, and latches nothing.
func TestReviewedBinding_ScopeIndependentPathIgnoresUnreviewedTools(t *testing.T) {
	r := newReviewedRig(t)

	// A tool that RESOLVES but was never reviewed is the case that matters, and it is the one an
	// earlier version of this test missed: every identity it named was absent from the catalog, so
	// the sink returned "nothing to compare" before the reviewed comparison was ever reached and
	// the gate proved nothing about it. The inventory therefore gains a second, real tool on the
	// same server, with the reviewed tool republished UNCHANGED beside it.
	const otherTool = "sibling"
	publishTwoToolInventory(t, r.sid, r.tool, otherTool)
	if _, ok := mcpCurrentAuthoritativeTarget(r.sid, otherTool); !ok {
		t.Fatal("premise: the sibling tool must resolve to a real authoritative target")
	}
	if cur, ok := mcpCurrentAuthoritativeTarget(r.sid, r.tool); !ok || cur.Fingerprint != mustDigest(t, r.fp1) {
		t.Fatal("premise: republishing must have left the REVIEWED tool exactly as reviewed")
	}

	for _, tc := range []struct {
		name, sid, tool string
		resolves        bool
	}{
		{"a resolvable sibling tool on the reviewed server", r.sid, otherTool, true},
		{"a tool that does not resolve at all", r.sid, "no-such-tool", false},
		{"another server", "some-other-server", r.tool, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := mcpCurrentAuthoritativeTarget(tc.sid, tc.tool); ok != tc.resolves {
				t.Fatalf("premise: resolvability = %v, want %v", !tc.resolves, tc.resolves)
			}
			canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
				Generation: r.gen, ServerID: tc.sid, ToolName: tc.tool,
			})
			if r.rt.abortedNow(r.capb) {
				t.Fatalf("SECURITY: a catalog observation for a tool this activation never reviewed "+
					"must not stop it (abort code %q)", r.rt.abortCodeNow(r.capb))
			}
			// And it must produce NO DRIFT VERDICT at all, not merely fail to latch. The abort
			// taxonomy would refuse to latch an unrecognised code anyway, so asserting only on
			// abortedNow lets this path quietly report drift for a tool nobody reviewed — bounded
			// evidence an operator would then have to explain. The verdict itself is the contract.
			latch := r.rt.latchReviewedDriftUnderActivation(r.capb, r.gen, r.now,
				func() (canary.ReviewedTarget, bool) {
					return mcpCurrentAuthoritativeTarget(tc.sid, tc.tool)
				})
			if latch.DriftCode != "" || latch.Latched {
				t.Fatalf("SECURITY: an unreviewed tool produced drift verdict %q (latched=%v) — an "+
					"activation must report drift only about the targets it was reviewed for",
					latch.DriftCode, latch.Latched)
			}
		})
	}
	// And the experiment is still genuinely alive afterwards.
	if !r.request(r.fp1, r.now) {
		t.Fatal("the Canary must still admit its own reviewed target")
	}
}

// publishTwoToolInventory republishes the server carrying the reviewed tool UNCHANGED plus one
// additional real tool, so a test can observe an identity that resolves but was never reviewed.
func publishTwoToolInventory(t *testing.T, sid, reviewedTool, otherTool string) {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"` + reviewedTool + `","input_schema":{"type":"object"}},
	            {"name":"` + otherTool + `","input_schema":{"type":"object","properties":{"z":{"type":"string"}}}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
}

// The generation rules are the same as every other latch on this runtime, and they are what stop a
// stale observation from reaching an activation it was never made under.
func TestReviewedBinding_ScopeIndependentPathHonoursGenerationRules(t *testing.T) {
	t.Run("generation zero latches nothing", func(t *testing.T) {
		r := newReviewedRig(t)
		r.moveToF2(t)
		r.observeTarget(0)
		if r.rt.abortedNow(r.capb) {
			t.Fatal("SECURITY: an observation naming no activation must never be read as 'whatever " +
				"is current' — that wildcard belongs only to the unbound entry point")
		}
	})
	t.Run("a superseded generation latches nothing", func(t *testing.T) {
		r := newReviewedRig(t)
		stale := r.gen
		if err := r.rt.demoteCanary(r.capb); err != nil {
			t.Fatalf("demote: %v", err)
		}
		fp2 := r.moveToF2(t)
		genNew := armReviewedActivation(t, r.rt, r.capb, r.sid, r.tool, fp2)
		if genNew == stale {
			t.Fatal("premise: the re-activation must have bumped the generation")
		}
		// The stale observation names the OLD activation; the one in force was explicitly
		// reviewed against F2 and is healthy.
		r.observeTarget(stale)
		if r.rt.abortedNow(r.capb) {
			t.Fatal("SECURITY: an observation made under a superseded activation must not stop the " +
				"one that replaced it — its reviewed set may legitimately differ")
		}
	})
	t.Run("a demoted runtime latches nothing", func(t *testing.T) {
		r := newReviewedRig(t)
		gen := r.gen
		if err := r.rt.demoteCanary(r.capb); err != nil {
			t.Fatalf("demote: %v", err)
		}
		r.moveToF2(t)
		r.observeTarget(gen)
		if r.rt.abortedNow(r.capb) {
			t.Fatal("SECURITY: with no live activation there is nothing to stop, and nothing an " +
				"observation may be charged to")
		}
	})
}
