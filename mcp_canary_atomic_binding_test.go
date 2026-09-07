package main

import (
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mcp_canary_atomic_binding_test.go — the §8 race matrix for the ATOMIC activation-bound admission
// transaction.
//
// Every case here is BARRIER-DRIVEN: the racing goroutine is released from inside the trust probe,
// which runs while the activation lock is held, so the interleaving under test is forced rather
// than hoped for. There are no sleeps and no timing assumptions; each case is deterministic on any
// hardware, at any load, with or without -race.
//
// The property under test is the one five previous iterations failed to establish: an observation
// may latch generation G only if G was active before the observation began, stayed the same active
// activation throughout it, and the latch decision was made against G atomically.

// atomicRig is one armed capability runtime plus the knobs the matrix needs.
type atomicRig struct {
	rt   *canaryRuntime
	capb rollout.Capability
}

func newAtomicRig(t *testing.T) *atomicRig {
	t.Helper()
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	swapCanaryClock(t, func() time.Time { return canaryRuntimeTestNow })
	swapCanaryTimer(t)
	return &atomicRig{rt: rt, capb: rollout.CapabilityGateway}
}

func (r *atomicRig) arm(t *testing.T, total int) uint64 {
	t.Helper()
	if _, err := r.rt.beginCanaryActivation(r.capb, runtimeTestBudget(total), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin activation: %v", err)
	}
	g := r.rt.currentGeneration(r.capb)
	if g == 0 {
		t.Fatal("premise: an armed activation must have a non-zero generation")
	}
	return g
}

// remaining reports the CURRENT activation's unspent budget. It is how the matrix proves WHICH
// enforcer a reservation actually landed on — a generation number in the result struct cannot,
// because it is captured before the work happens.
func (r *atomicRig) remaining() int {
	cr := r.rt.capRuntime(r.capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if cr.enforcer == nil {
		return -1
	}
	return cr.enforcer.Remaining()
}

func (r *atomicRig) admit(trust canaryTrustProbe) canaryAdmission {
	return r.rt.admitLiveExecution(r.capb, canaryRuntimeTestNow, canary.ExecutionIdentity{
		Principal: "p1", Tool: "t1", Server: "s1",
	}, trust)
}

// probeDrift returns a probe reporting an authoritative drift.
func probeDrift(code string) canaryTrustProbe { return func() (bool, string) { return false, code } }

// probeTrusted returns a probe reporting healthy trust.
func probeTrusted() canaryTrustProbe { return func() (bool, string) { return true, "" } }

// ── A. Normal drift ──────────────────────────────────────────────────────────

// TestAtomicBinding_A_DriftLatchesTheActiveGeneration is the base case: with G active, an
// authoritative drift latches G, denies the request, and authorizes no attempt.
func TestAtomicBinding_A_DriftLatchesTheActiveGeneration(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 3)

	adm := r.admit(probeDrift("tool_fingerprint_drift"))

	if adm.Denial != canaryAdmitDrift {
		t.Fatalf("want a drift denial, got %v", adm.Denial)
	}
	if adm.Generation != g {
		t.Fatalf("the drift must be charged to the active generation %d, got %d", g, adm.Generation)
	}
	if !adm.Latched || !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: an authoritative drift under an active activation must latch the whole Canary")
	}
	if adm.Granted() {
		t.Fatal("SECURITY: a drifted request must not be authorized")
	}
	if st := canaryAbortStatusFor(r.capb); st.FirstAbortReason != "tool_fingerprint_drift" {
		t.Fatalf("first cause should be the drift, got %q", st.FirstAbortReason)
	}
}

// ── B. Demotion racing the observation ───────────────────────────────────────

// TestAtomicBinding_B_DemotionRacingTheObservationNeverLatchesTheReplacement forces a demotion to
// race the trust evaluation by releasing it from INSIDE the probe.
//
// Because the probe runs under the activation lock, the demotion cannot interleave: it blocks until
// the transaction finishes. So exactly one of two outcomes is legal — the observation owned G and
// latched G, or it never started and saw no active G. What must never happen is a latch of anything
// other than G.
func TestAtomicBinding_B_DemotionRacingTheObservationNeverLatchesTheReplacement(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 3)

	var wg sync.WaitGroup
	released := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-released // released from inside the critical section
		_ = r.rt.demoteCanary(r.capb)
	}()

	adm := r.admit(func() (bool, string) {
		close(released) // the demotion is now runnable and MUST be unable to proceed
		return false, "tool_fingerprint_drift"
	})
	wg.Wait()

	if adm.Generation != g {
		t.Fatalf("SECURITY: the transaction must be bound to the generation it started under (%d), got %d", g, adm.Generation)
	}
	if adm.Denial != canaryAdmitDrift {
		t.Fatalf("want a drift denial, got %v", adm.Denial)
	}
	if adm.Granted() {
		t.Fatal("SECURITY: a drifted request must never be authorized")
	}
}

// ── C. Reactivation ──────────────────────────────────────────────────────────

// TestAtomicBinding_C_ObservationCanNeverLatchTheReplacementActivation is the round-15-to-19
// finding stated as a property: an observation that began under G can never stop G+1.
//
// The demote AND the re-activation are both released from inside the probe, so the transaction
// completes against G while a whole new activation is waiting to be created. The new activation
// must start clean.
func TestAtomicBinding_C_ObservationCanNeverLatchTheReplacementActivation(t *testing.T) {
	r := newAtomicRig(t)
	g1 := r.arm(t, 3)

	var wg sync.WaitGroup
	released := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-released
		_ = r.rt.demoteCanary(r.capb)
		_, _ = r.rt.beginCanaryActivation(r.capb, runtimeTestBudget(3), canaryRuntimeTestNow)
	}()

	adm := r.admit(func() (bool, string) {
		close(released)
		return false, "tool_fingerprint_drift"
	})
	wg.Wait()

	g2 := r.rt.currentGeneration(r.capb)
	if g2 == g1 {
		t.Fatalf("premise: the racing goroutine must have created a new generation, still %d", g1)
	}
	if adm.Generation != g1 {
		t.Fatalf("SECURITY: the observation must be charged to %d, got %d", g1, adm.Generation)
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: an observation that began under the previous activation stopped the one " +
			"that replaced it — the new experiment never saw this drift")
	}
	if st := canaryAbortStatusFor(r.capb); st.ExecutionAuthority != "granted" {
		t.Fatalf("the fresh activation must keep its authority, got %q", st.ExecutionAuthority)
	}
}

// ── D. The rollout publication gap ───────────────────────────────────────────

// TestAtomicBinding_D_PublicationGapDeniesAndPoisonsNothing covers §6: commitRolloutTransitionAt
// publishes the live Canary mode BEFORE beginCanaryActivation arms the runtime, so a request can
// resolve to an executing disposition while no activation exists.
//
// Admission must fail closed, and — the part that matters — a drift observed in that interval must
// not be banked against the activation that arrives next.
func TestAtomicBinding_D_PublicationGapDeniesAndPoisonsNothing(t *testing.T) {
	r := newAtomicRig(t) // deliberately NOT armed: this is the gap

	probed := false
	adm := r.admit(func() (bool, string) {
		probed = true
		return false, "tool_fingerprint_drift"
	})

	if adm.Denial != canaryAdmitNoActivation {
		t.Fatalf("admission must fail closed with no activation, got %v", adm.Denial)
	}
	if adm.Generation != 0 || adm.Latched {
		t.Fatalf("nothing may be attributed or latched with no activation: gen=%d latched=%v", adm.Generation, adm.Latched)
	}
	if probed {
		t.Fatal("the trust probe must not even run without an activation to attribute it to")
	}

	// The activation now arrives. It must start clean — the gap observation cannot have poisoned it.
	g := r.arm(t, 3)
	if r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: a drift observed during the publication gap latched activation %d, "+
			"which did not exist when it was observed", g)
	}
	if st := canaryAbortStatusFor(r.capb); st.ExecutionAuthority != "granted" {
		t.Fatalf("the new activation must be executable, got %q", st.ExecutionAuthority)
	}
}

// ── E. Trust under G, reservation under G+1 ──────────────────────────────────

// TestAtomicBinding_E_TrustAndReservationShareOneGeneration constructs the old race deliberately:
// a demote-and-reactivate released from inside the probe, on the path that RESERVES.
//
// Under the previous design the trust verdict and the reservation were separate calls, so a request
// could be trusted under G and reserve under G+1. Here they are one transaction, so the split is
// not merely unlikely — it is unrepresentable.
func TestAtomicBinding_E_TrustAndReservationShareOneGeneration(t *testing.T) {
	r := newAtomicRig(t)
	g1 := r.arm(t, 3)

	var wg sync.WaitGroup
	released := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-released
		_ = r.rt.demoteCanary(r.capb)
		_, _ = r.rt.beginCanaryActivation(r.capb, runtimeTestBudget(3), canaryRuntimeTestNow)
	}()

	adm := r.admit(func() (bool, string) {
		close(released) // a replacement activation is now racing the reservation below
		return true, ""
	})
	wg.Wait()

	g2 := r.rt.currentGeneration(r.capb)
	if g2 == g1 {
		t.Fatalf("premise: a replacement generation must exist, still %d", g1)
	}
	if !adm.Trusted {
		t.Fatal("premise: the probe reported trust")
	}
	if adm.Generation != g1 {
		t.Fatalf("SECURITY: trust was evaluated under %d but the transaction reports %d — a request "+
			"must not inherit trust from one activation and budget authority from another", g1, adm.Generation)
	}
	// THE ACTUAL PROOF, and the reason a generation field is not enough: a result struct captured
	// before the work happened still SAYS g1 even if the spend landed on the replacement's enforcer.
	// So look at where the budget actually went. G2 was armed with a full budget and no request has
	// ever been admitted under it; if the reservation leaked across the boundary, G2 is short.
	if got, want := r.remaining(), 3; got != want {
		t.Fatalf("SECURITY: the replacement activation has %d of %d slots left — this request was "+
			"trusted under %d and spent budget under %d", got, want, g1, g2)
	}
}

// ── F. Control ───────────────────────────────────────────────────────────────

// TestAtomicBinding_F_HealthyRequestReservesUnderExactlyG is the anti-vacuity control. Without it,
// a transaction that denied everything would satisfy every case above.
func TestAtomicBinding_F_HealthyRequestReservesUnderExactlyG(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 3)

	adm := r.admit(probeTrusted())

	if !adm.Granted() {
		t.Fatalf("control: a trusted request under an armed activation with budget must be granted, got %v", adm.Denial)
	}
	if adm.Generation != g {
		t.Fatalf("control: the reservation must be made under exactly %d, got %d", g, adm.Generation)
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("control: a healthy admission must not stop the Canary")
	}
	if adm.DriftCode != "" || adm.Latched {
		t.Fatalf("control: nothing should have latched: drift=%q latched=%v", adm.DriftCode, adm.Latched)
	}
}

// ── Structural: the lock is actually held across the observation ─────────────

// TestAtomicBinding_TrustProbeRunsUnderTheActivationLock is the structural proof the whole matrix
// rests on, and it contains NO timing assumption.
//
// The first version of this test raced a peer goroutine against the probe and checked whether the
// peer had finished yet. That was worthless: with the lock released the peer still usually had not
// been scheduled, so the test passed against the very defect it was written to catch — the same
// "checks the statement I had in mind, not the one the guarantee needs" failure this work has hit
// before. It now asks the lock directly.
//
// The peer performs ONE TryLock at a point the barrier guarantees is inside the probe, and the
// probe blocks until that attempt has been made and reported. Acquiring the activation mutex while
// the trust observation is running is only possible if the observation is not covered by it.
func TestAtomicBinding_TrustProbeRunsUnderTheActivationLock(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 3)
	cr := r.rt.capRuntime(r.capb)

	var wg sync.WaitGroup
	released := make(chan struct{})
	tried := make(chan struct{})
	var peerAcquired bool

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-released
		if cr.mu.TryLock() {
			peerAcquired = true
			cr.mu.Unlock()
		}
		close(tried)
	}()

	r.admit(func() (bool, string) {
		close(released)
		<-tried // deterministic: the probe does not return until the peer has actually tried
		return true, ""
	})
	wg.Wait()

	if peerAcquired {
		t.Fatal("SECURITY: the activation mutex was ACQUIRABLE while the trust observation was " +
			"running, so the observation is not covered by it. Nothing it reports can be attributed " +
			"to the activation it appeared to run under — which is the entire defect this closes")
	}
}

// TestAtomicBinding_TrustProbeMayNotReEnterTheRuntime pins the lock-order premise recorded in
// mcp_canary_admission.go: the probe runs with cr.mu held, so a probe that called back into the
// activation runtime would self-deadlock. Nothing in the trust path does today — this fails loudly
// if that ever changes, rather than hanging CI.
func TestAtomicBinding_TrustProbeMayNotReEnterTheRuntime(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 3)

	done := make(chan canaryAdmission, 1)
	go func() {
		done <- r.admit(probeTrusted()) // the REAL probe shape: no re-entry
	}()
	select {
	case adm := <-done:
		if !adm.Granted() {
			t.Fatalf("premise: a trusted probe should be granted, got %v", adm.Denial)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the admission transaction did not complete: a re-entrant trust probe would " +
			"self-deadlock under cr.mu — audit the lock order recorded in mcp_canary_admission.go")
	}
}

// TestAtomicBinding_ActiveWithZeroGenerationIsNotAnActivation forces the one state the normal
// lifecycle cannot produce: a runtime flagged active whose generation is still zero.
//
// It exists because zero is not a null downstream — tripCanaryAbortForGeneration reads wantGen == 0
// as "whatever is current" and skips the generation check, a wildcard reserved for the unbound
// entry point. A transaction that let a zero out as an attribution would hand the abort authority a
// wildcard, so the guard is explicit and this pins it against a state no test could otherwise reach.
func TestAtomicBinding_InactiveRuntimeIsNotAnActivation(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 3)

	// Force the one shape the lifecycle cannot produce on its own: not active, but with the
	// enforcer and aborter still in place. demoteCanary nils both, so without this the `!cr.active`
	// clause is shadowed by the nil checks and a mutation removing it would survive unnoticed.
	cr := r.rt.capRuntime(r.capb)
	cr.mu.Lock()
	cr.active = false
	cr.mu.Unlock()

	probed := false
	adm := r.admit(func() (bool, string) {
		probed = true
		return false, "tool_fingerprint_drift"
	})

	if adm.Denial != canaryAdmitNoActivation {
		t.Fatalf("SECURITY: an inactive runtime must not be treated as an activation, got %v", adm.Denial)
	}
	if adm.Latched || adm.Generation != 0 {
		t.Fatalf("nothing may be attributed or latched: gen=%d latched=%v", adm.Generation, adm.Latched)
	}
	if probed {
		t.Fatal("SECURITY: the trust probe ran against an inactive runtime")
	}
}

func TestAtomicBinding_ActiveWithZeroGenerationIsNotAnActivation(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 3)

	cr := r.rt.capRuntime(r.capb)
	cr.mu.Lock()
	cr.generation = 0 // corrupt: active, but naming no activation
	cr.mu.Unlock()

	probed := false
	adm := r.admit(func() (bool, string) {
		probed = true
		return false, "tool_fingerprint_drift"
	})

	if adm.Denial != canaryAdmitNoActivation {
		t.Fatalf("SECURITY: a zero generation must not count as an activation, got %v", adm.Denial)
	}
	if adm.Generation != 0 || adm.Latched {
		t.Fatalf("nothing may be attributed or latched: gen=%d latched=%v", adm.Generation, adm.Latched)
	}
	if probed {
		t.Fatal("SECURITY: the trust probe ran with no generation to charge its verdict to")
	}
}

// ── Pre-admission drift evidence (§6) ────────────────────────────────────────
//
// The pre-executor refusal path binds to no activation, so it deliberately latches nothing. What
// it MUST do is leave a bounded, readable trace: a counter nothing can read is not evidence, it is
// dead state that only looks like observability. These gates pin both halves — that the write is
// bounded and capability-scoped, and that the read actually reaches the operator surface.

func resetPreAdmissionDriftForTest(t *testing.T) {
	t.Helper()
	mcpCanaryPreAdmissionDrift.mu.Lock()
	mcpCanaryPreAdmissionDrift.m = map[string]map[string]uint64{}
	mcpCanaryPreAdmissionDrift.mu.Unlock()
	t.Cleanup(func() {
		mcpCanaryPreAdmissionDrift.mu.Lock()
		mcpCanaryPreAdmissionDrift.m = map[string]map[string]uint64{}
		mcpCanaryPreAdmissionDrift.mu.Unlock()
	})
}

func TestAtomicBinding_PreAdmissionDriftEvidenceIsBoundedAndReadable(t *testing.T) {
	resetPreAdmissionDriftForTest(t)

	gw := rollout.CapabilityGateway.String()
	noteCanaryPreAdmissionDrift(gw, "tool_fingerprint_drift")
	noteCanaryPreAdmissionDrift(gw, "tool_fingerprint_drift")
	noteCanaryPreAdmissionDrift(gw, "server_identity_drift")

	// The key space is bounded: an arbitrary code can never become a new key.
	for _, junk := range []string{"", "attacker-controlled", "tool_fingerprint_drift ", "🙂"} {
		noteCanaryPreAdmissionDrift(gw, junk)
	}

	got := canaryPreAdmissionDriftCounts(gw)
	if got["tool_fingerprint_drift"] != 2 {
		t.Fatalf("tool_fingerprint_drift = %d, want 2", got["tool_fingerprint_drift"])
	}
	if got["server_identity_drift"] != 1 {
		t.Fatalf("server_identity_drift = %d, want 1", got["server_identity_drift"])
	}
	if got["other"] != 4 {
		t.Fatalf("unrecognised codes must fold into exactly one bucket: other = %d, want 4", got["other"])
	}
	if len(got) != 3 {
		t.Fatalf("SECURITY: the evidence key space is unbounded — %d keys: %v", len(got), got)
	}

	// The counter is capability-scoped: one capability's evidence never appears under another.
	if other := canaryPreAdmissionDriftCounts(rollout.CapabilityManagement.String()); len(other) != 0 {
		t.Fatalf("management must carry no gateway evidence, got %v", other)
	}

	// The mutation returns a COPY: a caller cannot reach in and rewrite the evidence.
	got["tool_fingerprint_drift"] = 999
	if again := canaryPreAdmissionDriftCounts(gw); again["tool_fingerprint_drift"] != 2 {
		t.Fatalf("the accessor leaked its backing map: %d", again["tool_fingerprint_drift"])
	}
}

func TestAtomicBinding_PreAdmissionDriftReachesTheOperatorSurface(t *testing.T) {
	resetPreAdmissionDriftForTest(t)

	noteCanaryPreAdmissionDrift(rollout.CapabilityGateway.String(), "server_identity_drift")

	st := mcpCanaryStatus()
	ar, ok := st["activation_runtime"].(map[string]any)
	if !ok {
		t.Fatal("activation_runtime missing from the Canary status surface")
	}
	counts, ok := ar["pre_admission_drift"].(map[string]uint64)
	if !ok {
		t.Fatalf("SECURITY: pre-admission drift evidence is write-only — it never reaches "+
			"GET /api/mcp/rollout. activation_runtime keys: %v", keysOf(ar))
	}
	if counts["server_identity_drift"] != 1 {
		t.Fatalf("server_identity_drift = %d on the operator surface, want 1", counts["server_identity_drift"])
	}
}

// ── G-I. The pre-executor drift latch ────────────────────────────────────────
//
// A rug-pull that lands BEFORE policy resolution never reaches the admission transaction: the
// pipeline refuses it upstream. Codex round 20 showed why "it will be caught on the next request"
// is false — after the catalog moves, later requests resolve cleanly against the NEW fingerprint
// and fail approval validation, which is request-scoped, not drift. So an authoritative
// whole-Canary breach would stop nothing at all.
//
// latchDriftUnderActivation closes that by re-deriving the drift under the activation lock. These
// cases pin the three outcomes that matter: it latches when an activation owns the observation, it
// latches NOTHING in the publication gap, and it never invents a breach.

func (r *atomicRig) latchDrift(trust canaryTrustProbe) canaryDriftLatch {
	return r.rt.latchDriftUnderActivation(r.capb, canaryRuntimeTestNow, trust)
}

// TestAtomicBinding_G_PreExecutorDriftLatchesTheActiveGeneration is the case Codex round 20 proved
// unreachable: the drift is seen before the executor, and it must still stop the experiment.
func TestAtomicBinding_G_PreExecutorDriftLatchesTheActiveGeneration(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 4)

	got := r.latchDrift(probeDrift("tool_fingerprint_drift"))

	if !got.Active || got.Generation != g {
		t.Fatalf("latch ran under generation %d (active=%v), want %d", got.Generation, got.Active, g)
	}
	if got.DriftCode != "tool_fingerprint_drift" {
		t.Fatalf("DriftCode = %q, want the code re-derived under the lock", got.DriftCode)
	}
	if !got.Latched {
		t.Fatal("SECURITY: an authoritative pre-executor drift did not latch the whole Canary — " +
			"the breach condition is declared but unreachable (Codex round 20)")
	}
	// The activation must now be dead: no later request may execute under it.
	if r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatal("SECURITY: the activation is still execution-eligible after a latched drift")
	}
	// And the latch must be the SAME authority the admission path uses, not a parallel one.
	if adm := r.admit(probeTrusted()); adm.Denial != canaryAdmitAborted {
		t.Fatalf("a request after the latch was denied %v, want canaryAdmitAborted", adm.Denial)
	}
}

// TestAtomicBinding_H_PreExecutorDriftInThePublicationGapLatchesNothing pins §6. During ModeCanary
// with no live activation there is nothing to attribute the observation to, and it must never be
// inherited by an activation created afterwards.
func TestAtomicBinding_H_PreExecutorDriftInThePublicationGapLatchesNothing(t *testing.T) {
	r := newAtomicRig(t)
	// Deliberately NOT armed: this is the publication gap.

	got := r.latchDrift(probeDrift("server_identity_drift"))

	if got.Active || got.Generation != 0 || got.Latched {
		t.Fatalf("SECURITY: a drift observed with no live activation reported %+v — it must "+
			"latch nothing and name no generation", got)
	}

	// Now an activation is published. It must be born healthy: it never saw that drift.
	g := r.arm(t, 4)
	if !r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatalf("SECURITY: activation %d inherited a drift observed before it existed", g)
	}
	if adm := r.admit(probeTrusted()); !adm.Granted() || adm.Generation != g {
		t.Fatalf("a healthy request under the new activation was denied: %+v", adm)
	}
}

// TestAtomicBinding_I_PreExecutorLatchNeverInventsABreach is the anti-vacuity control. The caller's
// upstream verdict is NOT the latch input — only the value re-derived under the lock is — so a
// probe that finds live state healthy must leave the experiment running. Without this, "latch
// whenever the pipeline reports drift" would pass every gate above while being able to stop a
// healthy Canary on a stale observation.
func TestAtomicBinding_I_PreExecutorLatchNeverInventsABreach(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 4)

	got := r.latchDrift(probeTrusted())

	if got.Latched || got.DriftCode != "" {
		t.Fatalf("SECURITY: the latch fired without re-deriving a drift: %+v", got)
	}
	if got.Generation != g {
		t.Fatalf("Generation = %d, want %d", got.Generation, g)
	}
	if !r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatal("SECURITY: a healthy Canary was stopped by an observation that did not reproduce")
	}
}

// TestAtomicBinding_PreExecutorLatchHoldsTheActivationLockAcrossItsProbe is the structural twin of
// the admission-path gate: the re-derivation is worthless if the activation can change under it.
func TestAtomicBinding_PreExecutorLatchHoldsTheActivationLockAcrossItsProbe(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 4)
	cr := r.rt.capRuntime(r.capb)

	var (
		wg           sync.WaitGroup
		peerAcquired bool
	)
	released := make(chan struct{})
	tried := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-released
		if cr.mu.TryLock() {
			peerAcquired = true
			cr.mu.Unlock()
		}
		close(tried)
	}()

	r.latchDrift(func() (bool, string) {
		close(released)
		<-tried
		return false, "tool_fingerprint_drift"
	})
	wg.Wait()

	if peerAcquired {
		t.Fatal("SECURITY: the activation mutex was ACQUIRABLE while the pre-executor drift " +
			"re-derivation was running — the observation is not activation-bound, which is the " +
			"exact defect five review rounds were spent on")
	}
}
