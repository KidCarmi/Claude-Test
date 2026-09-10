package main

import (
	"sync"
	"time"

	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mcp_canary_admission.go — the ATOMIC activation-bound admission transaction.
//
// WHY THIS EXISTS. PR #1314 shipped the whole-Canary automatic abort with a pre-admission drift
// path that read the activation generation around an UNLOCKED trust observation and compared the
// two reads. Codex rounds 15-19 produced a P1 against every iteration of that shape, and the last
// one named the reason exactly: counter equality proves the value did not CHANGE, it does not
// prove the generation was ACTIVE for the whole observation. Two reads of G can both be a stale G
// (the rollout publication gap, §6) or both straddle work that was never bound to G at all.
//
// The invariant this file exists to make true — a pre-admission observation may latch generation G
// only if G was active before the observation began, remained the same active activation for the
// complete observation, and the latch decision is made against G atomically — is not expressible
// with reads around a critical section. It requires the observation and the latch to happen INSIDE
// one. So they do.
//
// LOCK-ORDER AUDIT (required before implementation). The trust probe runs while cr.mu is held, so
// what it may touch is load-bearing and was verified against the tree, not assumed:
//
//	cr.mu ─→ mcpInventory.mu   (RLock; returns two pointers immediately)
//	      ─→ mcpToolTrust.mu   (RLock; returns the store pointer immediately)
//
//	catalog.Current() / registry.Current() are atomic.Pointer loads and take NO lock.
//
// Two facts make that order safe rather than merely plausible. (1) NOTHING reachable from the trust
// probe references canaryRuntime — tooltrust, inventory, catalog, registry and internal/mcp/canary
// contain no path back — so the edge cannot close into a cycle. (2) cr.mu previously reached NONE
// of those packages, so this introduces the FIRST edge between them and it is one-way by
// construction. A future change that makes any of those packages call into canaryRuntime creates
// the cycle; TestAtomicBinding_TrustProbeMayNotReEnterTheRuntime pins that it does not today, and
// it drives the REAL production probe rather than a closure so it can actually see such an edge
// appear.
//
// ONE EDGE WAS DELIBERATELY REMOVED RATHER THAN ORDERED, and the reason is worth stating because
// the first version of this audit got it wrong. It concluded the probe was safe because
// "ActiveLiveApprovals is a read-only in-memory walk". That is true and it is not the question:
// the walk takes tooltrust.Store.mu, and EVERY approval mutation holds that same mutex across
// persistLocked and its atomic file write. So one stuck disk would have blocked cr.mu, and with it
// automatic abort, demotion and generation revalidation — the controls whose whole job is to stop
// the experiment (Codex round 21). §5 forbids exactly that, and no ordering argument helps: the
// hazard is DURATION, not deadlock, and a correct lock order is perfectly compatible with being
// blocked for as long as the disk is.
//
// The split that fixes it is described on mcpLiveTrustPrecheck. What matters here is why it is
// sound: every signal that can latch the whole Canary comes from pointer-published inventory
// state, and the approval lookup — the only blocking part — can produce nothing but a
// request-scoped verdict, which needs no activation attribution at all. So the durable store is
// consulted BEFORE the lock is taken, and the transaction keeps its atomic binding.
// TestAtomicBinding_ApprovalLookupDoesNotHoldTheActivationLock pins that structurally.
//
// The probe performs no network I/O, no credential materialization, no DNS and no upstream call.
// The durable persist that DOES happen under this lock is the SAME persistLocked every other
// canary-runtime mutation already performs under it — pre-existing, and the abort path's own write.

// canaryTrustProbe is the live-trust predicate evaluated INSIDE the activation critical section.
//
// It is deliberately a nullary closure: the caller binds the request's (tenant, server, tool,
// fingerprint) when it builds the probe, so the runtime never learns request shape and the trust
// layering stays where it is. The contract on any implementation is narrow and is the reason the
// lock can be held across it — LOCAL CONTROL-PLANE STATE ONLY. No network I/O, no credential
// materialization, no DNS, no upstream call, no unbounded or blocking work.
type canaryTrustProbe func() canaryTrustObservation

// canaryTrustObservation is one probe's report of the CURRENT authoritative state of the target a
// request names. The transaction, not the probe, decides what it means for the activation: the
// probe reports observations, the transaction compares them against what the activation was
// reviewed against and owns every latch.
//
// That division is the point. A probe that decided drift on its own would have to know what was
// reviewed, and the only record of that it could reach without the lock is the approval store —
// which is exactly the conflation this change exists to remove (see reviewed.go).
type canaryTrustObservation struct {
	// DriftCode is an authoritative whole-Canary breach the PROBE itself established from
	// pointer-published inventory state — today, the reviewed server no longer being usable.
	// Non-empty short-circuits the transaction straight to the latch.
	DriftCode string
	// Found reports that a current authoritative target was resolvable for this request. False is
	// request-scoped: a request naming a target that does not resolve is a malformed or
	// wrong-tenant request, never evidence that the reviewed target moved.
	Found bool
	// Current is the CURRENT authoritative target — fingerprint, format and pinned server identity
	// as observed now. It is what the transaction compares against the activation's reviewed set.
	Current canary.ReviewedTarget
	// Trusted is the request-scoped authorization verdict (a valid live approval covers this exact
	// request). It is consulted only AFTER the reviewed comparison passes.
	Trusted bool
}

// canaryAdmissionDenial is the bounded reason class a denied transaction reports.
//
// It is an EXPLICIT field rather than something the caller infers from the other result fields. The
// first draft of this refactor let the caller infer it, and an already-aborted Canary — which
// returns "not trusted" only because the trust probe never ran — was reported to the client as a
// trust-revalidation failure instead of a budget denial. Two different denials must not be
// distinguishable only by which field happens to be zero.
type canaryAdmissionDenial uint8

const (
	canaryAdmitGranted      canaryAdmissionDenial = iota // the transaction authorizes a physical attempt
	canaryAdmitNoActivation                              // no armed activation owned this transaction
	canaryAdmitAborted                                   // the Canary is already stopped
	canaryAdmitDrift                                     // authoritative drift; latched against Generation
	canaryAdmitUntrusted                                 // request-scoped: this request is not authorized
	canaryAdmitNotReviewed                               // request-scoped: not a target THIS activation was reviewed for
	canaryAdmitBudget                                    // budget / blast-radius denial
)

// canaryAdmission is the bounded result of one atomic admission transaction. The caller receives
// facts, never a lock and never a generation it must re-verify.
type canaryAdmission struct {
	// Denial is the bounded reason class. canaryAdmitGranted means the attempt is authorized.
	Denial canaryAdmissionDenial
	// Active reports whether an armed activation owned this transaction. False means there was no
	// generation to bind to — the rollout publication gap (§6), a demotion, or an unarmed runtime —
	// and NOTHING was latched, reserved or observed against any activation.
	Active bool
	// Generation is the EXACT activation the whole transaction ran under. Non-zero whenever Active
	// is true; zero otherwise, and a zero is never handed to the abort authority.
	Generation uint64
	// Trusted is the trust verdict, evaluated under the same lock.
	Trusted bool
	// DriftCode is the authoritative whole-Canary breach code when the trust probe found the
	// reviewed target is no longer the one in force. Non-empty implies the abort was tripped
	// against Generation inside this transaction.
	DriftCode string
	// Outcome is the budget outcome. Meaningful only when Trusted and DriftCode == "".
	Outcome canary.BudgetOutcome
	// Latched reports whether this transaction latched the whole-Canary abort.
	Latched bool
}

// Granted reports whether this admission authorizes a physical attempt.
func (a canaryAdmission) Granted() bool { return a.Denial == canaryAdmitGranted }

// admitLiveExecution is the single activation-bound admission transaction: it verifies an armed
// activation, captures its exact generation, evaluates live trust, latches an authoritative drift
// against THAT generation, and reserves the budget — all under one acquisition of cr.mu.
//
// The ordering inside is not incidental:
//
//	active + non-zero generation   — there is an activation to attribute to at all
//	execution eligibility          — an already-aborted Canary admits nothing
//	trust probe                    — evaluated against the activation that will be latched
//	drift  ⇒ trip(G) + persist     — fail-closed; the request is denied
//	untrusted ⇒ deny               — request-scoped; nothing is latched and nothing persisted
//	reserve(G) + persist           — only a trusted request spends budget
//
// Trust is checked BEFORE the reservation so an untrusted request never consumes blast radius,
// preserving the gate's prior ordering. The reservation can therefore only ever be made under the
// SAME generation the trust verdict was computed against: "trust under G, reserve under G+1" is not
// a race that is unlikely here, it is a state the code cannot express.
func (rt *canaryRuntime) admitLiveExecution(capb rollout.Capability, now time.Time, ident canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()

	// (1) An activation must own this transaction. During the rollout publication gap the live mode
	// is already Canary while beginCanaryActivation has not run (§6), so "the mode says Canary" is
	// NOT proof an activation exists and is deliberately not consulted here. A zero generation is
	// rejected with the same force: it is the wildcard the abort authority reads as "whatever is
	// current", so it must never leave this function as an attribution (§7).
	if !cr.active || cr.enforcer == nil || cr.aborter == nil || cr.generation == 0 {
		return canaryAdmission{Denial: canaryAdmitNoActivation}
	}
	gen := cr.generation

	// (2) An aborted Canary admits nothing. Checked before the trust probe so a stopped experiment
	// does no further work and cannot latch a second cause over its immutable first one.
	if !cr.aborter.ExecutionEligible(gen) {
		return canaryAdmission{Denial: canaryAdmitAborted, Active: true, Generation: gen, Outcome: canary.BudgetDeniedInvalid}
	}

	// (3) Observe the CURRENT authoritative target, under the lock, against the activation captured
	// above. The probe reads local control-plane state only (§5).
	var obs canaryTrustObservation
	if trust != nil {
		obs = trust()
	}

	// (4) An authoritative drift the probe itself established is a whole-Canary breach: latch it
	// against G, durably, fail-closed.
	if obs.DriftCode != "" {
		return rt.latchDriftLocked(cr, capb, obs.DriftCode, gen, now)
	}

	// (5) THE REVIEWED COMPARISON — the fact this transaction exists to decide.
	//
	// It is made against the activation's OWN immutable record, never against an approval, so it
	// stays decidable for the whole activation window even after every approval that recorded the
	// review has expired. That independence is the entire Round-24 fix: an activation may run for
	// FirstCanaryMaxWindowCeiling (7 days) while an approval may live for at most
	// MaxInitialCanaryApprovalTTL (24 hours), so for most of its life the approval store can no
	// longer say what this activation was reviewed against — and a later approval for a DIFFERENT
	// fingerprint must never be able to say it either.
	//
	// A request naming a target that does not resolve is request-scoped: no evidence the reviewed
	// target moved, so nothing is latched.
	if !obs.Found {
		return canaryAdmission{Denial: canaryAdmitUntrusted, Active: true, Generation: gen, Outcome: canary.BudgetDeniedInvalid}
	}
	switch v := cr.reviewed.Compare(obs.Current); v {
	case canary.ReviewedMatches:
		// The current target IS the reviewed one. Proceed to authorization.
	case canary.ReviewedOutOfScope:
		// This activation was never reviewed for this target. REQUEST-SCOPED by design: an
		// activation correctly refusing a target outside its review is the Canary working, and
		// latching the whole experiment for it would let any unrelated request stop it.
		return canaryAdmission{Denial: canaryAdmitNotReviewed, Active: true, Generation: gen, Outcome: canary.BudgetDeniedInvalid}
	default:
		// The reviewed target MOVED — a different fingerprint, or a different pinned server
		// identity. Whole-Canary breach, latched against G inside this same transaction.
		return rt.latchDriftLocked(cr, capb, string(v), gen, now)
	}

	// (6) Untrusted without drift is request-scoped: the target still matches what was reviewed,
	// this request simply is not authorized (expired, revoked, never granted). Nothing is latched
	// and nothing is persisted.
	if !obs.Trusted {
		return canaryAdmission{Denial: canaryAdmitUntrusted, Active: true, Generation: gen, Outcome: canary.BudgetDeniedInvalid}
	}

	// (7) Budget, under the same generation the trust verdict was computed against.
	outcome := rt.reserveLocked(cr, capb, gen, now, ident)
	denial := canaryAdmitGranted
	if !outcome.Granted() {
		denial = canaryAdmitBudget
	}
	return canaryAdmission{
		Denial: denial, Active: true, Generation: gen, Trusted: true, Outcome: outcome,
		Latched: !cr.aborter.ExecutionEligible(gen),
	}
}

// latchDriftLocked latches an authoritative drift against gen and returns the denial, with cr.mu
// ALREADY HELD. It exists so every drift exit from the transaction is the same exit: one latch
// site, one shape of result, no path that denies a drifted request without latching it.
func (rt *canaryRuntime) latchDriftLocked(cr *canaryCapRuntime, capb rollout.Capability, code string, gen uint64, now time.Time) canaryAdmission {
	res := rt.tripLockedForGeneration(cr, capb, code, gen, now)
	return canaryAdmission{
		Denial: canaryAdmitDrift, Active: true, Generation: gen, DriftCode: code,
		Outcome: canary.BudgetDeniedInvalid,
		Latched: res == canary.TripCanaryLatched,
	}
}

// tripLockedForGeneration latches a whole-Canary abort for gen with cr.mu ALREADY HELD.
//
// It is the locked core tripCanaryAbortForGeneration wraps, extracted so the admission transaction
// can latch inside its own critical section instead of releasing and re-acquiring — which is the
// window every previous iteration of this fix left open. The persist-failure handling is the
// existing fail-closed one: a latch that did not reach disk has its durable record removed, so a
// restart cannot revive the pre-abort activation.
func (rt *canaryRuntime) tripLockedForGeneration(cr *canaryCapRuntime, capb rollout.Capability, code string, gen uint64, now time.Time) canary.TripResult {
	if !cr.active || cr.aborter == nil || cr.generation != gen {
		return canary.TripCanaryLatched
	}
	res := cr.aborter.Trip(code, cr.generation, now)
	if res == canary.TripCanaryLatched {
		if err := canaryRuntimePersist(rt, capb, cr); err != nil {
			_ = rt.removeRuntimeStateAfterSafetyPersistFailure(capb, "abort", err) // in-memory already latched; residual risk is logged
		}
	}
	return res
}

// ── Pre-admission drift evidence ─────────────────────────────────────────────
//
// The runtime pipeline refuses a decision whose tool drifted before the executor is reached. That
// refusal is fail-closed and unchanged; what it must NOT do is latch the whole-Canary abort,
// because no reservation exists yet and therefore nothing binds the observation to an activation.
//
// The observation is still worth having — an operator seeing refusals wants to know the catalog
// moved under a decision — so it is counted here, by bounded reason code, and surfaced read-only.
// It is deliberately a COUNTER and not a control input: nothing reads it to make a decision.
var mcpCanaryPreAdmissionDrift = struct {
	mu sync.Mutex
	m  map[string]map[string]uint64
}{m: map[string]map[string]uint64{}}

// canaryPreAdmissionDriftCodes bounds the key space to the taxonomy's drift codes, so a caller can
// never grow the map with arbitrary strings.
var canaryPreAdmissionDriftCodes = map[string]struct{}{
	"tool_fingerprint_drift": {},
	"server_identity_drift":  {},
}

// noteCanaryPreAdmissionDrift records one pre-admission drift observation. Unrecognised codes are
// folded into a single bucket rather than admitted as new keys.
func noteCanaryPreAdmissionDrift(capability, code string) {
	if _, ok := canaryPreAdmissionDriftCodes[code]; !ok {
		code = "other"
	}
	mcpCanaryPreAdmissionDrift.mu.Lock()
	defer mcpCanaryPreAdmissionDrift.mu.Unlock()
	byCode := mcpCanaryPreAdmissionDrift.m[capability]
	if byCode == nil {
		byCode = map[string]uint64{}
		mcpCanaryPreAdmissionDrift.m[capability] = byCode
	}
	byCode[code]++
}

// canaryPreAdmissionDriftCounts returns a copy of one capability's bounded evidence counters,
// keyed by drift code. This is the READ half of the counter and it is not optional: a counter
// nothing can read is not evidence, it is dead state that only looks like observability (the
// write-only-latch class this repository has been bitten by before — see the sslInspectionLoadError
// note in CLAUDE.md). It is surfaced under GET /api/mcp/rollout and read by nothing else; no
// control path consults it.
func canaryPreAdmissionDriftCounts(capability string) map[string]uint64 {
	mcpCanaryPreAdmissionDrift.mu.Lock()
	defer mcpCanaryPreAdmissionDrift.mu.Unlock()
	byCode := mcpCanaryPreAdmissionDrift.m[capability]
	out := make(map[string]uint64, len(byCode))
	for k, v := range byCode {
		out[k] = v
	}
	return out
}

// ── Pre-executor drift: the activation-bound latch ───────────────────────────

// canaryDriftLatch is the bounded result of a pre-executor drift latch attempt. Every field is a
// fact established INSIDE the activation critical section.
type canaryDriftLatch struct {
	// Active reports whether an activation owned this evaluation at all. False is the §6
	// publication gap: nothing was latched and no future activation can inherit the observation.
	Active bool
	// Generation is the exact non-zero generation the re-derivation ran under. Zero iff !Active.
	Generation uint64
	// DriftCode is the drift RE-DERIVED under the lock — not the caller's earlier observation.
	// Empty means the drift did not reproduce against live state, so nothing is latched.
	DriftCode string
	Latched   bool
}

// latchDriftUnderActivation takes the whole-Canary latch for an authoritative drift observed BEFORE
// the executor was reached.
//
// The caller's observation is NOT the input to the decision. The caller saw drift outside any
// critical section, so its verdict is unattributable by construction — the exact defect five review
// rounds were spent on. What this does instead is re-run the trust probe against LIVE state inside
// the activation lock, so the drift that decides the latch and the generation it is charged to are
// established together, atomically, and the §2 invariant holds for the same reason it holds in
// admitLiveExecution: G is verified active before the probe runs, the lock is held for the
// complete probe, and the trip is taken against that same G without ever releasing it.
//
// It never reserves budget and never admits anything — the request is already refused, fail-closed,
// by the caller. Its only effect is to stop the experiment that owns the drift.
//
// §5 applies unchanged: the probe passed here must be local control-plane state only.
func (rt *canaryRuntime) latchDriftUnderActivation(capb rollout.Capability, wantGen uint64, now time.Time, trust canaryTrustProbe) canaryDriftLatch {
	if wantGen == 0 {
		// §7. An observation that names no activation latches nothing, and 0 is NEVER read as
		// "whatever is current" — that wildcard is exactly how an earlier revision inverted its
		// own fix into the defect it was closing.
		return canaryDriftLatch{}
	}
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.aborter == nil || cr.generation == 0 {
		// §6 THE PUBLICATION GAP. ModeCanary with no live activation is not an activation, and an
		// observation made in that interval must never latch one created later. It stays evidence.
		return canaryDriftLatch{}
	}
	if cr.generation != wantGen {
		// THE ACTIVATION MOVED UNDER THIS OBSERVATION. The request's scope decision was made
		// against wantGen; the activation now in force is a different experiment whose scope may
		// exclude this target entirely, so latching it would stop an unrelated Canary for
		// something outside its blast radius (Codex round 22 — the round-15 lesson from the other
		// side). Generations are strictly monotonic and never reused, so this comparison against a
		// value captured before the resolution is a real statement about the window, not a
		// counter-equality argument: a mismatch means an activation intervened.
		//
		// Skipping is the safe direction. If the target IS in the new activation's scope, that
		// activation's own requests observe the same drift and latch it there.
		return canaryDriftLatch{Active: true, Generation: cr.generation}
	}
	gen := cr.generation
	code := ""
	if trust != nil {
		code = trust().DriftCode
	}
	if code == "" {
		// The drift did not reproduce against live state under the lock. It may have been repaired,
		// or it may never have belonged to this activation. Either way there is no authoritative
		// breach to charge, and inventing one would stop a healthy experiment.
		return canaryDriftLatch{Active: true, Generation: gen}
	}
	res := rt.tripLockedForGeneration(cr, capb, code, gen, now)
	return canaryDriftLatch{
		Active: true, Generation: gen, DriftCode: code,
		Latched: res == canary.TripCanaryLatched,
	}
}

// canaryPreAdmissionDrift is the composition-root sink for an authoritative drift the runtime
// pipeline observed BEFORE the executor was reached. It does two separable things, in this order:
//
//  1. counts the observation as bounded evidence, unconditionally — an operator learns the catalog
//     moved under a decision even when there is no activation to stop; and
//  2. attempts the whole-Canary latch by RE-DERIVING the drift live inside the activation critical
//     section, so the breach and the generation it is charged to are established atomically.
//
// The runtime's own verdict is deliberately not trusted as the latch input. It was computed outside
// any critical section, so it cannot be attributed to a generation; only the value re-derived under
// the lock can be. When no activation is live, step 2 latches nothing at all (§6).
func canaryPreAdmissionDrift(capability string, obs mcpruntime.CanaryDriftTarget) {
	noteCanaryPreAdmissionDrift(capability, obs.Code)

	capb, err := rollout.ParseCapability(capability)
	if err != nil {
		// Fail closed: an unrecognised capability names no activation, so there is nothing to
		// latch. The evidence above is already recorded.
		return
	}
	now := time.Now()
	globalCanaryRuntime.latchDriftUnderActivation(capb, obs.Generation, now, func() canaryTrustObservation {
		// DRIFT-ONLY. The latch's sole output is a drift code, so consulting the approval store
		// here would be work whose answer is discarded — and it would drag the durable store into
		// the activation critical section for nothing (Codex round 22). The precheck reads only
		// pointer-published inventory.
		live := mcpLiveTrustPrecheck(obs.Tenant, obs.ServerID, obs.ToolName, obs.DecisionFP)
		return canaryTrustObservation{DriftCode: live.DriftCode}
	})
}

// canaryGenerationForCapability is the Deps.CanaryGeneration seam: the activation generation
// currently in force for a capability, or 0 for an unrecognised capability or a dormant runtime.
// Its only consumer is the pre-executor drift latch, where it NARROWS which activation an
// observation may stop — see Deps.CanaryGeneration for why that is not the attribution proof
// earlier revisions wrongly tried to build from a generation read.
func canaryGenerationForCapability(capability string) uint64 {
	capb, err := rollout.ParseCapability(capability)
	if err != nil {
		return 0
	}
	return globalCanaryRuntime.currentGeneration(capb)
}
