package main

import (
	"sync"
	"time"

	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
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

// canaryScopeProbe reports the content hash of the rollout scope CURRENTLY in force for this
// capability. Like canaryTrustProbe it is evaluated INSIDE the activation lock, and the same
// narrow contract makes that legitimate: one lock-free atomic load of local control-plane state
// — no network I/O, no credential materialization, no blocking work.
//
// It is a probe rather than a value because the comparison has to happen at the moment budget
// authority is decided. A hash read before the lock is a hash that may already be stale by the
// time it matters, which is the defect class this whole boundary exists to close.
type canaryScopeProbe func() string

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
	// AnchorLost reports that the trust anchor the experiment was authorized against is no longer
	// in force — the server is not usable, or the registry pins an identity the catalog record was
	// not built against. It is carried as a FACT rather than pre-classified as a drift code because
	// whether it may stop THIS activation depends on the reviewed set, which only the transaction
	// can consult (see canaryDriftCause).
	AnchorLost bool
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
	// canaryAdmitClassNotInForce — request-scoped: the operation class this request was decided
	// under is not the class the activation that will be charged binds to this target.
	canaryAdmitClassNotInForce
	// canaryAdmitScopeNotInForce — request-scoped: the authorization envelope this request
	// resolved under is not the one in force now. STALE AUTHORIZATION, never target drift.
	canaryAdmitScopeNotInForce
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
//	class in force under G         — the classification the request carries is still the one G binds
//	scope in force                 — the authorization envelope it resolved under is still installed
//	untrusted ⇒ deny               — request-scoped; nothing is latched and nothing persisted
//	reserve(G) + persist           — only a trusted request spends budget
//
// Trust is checked BEFORE the reservation so an untrusted request never consumes blast radius,
// preserving the gate's prior ordering. The reservation can therefore only ever be made under the
// SAME generation the trust verdict was computed against: "trust under G, reserve under G+1" is not
// a race that is unlikely here, it is a state the code cannot express.
func (rt *canaryRuntime) admitLiveExecution(capb rollout.Capability, now time.Time, opClass policy.OperationClass, resolvedScope string, scopeNow canaryScopeProbe, ident canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission {
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

	// (4) THE ONE ORDERING RULE. Scope decides whether this activation may be stopped at all;
	// anchor state and the probe decide which cause is recorded. Shared with every other latch
	// path so one published state cannot produce two different causes (canaryDriftCause).
	if code := canaryDriftCause(cr.reviewed, obs); code != "" {
		return rt.latchDriftLocked(cr, capb, code, gen, now)
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
	// Every breach is already latched above, so the only remaining distinction is request-scoped:
	// a target outside this activation's review is refused without stopping anything. That covers
	// the anchor-lost case too — an unreviewed target whose server is disabled is still refused
	// here, it simply does not stop an experiment that never depended on it.
	if cr.reviewed.Compare(obs.Current) == canary.ReviewedOutOfScope {
		return canaryAdmission{Denial: canaryAdmitNotReviewed, Active: true, Generation: gen, Outcome: canary.BudgetDeniedInvalid}
	}

	// (5b) THE CLASS THE REQUEST CARRIES MUST BE THE CLASS THIS ACTIVATION BINDS (blocker #4).
	//
	// The operation class is decided once, at policy time, from the activation armed AT THAT
	// INSTANT — which is what makes the policy engine, the activation gate and the live gate read
	// one value instead of three. But "decided once" is a statement about how many times it is
	// COMPUTED, not about how long it stays true, and the request that carries it is charged to
	// whatever activation is current HERE.
	//
	// So this sequence was admissible and must not be (Codex P1, PR #1370):
	//
	//	T0     G1 is armed, reviewed read-only for tool X at F1. A request is decided: OpRead.
	//	T+     the request pauses — a credential path, a durable commit, a scheduler stall.
	//	T++    G1 is demoted. G2 is armed for the SAME tool at the SAME fingerprint, but its
	//	       review states MUTATING: a reviewer corrected the earlier determination.
	//	T+++   the request resumes. Gate 2 reads OpRead off its own decision and admits it; the
	//	       target identity still matches, so nothing drifts; the reservation is charged to G2.
	//
	// The call then reaches upstream under a read-first classification that the activation paying
	// for it does not make. The correction lands in the one window where it matters most.
	//
	// This is REVALIDATION, not a second classification, and the distinction is the whole reason
	// it does not violate the one-classification rule: nothing here computes a class from a
	// different set of inputs and hopes it agrees. It re-reads the SAME authority — the activation's
	// immutable reviewed record — under the lock that decides which activation is paying, and
	// requires the answer to be the one the request is relying on. It is the same discipline the
	// trust probe and the drift comparison above already follow at this boundary.
	//
	// EQUALITY, not "read is still read". Today only OpRead reaches here (gate 2 refuses every
	// other class for a tool call), so the two are the same predicate; equality is chosen because
	// it stays correct if a later phase admits a non-read class, and because it fails closed when
	// the record cannot speak for the target at all rather than treating silence as agreement.
	if current, ok := cr.reviewed.OperationClassFor(obs.Current); !ok || current != opClass {
		return canaryAdmission{Denial: canaryAdmitClassNotInForce, Active: true, Generation: gen, Outcome: canary.BudgetDeniedInvalid}
	}

	// (5c) THE AUTHORIZATION ENVELOPE MUST STILL BE THE ONE THAT AUTHORIZED THIS REQUEST.
	//
	// Sibling of (5b), and the same defect class one axis over. (5b) asks whether the CLASS the
	// request carries is still the one this activation binds; this asks whether the SCOPE the
	// request resolved under is still installed at all. Scope membership is decided once, at
	// resolution (rollout.Scope.Contains, via the executor's Resolve), and until now nothing
	// re-read it — so this sequence was admissible and must not be (Codex P1, PR #1370, round 2):
	//
	//	T0     G armed. Scope S1 permits principal A. A's request resolves executable under S1.
	//	T+     the request pauses — a credential path, a durable commit, a scheduler stall.
	//	T++    a SAME-MODE scope update installs S2: A removed, B added. The reviewed target and
	//	       the budget are unchanged, so reconcileCanaryRuntimeAfterCommit accepts it and the
	//	       generation stays G.
	//	T+++   the request resumes. The target has not moved, so nothing drifts; (5b) agrees,
	//	       because S2 binds the same target to the same class; and the budget merely COUNTS
	//	       principals, so A — already counted — passes the blast-radius ceiling too.
	//
	// The request then spends authority granted by an envelope that no longer exists.
	//
	// WHY EXACT HASH EQUALITY, and not "is the principal still in scope". Re-running membership
	// would close the principal case and leave every sibling open: a tool removed from the scope,
	// a server removed, a tenant changed, an exclusion added, a percentage or bucket-salt edit.
	// The hash covers every selector dimension at once (see rollout.Scope.computeHash), so ONE
	// comparison closes the whole family — and it fails closed on the dimensions nobody thought
	// to enumerate, which is the point. A request resolved under one authorization envelope
	// cannot spend authority under another, full stop.
	//
	// AN EMPTY RESOLVED HASH IS A REFUSAL, NOT A WILDCARD. "" is what a request carries when it
	// never went through State.ResolveFor, and an executing Canary request always does. Treating
	// it as a match would make the whole check optional for exactly the requests that skipped the
	// path that stamps it.
	//
	// AND IT IS REQUEST-SCOPED: nothing is latched. An operator narrowing a scope is the system
	// working, not evidence that the reviewed target drifted — latching the whole experiment for
	// it would let an ordinary scope edit stop a healthy Canary (the round-15/31 rule).
	if scopeNow == nil || resolvedScope == "" || scopeNow() != resolvedScope {
		return canaryAdmission{Denial: canaryAdmitScopeNotInForce, Active: true, Generation: gen, Outcome: canary.BudgetDeniedInvalid}
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

// canaryDriftCause is THE ordering rule for what stopped the experiment, shared by every latch
// path so one published state can only ever produce one recorded cause.
//
// It answers two questions in a fixed order, and the order is the whole content of rounds 3, 4, 30
// and 31:
//
//	MAY this activation be stopped for this target?   — the reviewed set decides, alone.
//	WHICH cause is recorded?                          — anchor state outranks the comparison.
//
// SCOPE FIRST, and it is a security property in the availability direction. A target the
// activation was never reviewed for must never stop it (the round-15 rule), and both paths used to
// check the anchor facts BEFORE the comparison could return ReviewedOutOfScope — so a resolvable
// tool on any disabled or repinned server aborted the whole Canary. Round 26's server-unavailable
// pipeline hook made that reachable for authenticated requests outside the rollout scope entirely,
// which means ordinary traffic to an unrelated disabled server could halt a healthy experiment
// (Codex P1, PR #1360, round 31).
//
// ANCHOR SECOND. Once the target IS this activation's concern, an anchor no longer in force
// outranks whatever the target compares as: losing the trust anchor is the stronger statement about
// what the experiment was authorized against, and it is the ordering the observation path has
// carried since round 3. A reviewed pair that changed hands still counts as reviewed here, so the
// tenant-reassignment case is inside the boundary rather than outside it.
//
// THE PROBE LAST, and only when the reviewed record has nothing to object to. Its code is derived
// from the REQUEST — the decision fingerprint against current inventory — so it can see one thing
// the activation's record cannot: that this particular request was decided against a fingerprint no
// longer in force, on a target that is otherwise exactly as reviewed.
//
// Returning "" means NO LATCH. The caller still refuses the request; refusing is request-scoped,
// stopping the experiment is not.
func canaryDriftCause(reviewed canary.ReviewedTargetSet, obs canaryTrustObservation) string {
	if !obs.Found {
		// Nothing resolved, so nothing can be attributed to the reviewed record. A transient
		// inventory gap must not stop the experiment.
		return ""
	}
	v := reviewed.Compare(obs.Current)
	switch {
	case v == canary.ReviewedOutOfScope:
		return ""
	case obs.AnchorLost:
		return "server_identity_drift"
	case canary.IsDriftVerdict(v):
		return string(v)
	default:
		// ReviewedMatches — the reviewed target is intact, so only the probe can still object.
		return obs.DriftCode
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
	"tool_fingerprint_drift":       {},
	"server_identity_drift":        {},
	"reviewed_target_tenant_drift": {},
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
		// The same rule every other latch path uses, so the two cannot disagree about one state
		// (the "two paths, same question, opposite answers" defect this file has closed twice).
		code = canaryDriftCause(cr.reviewed, trust())
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

// latchReviewedDriftUnderActivation compares the CURRENT authoritative target for one tool
// identity against the activation's immutable reviewed-target snapshot, under the activation lock,
// and latches the whole Canary when the reviewed target has moved.
//
// It exists because the reviewed comparison inside admitLiveExecution is, by itself, unreachable in
// the sequence that matters most. A Canary ScopeSpec pins the reviewed FINGERPRINT in its tool
// selector, so the moment the tool moves F1→F2 every request naming it is out of scope,
// resolveEnforcing routes it to the shadow/record-only fallback, and the admission transaction is
// never entered. The premise of the experiment has been violated and the violation is precisely
// what filters out the evidence (Codex P1, PR #1360). This path is keyed on the tool IDENTITY
// (tenant, server, tool) rather than on scope membership, so a fingerprint move cannot hide it.
//
// Everything the latch rests on is read HERE, inside the lock: the caller supplies an identity and
// a generation, never a verdict. The generation rules are the same as latchDriftUnderActivation's
// and are load-bearing for the same reasons — a zero latches nothing, the publication gap latches
// nothing, and an activation that moved under the observation latches nothing.
//
// A tool this activation was never reviewed for returns ReviewedOutOfScope and latches nothing.
// That is what makes it safe to call for EVERY request: a catalog change to an unrelated tool
// cannot stop an experiment that never reviewed it (the round-15 rule), and unlike the
// `canaryScoped` proxy that rule used to be enforced with, the reviewed set decides it exactly.
func (rt *canaryRuntime) latchReviewedDriftUnderActivation(capb rollout.Capability, wantGen uint64, now time.Time, current func() mcpAuthoritativeTarget) canaryDriftLatch {
	if wantGen == 0 {
		return canaryDriftLatch{}
	}
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.aborter == nil || cr.generation == 0 {
		return canaryDriftLatch{}
	}
	if cr.generation != wantGen {
		return canaryDriftLatch{Active: true, Generation: cr.generation}
	}
	gen := cr.generation
	if current == nil {
		return canaryDriftLatch{Active: true, Generation: gen}
	}
	obs := current()
	if !obs.Found {
		// The tool no longer resolves to an authoritative target at all. That is NOT read as drift
		// here: a tool absent from the catalog is refused per-request upstream of this point, and
		// a transient inventory gap must not stop the experiment on evidence this path cannot
		// distinguish from one. Fail-safe in the direction that costs availability, not safety.
		return canaryDriftLatch{Active: true, Generation: gen}
	}
	// An UNUSABLE server, and a registry pinning an identity the catalog record was not built
	// against, are both AFFIRMATIVE published states saying the trust anchor the experiment was
	// approved against is no longer in force — unlike "not found", which this path cannot tell
	// from a transient inventory gap. Both are carried as ONE fact into the shared ordering rule,
	// which decides scope first and cause second; see canaryDriftCause for why the order changed
	// in round 31 and why the anchor still outranks the comparison once the target is in scope.
	code := canaryDriftCause(cr.reviewed, canaryTrustObservation{
		Found:      true,
		Current:    obs.Target,
		AnchorLost: !obs.Usable || obs.RegistryPinDiverged,
	})
	if code == "" {
		return canaryDriftLatch{Active: true, Generation: gen}
	}
	res := rt.tripLockedForGeneration(cr, capb, code, gen, now)
	return canaryDriftLatch{
		Active: true, Generation: gen, DriftCode: code,
		Latched: res == canary.TripCanaryLatched,
	}
}

// canaryReviewedTargetObserved is the composition-root sink for the reviewed-target observation the
// runtime makes for every dispatched request that names a tool, whatever disposition it resolved to.
//
// It is deliberately CHEAP AND SILENT on the overwhelmingly common path: a tool outside the
// activation's reviewed set takes the activation lock once, compares, and returns. Only a reviewed
// target that has actually moved does anything, and what it does is stop the experiment.
func canaryReviewedTargetObserved(capability string, obs mcpruntime.CanaryTargetObservation) {
	capb, err := rollout.ParseCapability(capability)
	if err != nil {
		return
	}
	latch := globalCanaryRuntime.latchReviewedDriftUnderActivation(capb, obs.Generation, time.Now(),
		func() mcpAuthoritativeTarget {
			// Read inside the lock, from the same pointer-published inventory every other probe on
			// this path uses (§5: local control-plane state only, no durable store, no I/O).
			return mcpCurrentAuthoritativeTarget(obs.ServerID, obs.ToolName)
		})
	if latch.DriftCode != "" {
		// Same bounded evidence vocabulary as the pre-admission path, so an operator sees one
		// dialect for one fact however the drift was discovered.
		noteCanaryPreAdmissionDrift(capability, latch.DriftCode)
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
	capb, err := rollout.ParseCapability(capability)
	if err != nil {
		// Fail closed: an unrecognised capability names no activation, so there is nothing to
		// latch — but the observation is still evidence that the catalog moved under a decision.
		noteCanaryPreAdmissionDrift(capability, obs.Code)
		return
	}
	now := time.Now()
	latch := globalCanaryRuntime.latchDriftUnderActivation(capb, obs.Generation, now, func() canaryTrustObservation {
		// DRIFT-ONLY. The latch's sole output is a drift code, so consulting the approval store
		// here would be work whose answer is discarded — and it would drag the durable store into
		// the activation critical section for nothing (Codex round 22). The precheck reads only
		// pointer-published inventory.
		live := mcpLiveTrustPrecheck(obs.Tenant, obs.ServerID, obs.ToolName, obs.DecisionFP)
		if live.Resolved {
			// Every fact carried, none pre-classified. Trusted stays false and is never consulted
			// on this path: the request is already refused.
			return canaryTrustObservation{
				DriftCode: live.DriftCode, Found: true,
				Current: live.Authoritative, AnchorLost: live.AnchorLost,
			}
		}
		return canaryTrustObservation{DriftCode: live.DriftCode}
	})

	// COUNT WHAT WAS ACTUALLY LATCHED. The caller's observation was computed outside any critical
	// section and the re-derivation under the lock can sharpen it — an identity rotation already
	// re-ingested before an in-flight F1 decision arrives here reads as tool_fingerprint_drift to
	// the runtime and as server_identity_drift to the reviewed record. Counting the pre-lock value
	// made the admin evidence surface disagree with auto_stop about one event, which is the exact
	// shape this PR exists to close (Codex P2, PR #1360, round 31).
	//
	// When nothing was latched — no activation, a superseded generation, a drift that did not
	// reproduce, or a target this activation never reviewed — the observation is still recorded, so
	// an operator learns the catalog moved under a decision even where there is nothing to stop.
	if latch.DriftCode != "" {
		noteCanaryPreAdmissionDrift(capability, latch.DriftCode)
		return
	}
	noteCanaryPreAdmissionDrift(capability, obs.Code)
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
