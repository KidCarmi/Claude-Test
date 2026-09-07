package main

import (
	"sync"
	"time"

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
// the order it establishes is load-bearing and was verified against the tree, not assumed:
//
//	cr.mu ─→ mcpInventory.mu     (RLock; returns two pointers immediately)
//	      ─→ mcpToolTrust.mu     (RLock; returns the store pointer immediately)
//	      ─→ tooltrust.Store.mu  (in-memory map walk + clone + sort)
//
//	catalog.Current() / registry.Current() are atomic.Pointer loads and take NO lock.
//
// Two facts make that order safe rather than merely plausible. (1) NOTHING reachable from the trust
// probe references canaryRuntime — tooltrust, inventory, catalog, registry and internal/mcp/canary
// contain no path back — so the edge cannot close into a cycle. (2) cr.mu previously reached NONE
// of those packages, so this introduces the FIRST edge between them and it is one-way by
// construction. A future change that makes any of those packages call into canaryRuntime creates
// the cycle; TestAdmission_TrustProbeMayNotReEnterTheRuntime pins that it does not today.
//
// The probe also performs no network I/O, no credential materialization, no DNS and no upstream
// call — mcpLiveTrustRevalidate documents the credential rule itself, and ActiveLiveApprovals is a
// read-only in-memory walk. The durable persist that happens under this lock is the SAME
// persistLocked every other canary-runtime mutation already performs under it; this change does
// not add I/O to the critical section, it adds a local-state predicate.

// canaryTrustProbe is the live-trust predicate evaluated INSIDE the activation critical section.
//
// It is deliberately a nullary closure: the caller binds the request's (tenant, server, tool,
// fingerprint) when it builds the probe, so the runtime never learns request shape and the trust
// layering stays where it is. The contract on any implementation is narrow and is the reason the
// lock can be held across it — LOCAL CONTROL-PLANE STATE ONLY. No network I/O, no credential
// materialization, no DNS, no upstream call, no unbounded or blocking work.
type canaryTrustProbe func() (trusted bool, driftCode string)

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

	// (3) Live trust, under the lock, against the activation captured above.
	trusted, driftCode := false, ""
	if trust != nil {
		trusted, driftCode = trust()
	}

	// (4) An authoritative drift is a whole-Canary breach: latch it against G, durably, fail-closed.
	if driftCode != "" {
		res := rt.tripLockedForGeneration(cr, capb, driftCode, gen, now)
		return canaryAdmission{
			Denial: canaryAdmitDrift, Active: true, Generation: gen, DriftCode: driftCode,
			Outcome: canary.BudgetDeniedInvalid,
			Latched: res == canary.TripCanaryLatched,
		}
	}

	// (5) Untrusted without drift is request-scoped: the target still matches what was reviewed,
	// this request simply is not authorized. Nothing is latched and nothing is persisted.
	if !trusted {
		return canaryAdmission{Denial: canaryAdmitUntrusted, Active: true, Generation: gen, Outcome: canary.BudgetDeniedInvalid}
	}

	// (6) Budget, under the same generation the trust verdict was computed against.
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
