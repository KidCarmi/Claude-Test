package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mcpLiveSideEffectGate is the composition-layer implementation of execution.LiveExecutionGate.
// It runs the three gates that must live OUTSIDE the execution package — at the side-effect
// boundary, immediately before the executor's own tool-freshness + emergency-kill re-check:
//
//	(1) LIFECYCLE admission — reject a new live execution once quiesce has started (§6). This is
//	    FIRST so a quiescing tier never even reaches the budget/trust work.
//	(2) READ-FIRST (§9) — only OpRead/OpDiscovery may cross the boundary, decided from Culvert's
//	    own operation class, never the server-provided readOnlyHint.
//	(3) RUNTIME LIVE-TRUST revalidation (§10) — an active, unexpired live_execution approval must
//	    bind the EXACT current (tenant, server, tool, fingerprint) at THIS instant. A preflight
//	    approval that was revoked/expired, or a tool that drifted, fails closed here even though
//	    the transition preflight passed. No shadow-approval fallback.
//	(4) BUDGET reservation (§8) — the Canary blast-radius budget must grant a slot for this
//	    execution identity. A denied budget means Upstream.Call == 0. The reservation persists the
//	    spend BEFORE the grant, so a restart never replays it.
//
// Every seam is an injectable func so the deterministic race/mutation tests drive the exact
// admission logic with controlled inputs; the production constructor wires the real singletons.
// The gate performs NO upstream call and NO credential materialization.
type mcpLiveSideEffectGate struct {
	capb rollout.Capability

	// admit is the lifecycle admission (globalMCPLiveTier.admitExecution): returns a release and
	// ok==true only while armed and not quiescing.
	admit func() (release func(), ok bool)
	// readFirst decides whether the operation class may cross the boundary.
	readFirst func(policy.OperationClass) bool
	// trustPrecheck is the LOCK-FREE half of live-execution trust revalidation, bound to the
	// DECISION's fingerprint (the fingerprint the request was actually decided against). It is the
	// only half that can report a whole-Canary DRIFT code, and it reads only pointer-published
	// inventory state — which is what makes it legal to run inside the activation critical section
	// (§5). It is called TWICE per admission by design: once before the lock to decide whether the
	// approval lookup is worth doing, and once INSIDE the lock, where its verdict is the one the
	// latch is actually charged to.
	trustPrecheck func(tenant, serverID, toolName, fingerprint string) liveTrustPrecheck
	// approvalOK is the BLOCKING half: it consults the durable approval store, so it runs OUTSIDE
	// the activation lock. It can only ever produce a request-scoped verdict — it never reports
	// drift and never latches anything, which is exactly why it does not need to be attributed to
	// an activation generation.
	approvalOK func(tgt canary.LiveTarget, now time.Time) (satisfied bool, driftCode string)
	// admitUnderActivation is THE atomic activation-bound admission transaction: it verifies an
	// armed activation, captures its exact generation, evaluates the trust probe, latches an
	// authoritative drift against that generation, and reserves the budget — all under one
	// acquisition of the activation lock, which it owns and never exposes.
	//
	// It replaces the reserve / tripBreach / currentGeneration trio this gate used to sequence
	// itself. That composition was the defect: no ordering of unlocked reads can establish that the
	// generation being latched was continuously active across the trust observation, and Codex
	// rounds 15-19 produced a P1 against every arrangement of them.
	admitUnderActivation func(now time.Time, ident canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission
	// releaseBudget returns the in-flight concurrency slot for a reservation made under gen.
	releaseBudget func(gen uint64)
	// generationCurrent is the final-boundary revalidation: it reports whether the activation
	// generation a reservation was made under is STILL the current, armed, execution-eligible
	// generation. A concurrent Canary demotion between admission and the upstream call makes it
	// return false so the executor refuses at the boundary (§10 completeness; Codex P1 round-8).
	generationCurrent func(gen uint64) bool
	// note records a bounded denial reason for metrics/telemetry (never a secret). Optional.
	note func(reason mcperr.Reason)
}

var _ execution.LiveExecutionGate = (*mcpLiveSideEffectGate)(nil)

// newMCPLiveSideEffectGate wires the production gate for the Gateway capability from the real
// composition-layer singletons.
func newMCPLiveSideEffectGate(capb rollout.Capability) *mcpLiveSideEffectGate {
	lt := mcpLiveTierFor(capb)
	return &mcpLiveSideEffectGate{
		capb:          capb,
		admit:         lt.admitExecution,
		readFirst:     canary.IsReadFirstOperation,
		trustPrecheck: mcpLiveTrustPrecheck,
		approvalOK:    mcpLiveApprovalSatisfied,
		admitUnderActivation: func(now time.Time, ident canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission {
			return globalCanaryRuntime.admitLiveExecution(capb, now, ident, trust)
		},
		releaseBudget:     func(gen uint64) { globalCanaryRuntime.releaseCanaryExecution(capb, gen) },
		generationCurrent: func(gen uint64) bool { return globalCanaryRuntime.generationActive(capb, gen) },
		note:              noteMCPLiveGateDenied,
	}
}

// AdmitSideEffect implements execution.LiveExecutionGate. It runs the four gates in order and
// fails closed on any of them, releasing every slot it acquired along the way, so a denial can
// never leak a lifecycle in-flight count or a budget concurrency slot.
func (g *mcpLiveSideEffectGate) AdmitSideEffect(in execution.LiveGateInput) execution.LiveGateDecision {
	deny := func(reason mcperr.Reason) execution.LiveGateDecision {
		if g.note != nil {
			g.note(reason)
		}
		return execution.LiveGateDecision{Admit: false, Reason: reason}
	}

	// (1) Lifecycle admission — rejects a new execution during quiesce/unarmed (§6).
	releaseAdmit, ok := g.admit()
	if !ok {
		return deny(mcperr.ReasonRolloutModeInvalid)
	}

	// (2) Read-first (§9).
	if !g.readFirst(in.Operation) {
		releaseAdmit()
		return deny(mcperr.ReasonRolloutOutOfScope)
	}

	// (3+4) ATOMIC activation-bound trust revalidation, drift latch and budget reservation.
	//
	// These were three steps this gate sequenced itself, reading the activation generation around
	// them. That is the shape Codex rounds 15-19 defeated five times: no arrangement of unlocked
	// reads proves the generation being latched was continuously active across the trust
	// observation, and counter equality proves only that the value did not change — not that it was
	// ever live (the rollout publication gap, §6). They are now ONE transaction that owns the
	// activation lock for its whole duration and hands back facts.
	//
	// The gate does not manage activation locking and never sees the mutex. The probe it supplies
	// is local control-plane state only — no network I/O, no credential materialization, no DNS, no
	// upstream call — which is what makes holding the lock across it legitimate (§5).
	//
	// EVERY PART OF TRUST IS EVALUATED INSIDE THE TRANSACTION, INCLUDING THE APPROVAL.
	//
	// An earlier revision hoisted the approval lookup out of the lock to keep the durable
	// approval store's mutex off the critical section (§5). That was a real hazard, but hoisting
	// was the wrong fix and it bought a worse one: a request that read approved=true and then
	// waited for cr.mu could be admitted after the approval was REVOKED in that window, and
	// nothing downstream would catch it — the final boundary re-reads tool freshness, generation
	// and kill state, not approval status. Revoking a LIVE approval does not disturb the
	// fingerprint or eligibility either, because catalog promotion is derived from SHADOW-purpose
	// approvals (rederiveTool), so the in-lock precheck would still report Eligible. A stale
	// yes would have authorized an irreversible call (Codex round 22).
	//
	// The store read is now LOCK-FREE at the source (tooltrust publishes a copy-on-write snapshot
	// through an atomic pointer), so the §5 hazard is removed rather than relocated, and the
	// admission transaction can evaluate the whole predicate under one lock exactly as it did
	// before the split.
	adm := g.admitUnderActivation(in.Now, canary.ExecutionIdentity{
		Principal: in.Principal,
		Tool:      in.ToolName,
		Server:    in.ServerID,
	}, func() (bool, string) {
		live := g.trustPrecheck(in.Tenant, in.ServerID, in.ToolName, in.Fingerprint)
		if live.DriftCode != "" {
			return false, live.DriftCode
		}
		if !live.Eligible {
			return false, ""
		}
		return g.approvalOK(live.Target, in.Now)
	})
	// The denial class is read from an EXPLICIT field, never inferred from which other field is
	// zero: an already-aborted Canary and an untrusted request both leave Trusted false, and
	// inferring from that reported a stopped experiment to the client as a trust failure.
	switch adm.Denial {
	case canaryAdmitNoActivation:
		// No activation owned this transaction — the rollout publication gap, a demotion, or an
		// unarmed runtime. Admission fails CLOSED, and because there was no generation to attribute
		// to, NOTHING was latched: a drift seen here can never stop an activation created later (§6).
		releaseAdmit()
		return deny(mcperr.ReasonRolloutModeInvalid)
	case canaryAdmitDrift:
		// AUTHORITATIVE DRIFT (blocker #7 §17). The reviewed tool/server is no longer the one the
		// approval was granted against — proof the experiment's premise no longer holds, so the
		// request fails closed AND the whole Canary latches. The latch already happened INSIDE the
		// transaction, against the exact generation the probe ran under.
		releaseAdmit()
		return deny(mcperr.ReasonLiveTrustRevalidationFailed)
	case canaryAdmitUntrusted:
		releaseAdmit()
		return deny(mcperr.ReasonLiveTrustRevalidationFailed)
	case canaryAdmitAborted, canaryAdmitBudget:
		releaseAdmit()
		return deny(mcperr.ReasonRolloutBudgetExhausted)
	}
	gen := adm.Generation

	// Admitted. Revalidate is the final-boundary re-check the executor runs right before the kill
	// re-read: it fails closed if the generation this reservation was made under is no longer current
	// (a concurrent demotion), so an already-admitted request cannot cross the boundary after a
	// leaving-live transition returned (Codex P1 round-8). The release runs exactly once after the
	// upstream leg (executor defers it), and returns BOTH the budget concurrency slot and the lifecycle
	// in-flight count — including the §11 case where a later kill/freshness/demotion abort occurs after
	// this admit.
	// Reservation identity (review §5/§6). The budget enforcer meters COUNTS, not
	// identities, so the grant itself carries no name. Minting one here — at the
	// single admission point, after the slot is actually granted — binds each
	// physical attempt to the exact slot that paid for it, so an effect can never be
	// attributed to an unauthorized reservation and an orphan can be traced back to
	// its grant. Failing to mint fails CLOSED: an unnameable reservation must not be
	// allowed to authorize an unattributable side effect.
	resID, rerr := newCanaryReservationID()
	if rerr != nil {
		g.releaseBudget(gen)
		releaseAdmit()
		return deny(mcperr.ReasonEventEvidenceMissing)
	}

	return execution.LiveGateDecision{
		Admit:                true,
		ReservationID:        resID,
		ActivationGeneration: gen,
		Revalidate: func() bool {
			if g.generationCurrent == nil {
				return true // no revalidation seam wired ⇒ preserve prior behavior (never falsely refuse)
			}
			return g.generationCurrent(gen)
		},
		Release: func() {
			g.releaseBudget(gen)
			releaseAdmit()
		},
	}
}

// liveTrustPrecheck is the LOCK-FREE half of live-execution trust revalidation: everything that can
// produce an authoritative whole-Canary DRIFT verdict, and nothing that can block.
type liveTrustPrecheck struct {
	// DriftCode is non-empty only for an AUTHORITATIVE drift — the whole-Canary breach codes.
	DriftCode string
	// Eligible reports that the target is present, is this tenant's, is usable, and still carries
	// the decision's fingerprint. False with an empty DriftCode is a request-scoped denial.
	Eligible bool
	Target   canary.LiveTarget
}

// mcpLiveTrustPrecheck decides everything the whole-Canary latch depends on, reading ONLY
// pointer-published inventory state.
//
// WHY THIS IS SPLIT OUT, and it is a safety property rather than a tidiness one. The activation
// critical section latches aborts and gates demotion, so anything that can BLOCK inside it can
// block the controls that stop the experiment. The approval lookup can: Store.ActiveLiveApprovals
// takes Store.mu, and every approval mutation holds that same mutex across persistLocked and its
// atomic file write — so one stuck disk would sit in front of automatic abort, demotion and
// generation revalidation (Codex round 21). §5 forbids exactly that, and an audited lock ORDER
// would not have helped: the hazard is duration, not deadlock.
//
// The separation is clean because of what each half decides. Every authoritative drift signal —
// the server no longer usable, the fingerprint no longer the decision's — is derived from the
// inventory, which is published through atomic pointers (catalog.Current / registry.Current) behind
// one RLock that returns immediately. The approval lookup NEVER produces a drift code; it only
// distinguishes an authorized request from an unauthorized one, which is request-scoped and needs
// no activation attribution at all. So the latch keeps its atomic binding while the blocking read
// moves out of the critical section entirely — removing the edge rather than ordering it.
func mcpLiveTrustPrecheck(tenant, serverID, toolName, decisionFP string) liveTrustPrecheck {
	if mcpToolTrust == nil {
		return liveTrustPrecheck{}
	}
	ti := mcpToolTrust.loadTarget(serverID, toolName)
	if !ti.found || ti.target.Tenant == "" || ti.target.Tenant != tenant {
		// Request-scoped: this request names a target that is not this tenant's reviewed one. A
		// Canary that correctly refuses such a request is a Canary working, not a breach.
		return liveTrustPrecheck{}
	}
	// The reviewed server must still be usable at the boundary (P1b): an operator disable or a lost
	// identity verification after runExecute snapshotted in.Server fails closed here.
	//
	// WHOLE-CANARY. This one signal conflates two causes — an operator disabling the server and the
	// server losing identity verification — and they are not separable from the data available
	// here (a distinguishable peer-freshness source is blocker #11). The conservative reading is
	// taken deliberately: in BOTH cases the trust anchor the experiment was authorized against is
	// no longer the one in force, and the safe response to "the approved anchor is gone" is to stop
	// changing reality, not to keep going because one of the two possible causes was benign.
	if !ti.target.ServerUsable {
		return liveTrustPrecheck{DriftCode: "server_identity_drift"}
	}
	// Bind trust to the DECISION's fingerprint, not merely whichever fingerprint is current (P1a): the
	// current target must STILL equal the fingerprint this request was decided against, so an
	// F1→F2→F1 flap cannot let an F2 approval authorize an F1 request.
	//
	// WHOLE-CANARY when a fingerprint EXISTS and differs: that is the rug-pull the taxonomy names —
	// the executed tool is not the reviewed tool. A MISSING decision fingerprint is request-scoped:
	// it means this request never carried one, which is a malformed request, not evidence the
	// target changed.
	if decisionFP == "" {
		return liveTrustPrecheck{}
	}
	if hex.EncodeToString(ti.target.Fingerprint[:]) != decisionFP {
		return liveTrustPrecheck{DriftCode: "tool_fingerprint_drift"}
	}
	return liveTrustPrecheck{
		Eligible: true,
		Target: canary.LiveTarget{
			Tenant:            tenant,
			ServerID:          serverID,
			ToolName:          toolName,
			Fingerprint:       ti.target.Fingerprint,
			FingerprintFormat: ti.target.FingerprintFormatVersion,
		},
	}
}

// mcpLiveApprovalSatisfied answers the APPROVAL half of live-execution trust, and reports the one
// condition in it that is an authoritative whole-Canary drift rather than an ordinary denial.
//
// WHY THE DRIFT VERDICT LIVES HERE. A rug-pull landing before a request's policy resolution is
// refused upstream of this gate, and every request AFTER it resolves cleanly against the NEW
// fingerprint — so the comparison in mcpLiveTrustPrecheck sees F2 == F2, reports no drift, and the
// request is denied merely for lacking an approval. Read that way an authoritative breach is
// indistinguishable from ordinary unauthorized traffic and stops nothing (Codex rounds 20 and 23).
//
// The evidence is right here, though: an approval that is ACTIVE, live-purpose and valid in every
// respect EXCEPT that it pins a different fingerprint for this exact (tenant, server, tool) is
// precisely the taxonomy's rug-pull — the executed tool is not the reviewed tool. Detecting it at
// this point puts the whole-Canary latch inside the ATOMIC admission transaction, which already
// owns the activation lock and charges an exact generation. It is activation-bound BY
// CONSTRUCTION, needing no generation carried from elsewhere, no scope lookup, and no argument
// about which activation an observation belongs to.
//
// Anything else — no approval at all, expired, revoked, wrong tenant, never granted — stays
// REQUEST-SCOPED: a Canary correctly refusing an unauthorized request is a Canary working.
//
// The store read is LOCK-FREE (tooltrust publishes a copy-on-write snapshot through an atomic
// pointer), which is what makes it legal inside the critical section at all — see §5.
func mcpLiveApprovalSatisfied(tgt canary.LiveTarget, now time.Time) (satisfied bool, driftCode string) {
	if mcpToolTrust == nil {
		return false, ""
	}
	reviewedElsewhere := false
	for _, a := range mcpToolTrust.activeLiveApprovals(now) {
		if canary.SatisfiesLiveExecution(a, tgt, now) == canary.TrustOK {
			return true, ""
		}
		// Same reviewed tool, DIFFERENT reviewed fingerprint. Evaluated over the same approval set
		// at the same instant as the branch above, so it can never contradict it.
		if a.Tenant == tgt.Tenant && a.ServerID == tgt.ServerID && a.ToolName == tgt.ToolName &&
			a.Fingerprint != tgt.Fingerprint {
			reviewedElsewhere = true
		}
	}
	if reviewedElsewhere {
		return false, "tool_fingerprint_drift"
	}
	// No satisfying approval and nothing saying the reviewed target moved: request-scoped. This
	// request simply is not authorized (expired, revoked, never granted).
	return false, ""
}

// mcpLiveGateDenials counts live side-effect gate denials by bounded reason code, for the
// read-only status/metrics surface (§14 evidence truth: budget vs trust vs read-first vs
// quiescing are separately countable). It is process-global, never a secret.
var mcpLiveGateDenials = struct {
	mu sync.Mutex
	m  map[string]uint64
}{m: map[string]uint64{}}

// noteMCPLiveGateDenied increments the denial counter for a bounded reason code.
func noteMCPLiveGateDenied(reason mcperr.Reason) {
	mcpLiveGateDenials.mu.Lock()
	mcpLiveGateDenials.m[reason.Code()]++
	mcpLiveGateDenials.mu.Unlock()
}

// mcpLiveGateDenialSnapshot returns a copy of the denial counters for the status surface.
func mcpLiveGateDenialSnapshot() map[string]uint64 {
	mcpLiveGateDenials.mu.Lock()
	defer mcpLiveGateDenials.mu.Unlock()
	out := make(map[string]uint64, len(mcpLiveGateDenials.m))
	for k, v := range mcpLiveGateDenials.m {
		out[k] = v
	}
	return out
}

// canaryReservationIDBytes is the entropy width for a reservation identity: 128
// bits, matching the attempt identity, so neither is the weaker link when the two
// are correlated in evidence.
const canaryReservationIDBytes = 16

// newCanaryReservationID mints the identity for one granted budget slot. It is
// non-secret (it appears in evidence and is reconciled against), Culvert-minted,
// and never derived from request content — deriving it from caller input would let
// two distinct grants share one name and collapse them in the ledger.
func newCanaryReservationID() (string, error) {
	b := make([]byte, canaryReservationIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "rsv_" + hex.EncodeToString(b), nil
}
