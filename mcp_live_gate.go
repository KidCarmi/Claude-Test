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
	// admitOpen is the read-only form of the same question (globalMCPLiveTier.admissionOpen),
	// used as the auxiliary admission's final-boundary revalidation so a disarm or quiesce that
	// lands after admission still refuses. It takes no in-flight slot.
	admitOpen func() bool
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
		admitOpen:     lt.admissionOpen,
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
	}, func() canaryTrustObservation {
		live := g.trustPrecheck(in.Tenant, in.ServerID, in.ToolName, in.Fingerprint)
		if live.DriftCode != "" {
			return canaryTrustObservation{DriftCode: live.DriftCode}
		}
		if !live.Eligible {
			// Ineligible splits in two, and collapsing them loses a breach.
			//
			// If the (server, tool) RESOLVES — just not to this request's tenant — that is evidence
			// about the reviewed target: it may be the reviewed pair under a new owner. Report it so
			// the transaction can compare, with Trusted false so nothing is authorized by it. An
			// unrelated target simply compares out-of-scope and stays request-scoped.
			//
			// If nothing resolves at all, there is nothing to compare and a transient inventory gap
			// must not stop the experiment (Codex P1, PR #1360, round 6).
			if live.Resolved {
				return canaryTrustObservation{Found: true, Current: live.Authoritative}
			}
			return canaryTrustObservation{}
		}
		// The CURRENT authoritative target, including the pinned server identity, for the
		// transaction to compare against the activation's reviewed record. The identity read is
		// the same pointer-published inventory the precheck just used.
		cur := canary.ReviewedTarget{
			Tenant:            live.Target.Tenant,
			ServerID:          live.Target.ServerID,
			ToolName:          live.Target.ToolName,
			Fingerprint:       live.Target.Fingerprint,
			FingerprintFormat: live.Target.FingerprintFormat,
			ServerIdentity:    live.ServerIdentity,
		}
		trusted, _ := g.approvalOK(live.Target, in.Now)
		return canaryTrustObservation{Found: true, Current: cur, Trusted: trusted}
	})
	// The denial class is read from an EXPLICIT field, never inferred from which other field is
	// zero: an already-aborted Canary and an untrusted request both leave Trusted false, and
	// inferring from that reported a stopped experiment to the client as a trust failure.
	//
	// The switch is EXHAUSTIVE BY CONSTRUCTION: only canaryAdmitGranted continues to the admitted
	// path, and any denial class this gate does not recognise falls to a fail-CLOSED default. An
	// earlier shape listed the known denials and let everything else fall through to "admitted",
	// so adding a denial to the transaction silently ADMITTED the requests it was written to
	// refuse — a new refusal reason arriving as a grant is the one direction this boundary must
	// never fail in.
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
	case canaryAdmitNotReviewed:
		// The activation was never reviewed for this target. Request-scoped (nothing latched, per
		// the transaction), and reported as a trust-revalidation failure: from the caller's side
		// the target it named is not one this experiment is authorized to execute.
		releaseAdmit()
		return deny(mcperr.ReasonLiveTrustRevalidationFailed)
	case canaryAdmitAborted, canaryAdmitBudget:
		releaseAdmit()
		return deny(mcperr.ReasonRolloutBudgetExhausted)
	case canaryAdmitGranted:
		// The one class that authorizes a physical attempt. Named explicitly so
		// the default below can be what it should be.
	default:
		// FAIL CLOSED on a class this gate does not know. Reaching the admit
		// path by falling out of a switch is how a denial added to
		// canaryAdmissionDenial later would silently authorize an irreversible
		// upstream call: every existing class is handled above, so this branch
		// changes nothing today and is the whole point — the boundary must deny
		// what it cannot classify, not admit it.
		//
		// This branch and canaryAdmitNotReviewed above arrived from two sides at
		// once: main closed the fall-through generically (PR #1298) while this
		// branch hit it concretely, by adding a denial class the switch did not
		// list and watching the requests it was written to refuse be ADMITTED.
		// Both halves are kept — the new class is handled explicitly, and the
		// default still catches the next one.
		releaseAdmit()
		return deny(mcperr.ReasonRolloutModeInvalid)
	}
	if !adm.Granted() {
		// Belt-and-braces against the two halves disagreeing: Granted() is the
		// single authority on whether a physical attempt is authorized.
		releaseAdmit()
		return deny(mcperr.ReasonRolloutModeInvalid)
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

// AdmitAuxiliary implements execution.LiveExecutionGate for NON-side-effect-bearing traffic —
// MCP lifecycle (initialize / notifications/initialized / ping / notifications/cancelled) and
// discovery (tools/list). SEC-MCP-AUX-1.
//
// It runs gate (1) ONLY — the lifecycle admission. The other three are deliberately absent, and
// each absence is a decision rather than an omission:
//
//   - READ-FIRST (2) is not asked, because the operation class carried by session lifecycle
//     traffic is not the tool-call class the read-first rule was written for; asking it here is
//     the gate answering a question about a tool that does not exist.
//   - LIVE-TRUST REVALIDATION (3) is not asked for the same reason and more sharply: it binds
//     (tenant, server, TOOL, fingerprint), and auxiliary traffic has no tool binding, so the
//     production predicate refuses every time. That refusal is what made an armed Canary node
//     unable to complete a session handshake or list tools.
//   - BUDGET RESERVATION (4) is not taken, because the budget counts AUTHORIZED TOOL
//     EXECUTIONS. Spending a slot on a call that can cause no side effect makes
//     MaxTotalExecutions stop measuring physical invocations, which is exactly the accounting
//     property the physical-effect ledger exists to establish.
//
// What remains is the half that DOES apply: a tier the operator has disarmed, or has begun
// quiescing, must not open a session to a third-party upstream, read its catalog, or carry a
// materialized credential to it. That is the same fail-closed posture a restart deliberately
// leaves behind (a re-composed tier is never automatically re-armed), and it must not depend on
// which method the client happened to send.
//
// The returned Revalidate re-asks the SAME question read-only at the final boundary, so a
// disarm or quiesce landing between admission and the irreversible call still refuses; Release
// returns the lifecycle in-flight count exactly once, so a quiesce drain always completes.
// No ReservationID and no ActivationGeneration are returned: an auxiliary invocation has no
// attempt, so naming a slot it never consumed could only misattribute a physical effect.
func (g *mcpLiveSideEffectGate) AdmitAuxiliary(_ execution.LiveGateInput) execution.LiveGateDecision {
	releaseAdmit, ok := g.admit()
	if !ok {
		if g.note != nil {
			g.note(mcperr.ReasonRolloutModeInvalid)
		}
		return execution.LiveGateDecision{Admit: false, Reason: mcperr.ReasonRolloutModeInvalid}
	}
	return execution.LiveGateDecision{
		Admit: true,
		Revalidate: func() bool {
			if g.admitOpen == nil {
				return true // no revalidation seam wired ⇒ preserve the admission decision
			}
			return g.admitOpen()
		},
		Release: releaseAdmit,
	}
}

// mcpLiveTrustRevalidate is the runtime live-execution trust revalidation (§10). It resolves the
// CURRENT authoritative target for (serverID, toolName) from the tool-trust coordinator (never a
// request-supplied claim) and requires an active, unexpired live_execution approval that binds
// that EXACT (tenant, server, tool, fingerprint, format) under the full first-Canary governance
// (canary.SatisfiesLiveExecution). It is fail-closed: an uncomposed coordinator, a missing tool,
// a tenant mismatch, an unusable server, a fingerprint that no longer matches the decision, or no
// satisfying approval all deny. It NEVER consults a shadow approval (SatisfiesLiveExecution rejects
// a non-live purpose) and NEVER materializes a credential.

// liveTrustPrecheck is the LOCK-FREE half of live-execution trust revalidation: everything that can
// produce an authoritative whole-Canary DRIFT verdict, and nothing that can block.
type liveTrustPrecheck struct {
	// DriftCode is non-empty only for an AUTHORITATIVE drift — the whole-Canary breach codes.
	DriftCode string
	// Eligible reports that the target is present, is this tenant's, is usable, and still carries
	// the decision's fingerprint. False with an empty DriftCode is a request-scoped denial.
	Eligible bool
	Target   canary.LiveTarget
	// Resolved reports that the (server, tool) resolves to an authoritative target AT ALL —
	// independently of whether that target belongs to the REQUESTING tenant. Authoritative carries
	// it when true.
	//
	// The two facts are separate because conflating them loses a breach. A reviewed (server, tool)
	// reassigned from tenant A to B makes an A-request ineligible, and reporting that as "nothing
	// resolves" discards the very evidence the reviewed comparison needs: the target IS the
	// reviewed one, under a different owner. Admission would then issue a request-scoped denial,
	// never compare, and reassigning back to A would resume the activation with nothing latched
	// (Codex P1, PR #1360, round 6).
	Resolved bool
	// Authoritative is the CURRENT authoritative target, from the SAME loadTarget snapshot as
	// every other field here — never a second read. Meaningful only when Resolved.
	Authoritative canary.ReviewedTarget
	// ServerIdentity is the server's PINNED, verified identity as currently published. It rides
	// along here rather than in Target because Target is canary.LiveTarget — the key an approval is
	// matched on — and approvals record no identity, so widening it would break exact-target
	// approval matching. It is what makes server_identity_drift decidable against what was
	// REVIEWED rather than only against "is the server usable right now".
	ServerIdentity string
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
	if !ti.found {
		// Nothing resolves. Not drift: indistinguishable from a transient inventory gap.
		return liveTrustPrecheck{}
	}
	// Resolved BEFORE the tenant gate, so a target that exists under another owner is still
	// reported to the caller. See the Resolved/Authoritative field comments.
	authoritative := canary.ReviewedTarget{
		Tenant:            ti.target.Tenant,
		ServerID:          serverID,
		ToolName:          toolName,
		Fingerprint:       ti.target.Fingerprint,
		FingerprintFormat: ti.target.FingerprintFormatVersion,
		ServerIdentity:    ti.pinnedIdentity,
	}
	if ti.target.Tenant == "" || ti.target.Tenant != tenant {
		// Request-scoped for AUTHORIZATION — this request is not the owner — but the target is
		// carried out so the reviewed comparison can still see that the reviewed pair changed
		// hands. Eligible stays false, so nothing here authorizes anything.
		return liveTrustPrecheck{Resolved: true, Authoritative: authoritative}
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
	// The registry currently pins an identity the catalog record was NOT built against — the
	// repin/re-ingest window. A request would be routed to the registry's pin while every approval
	// and reviewed record describes the catalog's, so the workload about to be called is not the
	// one that was reviewed. Same code, same reason as an unusable anchor: the approved anchor is
	// not the one in force (Codex P1, PR #1360, round 4).
	if ti.registryPinDiverged {
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
		// From the SAME snapshot loadTarget resolved the fingerprint from, never a second lookup:
		// a Registry.Repin landing between two reads composes an (F1, I2) pair that was never
		// simultaneously authoritative. See the pinnedIdentity field comment in mcp_tooltrust.go.
		ServerIdentity: ti.pinnedIdentity,
	}
}

// mcpLiveApprovalSatisfied answers the APPROVAL half of live-execution trust: is THIS request
// authorized right now?
//
// It reports authorization and nothing else. It used to also report a drift verdict — an approval
// that was valid in every respect except that it pinned a different fingerprint for this exact
// (tenant, server, tool) was read as the rug-pull. That inference was correct whenever it fired,
// and it was the wrong instrument, because it could only fire while such an approval still
// EXISTED. An activation may run for FirstCanaryMaxWindowCeiling (7 days) and an approval may live
// at most MaxInitialCanaryApprovalTTL (24 hours), so once the reviewing approval expired the
// evidence was simply gone: a later F2 request read as an ordinary missing-approval denial, and a
// later F2 approval could resume execution across an intervening breach (Round-24 P1).
//
// Drift is now decided against the ACTIVATION's own immutable reviewed-target snapshot, inside the
// same atomic admission transaction, which is independent of approval lifetime by construction —
// see internal/mcp/canary/reviewed.go and admitLiveExecution step (5). The two questions are
// separate security facts and are no longer conflated:
//
//	approval   — is this request authorized NOW?
//	activation — is this still the exact target the experiment was reviewed against?
//
// The driftCode result is retained as always-empty so the seam's shape is unchanged for callers
// and a future authorization-scoped drift has somewhere to go; nothing produces one today.
func mcpLiveApprovalSatisfied(tgt canary.LiveTarget, now time.Time) (satisfied bool, driftCode string) {
	if mcpToolTrust == nil {
		return false, ""
	}
	for _, a := range mcpToolTrust.activeLiveApprovals(now) {
		if canary.SatisfiesLiveExecution(a, tgt, now) == canary.TrustOK {
			return true, ""
		}
	}
	// No satisfying approval: request-scoped. This request simply is not authorized (expired,
	// revoked, never granted).
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
