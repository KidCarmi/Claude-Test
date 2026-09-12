package execution

import (
	"errors"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// LiveExecutionGate is the OPTIONAL composition-layer gate the live Executor consults at the
// side-effect boundary. It exists so the gates that must live OUTSIDE this package —
// Canary blast-radius BUDGET reservation, runtime live-execution TRUST revalidation, and
// READ-FIRST operation enforcement — can run immediately before the irreversible upstream
// call WITHOUT this package importing the composition layer (rollout-runtime / tooltrust /
// canary singletons).
//
// PLACEMENT IS A SAFETY INVARIANT. The executor invokes the gate at the TOP of callUpstream,
// BEFORE preCallGuard's tool-freshness + emergency-kill re-check, so the kill re-read remains
// the LAST authoritative check before Upstream.Call (PREREQ-MCP-KILL-1): nothing the gate does
// (which may block on a durable budget persist) sits between the kill re-read and the side
// effect. A gate DENIAL therefore fails the execution closed and Upstream.Call is never
// reached; a gate ADMIT returns a Release the executor runs exactly once after the upstream leg
// (success, failure, or a later boundary refusal), so a reserved concurrency slot is never
// leaked — including the §11 case where a subsequent kill/freshness abort occurs AFTER the gate
// admitted (and after any credential materialization).
//
// The gate is nil in every non-live composition (the ShadowEvaluator has no LiveGate, and the
// disabled-by-default build composes no live executor), so the executor is byte-identical to
// the pre-gate path when it is unset.
type LiveExecutionGate interface {
	// AdmitSideEffect decides whether this request may cross the irreversible upstream
	// boundary. It performs NO upstream call and NO credential materialization.
	AdmitSideEffect(in LiveGateInput) LiveGateDecision

	// AdmitAuxiliary decides whether a NON-side-effect-bearing invocation — MCP
	// lifecycle and discovery traffic — may cross the same upstream boundary.
	//
	// It is a SEPARATE admission because the two questions are genuinely different,
	// and collapsing them in either direction is a defect this interface has already
	// suffered once in each direction:
	//
	//   - Routing auxiliary traffic through AdmitSideEffect spends a Canary execution
	//     reservation on a call that can cause no side effect (so MaxTotalExecutions
	//     stops measuring physical invocations) and refuses it on a tool-trust
	//     revalidation that has no tool to bind (so an armed node cannot complete a
	//     session handshake or list tools).
	//   - Skipping the gate ENTIRELY for auxiliary traffic — the first fix for the
	//     above — also discards the questions that DO apply to it: whether the live
	//     tier is armed at all, and whether it has begun quiescing. Those are the
	//     operator's disarm and wind-down controls, and after a restart the tier is
	//     deliberately left composed-but-unarmed while the persisted rollout mode may
	//     still resolve EffectExecute. Auxiliary traffic reaching a third-party
	//     upstream — establishing a session, reading its catalog, and carrying a
	//     materialized credential when the decision obliges one — on a tier the
	//     operator has disarmed or is winding down is the fail-closed restart posture
	//     (§17) being lost for every method except tools/call.
	//
	// So this admission runs the LIFECYCLE half and nothing else: no budget
	// reservation, no read-first, no live-trust revalidation. A denial fails the
	// invocation closed with the gate's bounded reason and Upstream.Call is never
	// reached; an admit returns a Release the executor runs exactly once after the
	// upstream leg, exactly as AdmitSideEffect does.
	//
	// It is part of the REQUIRED interface rather than an optional one on purpose: a
	// gate that does not answer this question must not be able to answer it by
	// omission, because omission is the permissive direction.
	AdmitAuxiliary(in LiveGateInput) LiveGateDecision
}

// LiveGateInput carries the authoritative, already-resolved facts the composition-layer gate
// needs. Every field derives from the pre-resolved decision (never a request-supplied claim):
// the executor builds it from runtime.ExecInput at the boundary.
type LiveGateInput struct {
	Capability protocol.Capability
	// Operation is the policy-engine operation class (read-first is decided from THIS, never
	// the server-provided readOnlyHint).
	Operation policy.OperationClass
	// Tenant / Principal identify the authenticated subject for the blast-radius ceilings.
	Tenant    string
	Principal string
	// ServerID / ToolName / Fingerprint are the exact reviewed target the live-trust
	// revalidation binds against (Fingerprint is the hex composite fingerprint the decision
	// was computed against; tool freshness separately proves it still matches the live tool).
	ServerID    string
	ToolName    string
	Fingerprint string
	// ResolvedScopeHash is the authorization envelope this request resolved under. The
	// admission transaction requires it to still be the one in force; "" is fail-closed.
	ResolvedScopeHash string
	Now               time.Time
}

// LiveGateDecision is the gate's verdict. Admit==false fails closed with Reason and Upstream.Call
// is never reached. Release (non-nil only when Admit) is run exactly once after the upstream leg.
type LiveGateDecision struct {
	Admit  bool
	Reason mcperr.Reason
	// Revalidate (non-nil only when Admit) is a FINAL-BOUNDARY re-check the executor runs inside
	// preCallGuard, immediately before the emergency-kill re-read, and again immediately before each
	// physical send. It returns mcperr.ReasonNone when the request may still proceed, and otherwise
	// the BOUNDED REASON naming which authority was withdrawn between admission and the irreversible
	// call — the reserved activation generation demoted, the resolved scope envelope replaced, or the
	// live approval revoked or expired.
	//
	// It RETURNS A REASON RATHER THAN A BOOL, and that is a correctness property, not ergonomics
	// (Codex P2, PR #1370, round 4). Collapsing every withdrawal onto one rollout reason made the
	// SAME scope mismatch report `rollout_out_of_scope` when admission caught it and
	// `rollout_mode_invalid` when the boundary did — two contradictory diagnoses for one fact,
	// separated only by timing, in the block telemetry an operator reads during an incident. The
	// mode is still a perfectly valid Canary in both cases.
	//
	// Because the admission-time reservation cannot see a later withdrawal, and preCallGuard's kill
	// re-read consults neither the Canary generation, the scope, nor the approval, WITHOUT this an
	// already-admitted request could still reach the upstream after a leaving-live transition, a
	// scope edit or a four-eyes revocation returned success (Codex P1, rounds 8/3/4). It is a
	// composition-layer concern — generation, scope and approval all live outside this package — so
	// it enters only as an injected predicate; the executor stays generic and byte-identical when the
	// gate (or Revalidate) is nil.
	Revalidate func() mcperr.Reason
	Release    func()
	// ReservationID (set only when Admit) names the budget slot this side effect was
	// authorized against. It binds a physical attempt to the reservation that paid
	// for it, so an effect can never be attributed to an unauthorized slot and an
	// orphan can be traced back to the exact grant. An empty value is tolerated:
	// gates that do not meter (nil/legacy) keep the executor byte-identical.
	ReservationID string
	// ActivationGeneration (set only when Admit) is the Canary activation generation
	// in force at admission. It is recorded on the attempt so an orphan from a
	// superseded generation stays recognizable after a restart and can never be
	// mistaken for fresh execution allowance. Zero when the gate does not meter.
	ActivationGeneration uint64
}

// errLiveGateRefused aborts callUpstream when the composition-layer gate denied the side effect.
// Like the drift/kill sentinels it never escapes the package: callUpstream captures the gate's
// bounded Reason in a local and classifyBoundaryRefusal surfaces it.
var errLiveGateRefused = errors.New("mcp: live side-effect gate refused")

// errLiveAuthorityWithdrawnAtBoundary aborts callUpstream when the gate's final-boundary Revalidate
// reports that the rollout authority this reservation rests on is no longer in force — the reserved
// activation generation is no longer current (a concurrent demotion), or the authorization envelope
// the request resolved under has been replaced (a concurrent scope update).
//
// Which of the two it was is deliberately NOT distinguished here: the gate owns that vocabulary,
// and this package must not learn to reason about scopes or generations to decide that a physical
// attempt is no longer authorized. Like the other boundary sentinels it never escapes the package:
// callUpstream maps it to a bounded rollout reason via classifyBoundaryRefusal so a client and block
// telemetry read a fail-closed refusal, never a transport/durability fault or ReasonNone.
var errLiveAuthorityWithdrawnAtBoundary = errors.New("mcp: live rollout authority withdrawn before upstream call")

// withdrawnErr carries the gate's bounded reason alongside the sentinel. The sentinel stays the
// thing every `errors.Is` in this package matches on, so the classification chain is unchanged;
// the reason rides beside it so the refusal can be diagnosed as what it was rather than as a
// fixed rollout reason (Codex P2, PR #1370, round 4).
type withdrawnErr struct{ reason mcperr.Reason }

func (e *withdrawnErr) Error() string { return errLiveAuthorityWithdrawnAtBoundary.Error() }
func (e *withdrawnErr) Unwrap() error { return errLiveAuthorityWithdrawnAtBoundary }

// withdrawnAtBoundary builds the refusal for a gate that named its reason.
func withdrawnAtBoundary(reason mcperr.Reason) error { return &withdrawnErr{reason: reason} }

// withdrawnReasonOf recovers the gate's reason, or ReasonNone when the error is not a
// withdrawal (or came from a gate that named nothing).
func withdrawnReasonOf(err error) mcperr.Reason {
	var we *withdrawnErr
	if errors.As(err, &we) {
		return we.reason
	}
	return mcperr.ReasonNone
}

// liveGateInput builds the gate input from the already-resolved ExecInput at the boundary. It
// reads ONLY resolved decision facts (principal/tool/server/operation), never a raw request
// value. in.Server is guaranteed non-nil here (runExecute blocks a nil/unusable server before
// callUpstream); in.Input.Tool may be nil for a non-tool method, in which case the target fields
// are empty and the gate's trust revalidation fails closed (no tool to approve).
//
// Now is read from the EXECUTOR'S CLOCK at this call — the boundary instant — NOT the request-entry
// timestamp in.Now. liveGateInput is built inside callUpstream, AFTER the durable decision commit and
// any credential materialization, which can each block; reusing in.Now would let the gate's live-trust
// revalidation treat an approval that expired during that delay as still valid, and evaluate the Canary
// budget window at an earlier instant (Codex P1, PR #1290). e.cfg.Clock is guaranteed non-nil (New
// defaults it to time.Now), so this evaluates trust/expiry/budget against the actual side-effect time.
func (e *Executor) liveGateInput(in runtime.ExecInput) LiveGateInput {
	var toolName, fp string
	if in.Input.Tool != nil {
		toolName = in.Input.Tool.Name
		fp = in.Input.Tool.FingerprintHash
	}
	var serverID string
	if in.Server != nil {
		serverID = string(in.Server.ID)
	}
	return LiveGateInput{
		Capability:  in.Capability,
		Operation:   in.Input.Operation.Class,
		Tenant:      in.Input.Principal.Tenant,
		Principal:   in.Input.Principal.SubjectID,
		ServerID:    serverID,
		ToolName:    toolName,
		Fingerprint: fp,
		// Carried through verbatim, exactly like the operation class: the gate revalidates
		// the envelope the request resolved under, it never re-derives one here. Re-reading
		// the live scope at this point would compare the current envelope against itself.
		ResolvedScopeHash: in.ResolvedScopeHash,
		Now:               e.cfg.Clock(), // the boundary instant, not the request-entry in.Now (see doc above)
	}
}
