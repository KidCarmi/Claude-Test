package runtime

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// Deps are the shared IMMUTABLE libraries the listeners read. They are read-only
// from the listeners' perspective (snapshots / pure validators); the listeners never
// mutate them and never share mutable per-capability state through them. The replay
// cache is per-capability partitioned internally, so one instance is safe for both.
type Deps struct {
	Registry     *registry.Registry
	Catalog      *catalog.Catalog
	Keys         authn.KeyResolver
	Introspector authn.Introspector
	Replay       *senderconstraint.ReplayCache
	// Sink receives sanitized observe records. A nil sink drops records (still
	// bounded). Sink failure NEVER permits a denied request or a decision-point
	// operation, and must not block shutdown.
	Sink Sink
	// Policy is the OPTIONAL capability-local policy provider (PR-6). When nil, the
	// listener keeps the PR-5 observe-only disposition for decision-point methods.
	// When set, decision-point methods are evaluated against the capability-local
	// policy snapshot (decision-only — never an upstream/credential/broker call); a
	// missing snapshot fails closed with MCP.POLICY.SNAPSHOT_UNAVAILABLE, never a
	// permissive fall-back.
	Policy PolicyProvider
	// Inspection is the OPTIONAL capability-local inspection provider (PR-7). When
	// nil, decision-point methods keep the pre-inspection path (byte-identical). When
	// set, a Gateway tools/call is semantically inspected (schema/DLP/destination)
	// BEFORE policy evaluation; a hard security failure blocks regardless of the
	// policy action, and an ALLOW_WITH_REDACTION obligation is satisfied by a
	// re-validated transform — still decision-only (no upstream/credential/broker
	// call, execution_state stays not_implemented).
	Inspection InspectionProvider
	// Events is the OPTIONAL capability-scoped PR-8 durable decision-event provider.
	// When nil, the pipeline keeps the PR-7 decision-only path byte-identically (no
	// event committed, no denial routed). When set, an ALLOW-class decision-point
	// outcome durably commits a sanitized decision event before the (still
	// not-implemented) response — a critical operation whose event cannot commit
	// fails closed — and auth/authorization denials are routed into the isolated
	// denial lane. It never causes an upstream/credential/broker call.
	Events EventProvider
	// Executor is the OPTIONAL capability-local guarded-execution provider (PR-11).
	// When nil, the pipeline keeps the PR-8 decision-only path byte-identically
	// (execution_state stays not_implemented). When set — only for the Gateway
	// capability, and only after rollout distribution arms it — a decision-point
	// outcome is handed to the rollout-mode executor AFTER inspection + policy have
	// run, which resolves the effective mode disposition (record-only / execute /
	// block) and, for an in-scope executing mode, performs the real guarded upstream
	// tools/call (credential broker + PR-8 commit-before-materialization + upstream
	// client + response DLP). A nil executor is the disabled-by-default posture.
	Executor ExecutionProvider
	// CanaryDriftObserved is the OPTIONAL narrow seam for recording that this pipeline observed
	// authoritative tool drift BEFORE the executor was reached. Nil ⇒ nothing composed and nothing
	// recorded, which is the disabled-by-default posture.
	//
	// IT IS EVIDENCE, NOT AN ABORT TRIGGER, and the distinction is the whole point of the seam.
	//
	// This observation happens before ADMISSION, and admission — the budget reservation taken under
	// the activation lock — is the only thing that binds a request to an activation. So at this point
	// there is no generation this observation belongs to, and PR #1314 spent five review rounds
	// discovering that no arrangement of unlocked generation reads can manufacture one: counter
	// equality either side of the observation proves the value did not change, not that any
	// activation was live throughout (the rollout publication gap makes both reads a stale value).
	//
	// Latching on an unattributable observation is exactly what the invariant forbids, and it fails
	// in the dangerous direction — a request decided under a since-demoted activation stopping the
	// experiment that replaced it, which never saw the drift. So this pipeline REFUSES the drifted
	// request (unchanged, fail-closed) and records the fact; the whole-Canary latch for drift is
	// taken by the atomic activation-bound admission transaction, which has a real generation to
	// charge and evaluates trust under the same lock that latches.
	CanaryDriftObserved func(capability, code string)
	// Clock is injected for deterministic tests; nil ⇒ time.Now.
	Clock func() time.Time
}

// noteCanaryDriftObserved records a pre-executor drift observation when a sink is composed.
// Nil-safe so call sites stay free of branching. It records; it never stops the Canary.
func (d Deps) noteCanaryDriftObserved(capability, code string) {
	if d.CanaryDriftObserved != nil {
		d.CanaryDriftObserved(capability, code)
	}
}

func (d Deps) now() time.Time {
	if d.Clock != nil {
		return d.Clock()
	}
	return time.Now()
}

// authDeps builds the PR-3 authn.Deps from the shared libraries.
func (d Deps) authDeps() authn.Deps {
	return authn.Deps{
		Keys:         d.Keys,
		Introspector: d.Introspector,
		Registry:     d.Registry,
		Catalog:      d.Catalog,
		Replay:       d.Replay,
	}
}
