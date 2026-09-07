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
	// CanaryDriftObserved is the OPTIONAL narrow seam for reporting that this pipeline observed
	// authoritative tool drift BEFORE the executor was reached. Nil ⇒ nothing composed and nothing
	// reported, which is the disabled-by-default posture.
	//
	// THIS PIPELINE DOES NOT DECIDE THE LATCH, AND IT DOES NOT SUPPLY THE VALUE THAT DOES.
	//
	// The observation here is made outside any activation critical section, so on its own it cannot
	// be attributed to a generation — that is what PR #1314 spent five review rounds failing to do
	// with reads around the observation, and counter equality proves only that a value did not
	// change, never that it was continuously active.
	//
	// But "cannot latch from here" is NOT the same as "must not latch", and treating them as the
	// same was its own defect (Codex round 20): a rug-pull landing before policy resolution is
	// refused here, and every later request then resolves cleanly against the NEW fingerprint and is
	// denied for a missing approval — request-scoped, not drift — so an authoritative whole-Canary
	// breach would stop nothing at all. That is the round-14 finding rebuilt.
	//
	// So the seam carries the TARGET, not just a verdict. The root re-evaluates the drift live
	// INSIDE the activation critical section and latches against the exact generation that is active
	// for that evaluation; if no activation is live (the §6 publication gap), nothing is latched and
	// no future activation can inherit the observation. What is passed here is evidence and an
	// identity to re-check — never the latch input itself.
	CanaryDriftObserved func(capability string, obs CanaryDriftTarget)
	// Clock is injected for deterministic tests; nil ⇒ time.Now.
	Clock func() time.Time
}

// CanaryDriftTarget names the exact target a pre-executor drift observation was made against.
// It exists so the root can RE-DERIVE the drift live under the activation lock rather than trust a
// verdict computed outside one: the re-derived value is what decides the latch.
type CanaryDriftTarget struct {
	Code       string
	Tenant     string
	ServerID   string
	ToolName   string
	DecisionFP string
}

// noteCanaryDriftObserved reports a pre-executor drift observation when a sink is composed.
// Nil-safe so call sites stay free of branching.
func (d Deps) noteCanaryDriftObserved(capability string, obs CanaryDriftTarget) {
	if d.CanaryDriftObserved != nil {
		d.CanaryDriftObserved(capability, obs)
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
