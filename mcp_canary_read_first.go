package main

import (
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mcp_canary_read_first.go — the ONE place a tools/call may be classified read-first.
//
// THE PROBLEM THIS CLOSES. runtime/policy.go classifies tools/call as OpWrite by default
// ("a tool call is a write unless a later slice supplies a finer class") and the Canary
// read-first gate admits only OpRead/OpDiscovery. So no real tool invocation could cross the
// First-Canary boundary, however harmless the reviewed tool actually is. The default is
// correct and stays: a gateway that guesses a tool is safe is a gateway that will eventually
// guess wrong. What was missing is an AUTHORITATIVE narrow exception.
//
// WHAT MAKES IT AUTHORITATIVE. Exactly one fact can promote a call, and it is the activation's
// own immutable reviewed record — the same snapshot blocker #7 bound to the generation, now
// carrying the reviewed operation class beside the fingerprint it was reviewed at. So the
// promotion requires, simultaneously:
//
//	an ARMED activation on this capability
//	whose reviewed record contains this exact (tenant, server, tool)
//	at this exact fingerprint AND fingerprint format
//	under this exact pinned server identity
//	classified by a four-eyes review as read-only
//
// Anything else — no activation, no reviewed entry, a moved fingerprint, a moved identity, a
// moved tenant, an unstated class — is not read-first. There is no partial credit.
//
// WHAT IS DELIBERATELY NOT AN INPUT, because each is a way the peer or the caller would end up
// deciding its own blast radius:
//
//   - the request, its arguments, or their shape — the class describes the TOOL CONTRACT at a
//     fingerprint, not one invocation; a tool whose effect depends on its arguments is simply
//     not reviewable as read-only (see tooltrust/reviewed_operation.go);
//   - the tool's NAME — "get_", "list_", "read_" are conventions, not contracts;
//   - any server-supplied metadata, including an MCP readOnlyHint the ingest path might one
//     day carry: a hint is input to a HUMAN REVIEW, never runtime authority;
//   - the catalog's descriptive/annotation material, for the same reason;
//   - anything a model or heuristic concluded.
//
// The function below takes (capability, serverID, toolName) and NOTHING else from its caller,
// and resolves every other fact from authoritative node inventory itself. That signature is
// the structural half of the guarantee: there is no parameter through which a hint, an
// argument, or a caller's opinion could arrive, so a future change that wanted one would have
// to widen the seam in a diff a reviewer sees.

// canaryReviewedOperationClass answers, for an exact named tool, the operation class the ACTIVE
// activation's immutable reviewed record binds to it — and whether that record can speak for
// the tool at all.
//
// It resolves the CURRENT authoritative target itself (registry + catalog, via the same
// single-snapshot reader the drift path uses) rather than accepting one, so the fingerprint,
// fingerprint format, tenant and pinned identity it compares are the node's own facts.
//
// It is fail-closed on every uncertainty, and three of those deserve saying out loud:
//
//   - NO ARMED ACTIVATION ⇒ nothing is classified. In the shipped build no activation ever
//     arms, so this returns false for every request and every tools/call stays OpWrite —
//     byte-identical to the behaviour before this file existed.
//   - THE TOOL IS NOT USABLE (server disabled, identity unverified) ⇒ not classified. The
//     classification's whole basis is that the current authoritative target IS the reviewed
//     one; a target whose trust anchor is not in force is not a target this node can speak
//     for. It does not REPLACE the catalog's own controls — a quarantined tool is still
//     denied by the policy engine's hard override — it declines to speak first.
//   - THE REGISTRY PIN HAS DIVERGED from the identity the catalog observed ⇒ not classified.
//     Two disagreeing answers to "what identity is this server" is the ambiguous case, and the
//     core invariant is that ambiguity is never read.
func canaryReviewedOperationClass(capb rollout.Capability, serverID, toolName string) (policy.OperationClass, bool) {
	if serverID == "" || toolName == "" {
		return policy.OpUnset, false
	}
	reviewed, armed := globalCanaryRuntime.activeReviewedTargets(capb)
	if !armed {
		return policy.OpUnset, false
	}
	cur := mcpCurrentAuthoritativeTarget(serverID, toolName)
	if !cur.Found || !cur.Usable || cur.RegistryPinDiverged {
		return policy.OpUnset, false
	}
	return reviewed.OperationClassFor(cur.Target)
}

// canaryReadFirstClassifier is the seam handed to the MCP runtime. It is bound to the Gateway
// capability because Management never crosses the upstream side-effect boundary, so a
// Management tools/call has nothing to be classified read-first FOR.
//
// The runtime receives a function, not the reviewed set: the root keeps the activation lock and
// the inventory read on its own side of the boundary, and the runtime can ask only the exact
// question it is entitled to ask.
func canaryReadFirstClassifier(capability string, serverID, toolName string) (policy.OperationClass, bool) {
	if capability != rollout.CapabilityGateway.String() {
		return policy.OpUnset, false
	}
	return canaryReviewedOperationClass(rollout.CapabilityGateway, serverID, toolName)
}
