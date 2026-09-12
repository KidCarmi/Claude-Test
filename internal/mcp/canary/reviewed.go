package canary

import (
	"sort"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// reviewed.go — the activation's IMMUTABLE record of what it was reviewed to execute.
//
// WHY THIS EXISTS. Live-execution trust answers one question — "is this request authorized
// NOW?" — and an approval is the right instrument for it: short-lived by construction
// (MaxInitialCanaryApprovalTTL, 24h) so authorization cannot outlive its review.
//
// Drift detection answers a DIFFERENT question — "is this still the exact target this
// experiment was reviewed against?" — and an approval is the wrong instrument for it, for
// precisely the reason that makes it the right one for the first: it expires. An activation
// may run for FirstCanaryMaxWindowCeiling (7 days), so for six of those days the approval
// that recorded what was reviewed is simply gone. Using approval lifetime as drift memory
// therefore produces this sequence, which is the Round-24 P1:
//
//	T0     activation G reviewed against fingerprint F1
//	T+24h  the F1 approval expires — the only record of "G was reviewed against F1"
//	later  the tool moves F1 → F2
//	later  an F2 request arrives, reads as an ordinary missing-approval denial
//	later  someone approves F2; execution resumes under G, across an intervening breach
//
// Nothing in that sequence latches, because by the time the target moved there was nothing
// left to compare it to. The two facts were conflated; this file separates them. The
// activation carries its own immutable snapshot of the reviewed targets, and drift is
//
//	current authoritative target  !=  activation's reviewed target
//
// which is decidable for the whole life of the activation and depends on no approval at all.

// MaxReviewedTargets bounds an activation's reviewed set. It is the first-Canary scope
// product (tenants × tools) — the set is derived from the scope the activation review
// proved, so a set larger than the scope could ever admit is malformed by construction.
const MaxReviewedTargets = MaxCanaryTenants * MaxCanaryTools

// ReviewedTarget is one exact target an activation was reviewed and authorized to execute.
//
// It carries ServerIdentity, which LiveTarget does not: server_identity_drift must be
// decidable against what was REVIEWED, and the authoritative identity (the registry's
// pinned, verified TLS/workload identity) is the minimum immutable field that distinguishes
// "the trust anchor changed" from "the tool changed". Adding it here rather than to
// LiveTarget is deliberate — LiveTarget is the key an approval is matched on, and approvals
// do not record an identity, so widening it would break exact-target approval matching.
type ReviewedTarget struct {
	Tenant            string
	ServerID          string
	ToolName          string
	Fingerprint       tooltrust.FingerprintDigest
	FingerprintFormat uint16
	// ServerIdentity is the registry's pinned verified identity, canonical string form, as
	// observed at activation review.
	ServerIdentity string
	// OperationClass is the operation class the review bound to THIS exact capability at THIS
	// exact fingerprint — the fact that decides whether a tools/call for it may be read-first.
	//
	// It lives here, on the activation's immutable record, rather than in a classifier of its
	// own, for the reason this whole file exists: two authorities that can answer the same
	// question about the same tool will eventually disagree, and the disagreement is silent.
	// The activation already answers "what was this experiment reviewed to execute"; "and with
	// what semantics" is the same question's second half. A separate classifier keyed on
	// (server, tool) would additionally be keyed on the WRONG thing — see Compare: the
	// classification is only ever consulted for a target whose fingerprint still matches, so a
	// tool that moves carries no determination at all until a new review states one.
	//
	// CanonicalizeReviewedTargets refuses a set whose class is unset or outside the reviewable
	// vocabulary, so an activation cannot arm carrying a target it cannot classify.
	OperationClass policy.OperationClass
}

// key is the exact identity a reviewed target is looked up by. Fingerprint is deliberately
// NOT part of it: the whole point is to find the reviewed entry for this (tenant, server,
// tool) and then compare fingerprints.
type reviewedKey struct{ tenant, serverID, toolName string }

func (t ReviewedTarget) key() reviewedKey {
	return reviewedKey{tenant: t.Tenant, serverID: t.ServerID, toolName: t.ToolName}
}

// ReviewedReason is a bounded classification for a rejected reviewed-target set. Fixed
// vocabulary; never interpolated with runtime data.
type ReviewedReason string

// Reviewed-set rejection sub-reasons (ReviewedOK is the empty admissible value).
const (
	ReviewedOK               ReviewedReason = ""
	ReviewedEmpty            ReviewedReason = "reviewed_targets_empty"
	ReviewedTooMany          ReviewedReason = "reviewed_targets_too_many"
	ReviewedIncompleteID     ReviewedReason = "reviewed_target_incomplete_identity"
	ReviewedZeroFingerprint  ReviewedReason = "reviewed_target_zero_fingerprint"
	ReviewedBadFormat        ReviewedReason = "reviewed_target_invalid_fingerprint_format"
	ReviewedNoServerIdentity ReviewedReason = "reviewed_target_no_server_identity"
	ReviewedDuplicate        ReviewedReason = "reviewed_target_duplicate"
	ReviewedAmbiguous        ReviewedReason = "reviewed_target_ambiguous"
	// ReviewedNoOperationClass — a target whose reviewed operation class is unset. An
	// activation that cannot say what a target's semantics were reviewed to be must not arm:
	// the alternative is a record that later has to be guessed at, and the read-first gate is
	// where that guess would land.
	ReviewedNoOperationClass ReviewedReason = "reviewed_target_no_operation_class"
	// ReviewedBadOperationClass — a class outside the reviewable vocabulary (see
	// reviewableOperationClasses). Discovery and control are not properties of a TOOL; a
	// reviewed target carrying one is malformed, not merely non-read.
	ReviewedBadOperationClass ReviewedReason = "reviewed_target_invalid_operation_class"
)

// reviewableOperationClasses is the complete set a REVIEW may bind to an exact tool
// capability. It is deliberately narrower than policy.OperationClass:
//
//   - OpUnset is "nobody answered" and is refused on its own named reason;
//   - OpDiscovery describes a PROTOCOL method (tools/list), not a tool's effect — a tool
//     reviewed as "discovery" would be a category error, and one that later reached the
//     read-first gate would pass it (IsReadFirstOperation admits discovery) on a
//     classification no reviewer meant as "this tool is safe to invoke";
//   - OpControl is a control-plane operation, likewise not a tool's effect on the world.
//
// That leaves the two answers a reviewer is actually being asked for, plus the destructive
// refinement of the mutating one. None of the three but OpRead is read-first, so admitting
// OpDestructive costs nothing and lets a reviewed record stay honest about severity.
func reviewableOperationClasses() []policy.OperationClass {
	return []policy.OperationClass{policy.OpRead, policy.OpWrite, policy.OpDestructive}
}

// reviewableOperationClass reports whether c is a class a review may bind to a tool.
func reviewableOperationClass(c policy.OperationClass) bool {
	for _, v := range reviewableOperationClasses() {
		if c == v {
			return true
		}
	}
	return false
}

// OperationClassFromReviewed maps a tooltrust review determination onto the policy operation
// class an activation records. It is the ONE translation between the two vocabularies, so a
// consumer never re-derives it — and the one place a reader checks to confirm that a server's
// metadata has no path into a policy class.
//
// The mapping is deliberately total and fail-closed: an unstated determination yields
// (OpUnset, false), and a caller that ignores the bool gets a class canonicalization refuses.
func OperationClassFromReviewed(c tooltrust.ReviewedOperationClass) (policy.OperationClass, bool) {
	switch c {
	case tooltrust.ReviewedOpReadOnly:
		return policy.OpRead, true
	case tooltrust.ReviewedOpMutating:
		return policy.OpWrite, true
	default:
		return policy.OpUnset, false
	}
}

// ReviewedTargetSet is a canonical, immutable reviewed-target set. The zero value is EMPTY
// and therefore never grants anything — an activation holding it can execute nothing, which
// is the fail-closed direction.
type ReviewedTargetSet struct {
	// targets is canonically ordered and duplicate-free. It is never mutated after
	// CanonicalizeReviewedTargets returns; accessors copy.
	targets []ReviewedTarget
}

// Len reports how many exact targets the activation was reviewed against.
func (s ReviewedTargetSet) Len() int { return len(s.targets) }

// Empty reports whether the set authorizes nothing. An activation MUST NOT be armed with an
// empty set: it would carry no evidence of what it was reviewed to do, which is the state
// this whole mechanism exists to make impossible.
func (s ReviewedTargetSet) Empty() bool { return len(s.targets) == 0 }

// Targets returns a COPY in canonical order, so a caller can persist or compare it without
// being able to mutate the activation's record.
func (s ReviewedTargetSet) Targets() []ReviewedTarget {
	if len(s.targets) == 0 {
		return nil
	}
	out := make([]ReviewedTarget, len(s.targets))
	copy(out, s.targets)
	return out
}

// Equal reports whether two canonical sets record exactly the same reviewed targets. It
// backs the same-generation immutability rule: a running activation's reviewed set may be
// re-supplied identically, but never REPLACED (§10).
func (s ReviewedTargetSet) Equal(o ReviewedTargetSet) bool {
	if len(s.targets) != len(o.targets) {
		return false
	}
	for i := range s.targets {
		if s.targets[i] != o.targets[i] {
			return false
		}
	}
	return true
}

// CanonicalizeReviewedTargets validates and canonicalizes a candidate reviewed set.
//
// It is PURE and fail-closed. Every rejection is a named reason, and an ambiguous input is
// REJECTED rather than resolved: "last one wins" on a set that decides what an experiment
// may execute would let a malformed activation silently authorize the wrong target.
//
//   - empty ⇒ rejected (an activation with nothing reviewed must not arm);
//   - more than MaxReviewedTargets ⇒ rejected;
//   - any incomplete identity, zero fingerprint, zero format, or missing server identity
//     ⇒ rejected;
//   - the same (tenant, server, tool) twice ⇒ rejected as duplicate when the entries are
//     identical, and as ambiguous when they disagree — two different answers to "what was
//     reviewed" is exactly the condition that must never be resolved by ordering.
//
// On success the returned set is sorted deterministically, so an activation's record — and
// therefore its persisted bytes — does not depend on the order the caller happened to
// resolve its scope in.
func CanonicalizeReviewedTargets(in []ReviewedTarget) (ReviewedTargetSet, ReviewedReason) {
	if len(in) == 0 {
		return ReviewedTargetSet{}, ReviewedEmpty
	}
	if len(in) > MaxReviewedTargets {
		return ReviewedTargetSet{}, ReviewedTooMany
	}
	seen := make(map[reviewedKey]ReviewedTarget, len(in))
	out := make([]ReviewedTarget, 0, len(in))
	for i := range in { // index-based: ReviewedTarget carries a 32-byte digest
		t := in[i]
		switch {
		case t.Tenant == "" || t.ServerID == "" || t.ToolName == "":
			return ReviewedTargetSet{}, ReviewedIncompleteID
		case t.Fingerprint == (tooltrust.FingerprintDigest{}):
			return ReviewedTargetSet{}, ReviewedZeroFingerprint
		case t.FingerprintFormat == 0:
			return ReviewedTargetSet{}, ReviewedBadFormat
		case t.ServerIdentity == "":
			return ReviewedTargetSet{}, ReviewedNoServerIdentity
		case t.OperationClass == policy.OpUnset:
			return ReviewedTargetSet{}, ReviewedNoOperationClass
		case !reviewableOperationClass(t.OperationClass):
			return ReviewedTargetSet{}, ReviewedBadOperationClass
		}
		if prev, dup := seen[t.key()]; dup {
			if prev == t {
				return ReviewedTargetSet{}, ReviewedDuplicate
			}
			return ReviewedTargetSet{}, ReviewedAmbiguous
		}
		seen[t.key()] = t
		out = append(out, t)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Tenant != out[b].Tenant {
			return out[a].Tenant < out[b].Tenant
		}
		if out[a].ServerID != out[b].ServerID {
			return out[a].ServerID < out[b].ServerID
		}
		return out[a].ToolName < out[b].ToolName
	})
	return ReviewedTargetSet{targets: out}, ReviewedOK
}

// ReviewedVerdict is the outcome of comparing a current authoritative target against the
// activation's reviewed record. Fixed vocabulary.
type ReviewedVerdict string

const (
	// ReviewedMatches — the current target is exactly the reviewed one. Execution may
	// proceed to the remaining checks.
	ReviewedMatches ReviewedVerdict = ""
	// ReviewedFingerprintDrift — same reviewed tool, DIFFERENT fingerprint. The executed
	// tool is not the reviewed tool: a whole-Canary breach.
	ReviewedFingerprintDrift ReviewedVerdict = "tool_fingerprint_drift"
	// ReviewedServerIdentityDrift — same reviewed tool, DIFFERENT pinned server identity.
	// The trust anchor the experiment was authorized against is no longer the one in
	// force: a whole-Canary breach.
	ReviewedServerIdentityDrift ReviewedVerdict = "server_identity_drift"
	// ReviewedOutOfScope — this (tenant, server, tool) is not in the reviewed set at all.
	// REQUEST-SCOPED, never a breach: an activation correctly refusing a target it was
	// never reviewed for is the Canary working. Latching the whole experiment for it would
	// let any unrelated request stop it.
	ReviewedOutOfScope ReviewedVerdict = "reviewed_target_out_of_scope"
	// ReviewedTenantDrift — the reviewed (server, tool) still exists, but it now belongs to a
	// DIFFERENT tenant than the one the review bound.
	//
	// This is a breach, and separating it from ReviewedOutOfScope is the whole point. The lookup
	// key is (tenant, server, tool), so a reassignment A→B makes the current target miss the
	// reviewed key and fall through to "not in the reviewed set" — which is deliberately silent.
	// A reviewed target crossing a tenant boundary would therefore be invisible, and reassigning
	// it back to A later would let the original activation resume with nothing recorded (Codex P1,
	// PR #1360, round 4). Tenancy is the isolation boundary the approval was granted within; a
	// target that changed hands is not the target that was reviewed.
	ReviewedTenantDrift ReviewedVerdict = "reviewed_target_tenant_drift"
)

// DriftVerdicts returns every verdict that means the reviewed target MOVED — the breach verdicts,
// as opposed to ReviewedMatches (healthy) and ReviewedOutOfScope (request-scoped by design).
//
// It exists so consumers enumerate this set from ONE place instead of hand-listing it. A drift
// verdict has to reach several surfaces to be useful — the abort taxonomy, the bounded evidence
// allowlist, the latch branches — and the failure mode this PR produced repeatedly is a new fact
// wired into some of them and not the rest. A hand-written list at each surface makes that failure
// silent; a shared accessor plus the exhaustiveness test beside it makes it loud.
func DriftVerdicts() []ReviewedVerdict {
	return []ReviewedVerdict{
		ReviewedFingerprintDrift,
		ReviewedServerIdentityDrift,
		ReviewedTenantDrift,
	}
}

// IsDriftVerdict reports whether v is one of the breach verdicts — the ones that stop the
// experiment. It is DERIVED from DriftVerdicts rather than written out again, so a verdict added
// to that list is classified here without a second edit; the exhaustiveness wall beside this file
// is what makes an unclassified verdict loud rather than silent.
func IsDriftVerdict(v ReviewedVerdict) bool {
	for _, d := range DriftVerdicts() {
		if v == d {
			return true
		}
	}
	return false
}

// NonBreachVerdicts returns the verdicts that deliberately do NOT stop the experiment.
func NonBreachVerdicts() []ReviewedVerdict {
	return []ReviewedVerdict{ReviewedMatches, ReviewedOutOfScope}
}

// Compare decides the current target against the activation's reviewed record.
//
// It is PURE, total, and deliberately makes only ONE distinction that latches: the target
// this activation was reviewed for has moved. Everything else is request-scoped.
//
// An EMPTY set returns ReviewedOutOfScope for every input rather than matching anything —
// the fail-closed direction for a record that should never have been armed.
func (s ReviewedTargetSet) Compare(cur ReviewedTarget) ReviewedVerdict {
	tenantMoved := false
	for i := range s.targets { // index-based: ReviewedTarget carries a 32-byte digest
		r := s.targets[i]
		if r.key() != cur.key() {
			// The (server, tool) IS reviewed, under a different tenant. Remember it, but keep
			// scanning: an exact key later in the set is the better answer, and the set is small
			// (MaxReviewedTargets), so the full walk costs nothing.
			if r.ServerID == cur.ServerID && r.ToolName == cur.ToolName {
				tenantMoved = true
			}
			continue
		}
		// The reviewed tool. Compare what the review actually bound.
		if r.ServerIdentity != cur.ServerIdentity {
			return ReviewedServerIdentityDrift
		}
		if r.Fingerprint != cur.Fingerprint || r.FingerprintFormat != cur.FingerprintFormat {
			return ReviewedFingerprintDrift
		}
		return ReviewedMatches
	}
	if tenantMoved {
		// A reviewed (server, tool) that now answers to another tenant. NOT out-of-scope: this is
		// the reviewed target, and it has crossed the isolation boundary the approval was granted
		// within.
		return ReviewedTenantDrift
	}
	return ReviewedOutOfScope
}

// OperationClassFor returns the operation class the review bound to the CURRENT target, and
// whether the activation's record can speak for it at all.
//
// This is the read-first classifier, and its entire correctness argument is the first line:
// it delegates to Compare, so it answers ONLY for a target that still matches the reviewed
// record exactly — same tenant, same server, same tool, same pinned server identity, same
// fingerprint AND same fingerprint format. Every other verdict yields (OpUnset, false).
//
// That is what makes the classification FINGERPRINT-BOUND rather than name-bound. A tool
// reviewed read-only at F1 that republishes as F2 produces ReviewedFingerprintDrift here, so
// F2 inherits nothing: it is not "read-only until someone notices", it is unclassified, and
// an unclassified target is not read-first. The same holds for a moved trust anchor
// (ReviewedServerIdentityDrift), a tool that changed tenants (ReviewedTenantDrift), a target
// the activation was never reviewed for (ReviewedOutOfScope), and the zero set — the last of
// which is why an activation that somehow armed with nothing reviewed classifies nothing.
//
// It is PURE and reads NOTHING but the caller-supplied current target and the immutable
// reviewed record: no clock, no catalog, no request, no server-supplied metadata. The caller
// is responsible for building `cur` from AUTHORITATIVE inventory state — that is the property
// the root's classifier seam exists to guarantee, and no amount of care here can substitute
// for it.
//
// cur.OperationClass is IGNORED. Compare does not read it, and it must not: the class is an
// output of this function, never an input to the match. A caller that could supply a class
// and have it honoured would be classifying its own request.
func (s ReviewedTargetSet) OperationClassFor(cur ReviewedTarget) (policy.OperationClass, bool) {
	if s.Compare(cur) != ReviewedMatches {
		return policy.OpUnset, false
	}
	for i := range s.targets { // index-based: ReviewedTarget carries a 32-byte digest
		if s.targets[i].key() == cur.key() {
			return s.targets[i].OperationClass, true
		}
	}
	// Unreachable: Compare returned ReviewedMatches, which it does only from inside the loop
	// over this same slice on this same key. Kept as the fail-closed answer rather than a
	// panic — a classifier is the wrong place to be right about being unreachable.
	return policy.OpUnset, false
}

// ReviewedReadFirst reports whether the CURRENT target is bound, by the activation's immutable
// reviewed record, to a read-only reviewed class.
//
// It exists so the one question the read-first gate actually asks is answered in one place,
// as a boolean, rather than each consumer comparing a class it fetched. The difference is not
// cosmetic: `class != policy.OpWrite` and `ok || class == policy.OpRead` are both plausible
// mis-readings of OperationClassFor that admit an UNSET class, and this predicate makes both
// impossible to write by accident. Both halves are required — a class is read-first only when
// the record could speak for the target AND said read.
func (s ReviewedTargetSet) ReviewedReadFirst(cur ReviewedTarget) bool {
	class, ok := s.OperationClassFor(cur)
	return ok && class == policy.OpRead
}
