package canary

import (
	"sort"

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
)

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
)

// Compare decides the current target against the activation's reviewed record.
//
// It is PURE, total, and deliberately makes only ONE distinction that latches: the target
// this activation was reviewed for has moved. Everything else is request-scoped.
//
// An EMPTY set returns ReviewedOutOfScope for every input rather than matching anything —
// the fail-closed direction for a record that should never have been armed.
func (s ReviewedTargetSet) Compare(cur ReviewedTarget) ReviewedVerdict {
	for i := range s.targets { // index-based: ReviewedTarget carries a 32-byte digest
		r := s.targets[i]
		if r.key() != cur.key() {
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
	return ReviewedOutOfScope
}
