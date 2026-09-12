package tooltrust

// reviewed_operation.go — the REVIEWED operation semantics of an exact approved tool.
//
// WHY THIS EXISTS, and why it is a separate fact from everything already on a ToolApproval.
//
// The First Controlled Canary needs to execute ONE real tool call. Culvert classifies
// tools/call as a WRITE by default (runtime/policy.go: "a tool call is a write unless a
// later slice supplies a finer class"), and the Canary read-first gate admits only
// read/discovery — so no real tool invocation could ever cross it. That is the correct
// default and must stay the default: the alternative is a gateway that guesses.
//
// What was missing is a way for Culvert to say, authoritatively and for ONE exact reviewed
// capability, "a human reviewed this exact tool at this exact fingerprint and determined its
// contract is non-mutating". That statement belongs on the approval, because the approval is
// already the reviewed artifact: four-eyes, bound to an exact fingerprint and fingerprint
// format, short-lived, revocable, and re-validated against current state at approve time.
// Putting it anywhere else would create a SECOND authority that could disagree with the
// approval about the same tool.
//
// THREE RULES, each of which is the whole point of the type:
//
//  1. IT IS NEVER DERIVED FROM THE SERVER. MCP tool metadata can carry annotations such as
//     readOnlyHint / destructiveHint / idempotentHint. Those are INPUT TO A REVIEW — a human
//     reading them and deciding — never runtime authority. A server asserting readOnlyHint
//     must not be able to change what Culvert will execute; otherwise the peer decides its
//     own blast radius. This package deliberately holds no hint field at all, so there is
//     nothing for a future change to accidentally wire through.
//
//  2. IT IS NEVER DERIVED FROM A REQUEST. The class describes the TOOL CONTRACT at an exact
//     fingerprint, not one invocation of it. A tool whose effect depends on its arguments is
//     therefore NOT reviewable as read-only here: the reviewer cannot bind a per-argument
//     promise to a fingerprint, so such a tool stays mutating and is simply ineligible for
//     the first Canary. Proving an argument-level safe subset would need an independently
//     reviewed operation-level contract, which this type does not attempt.
//
//  3. THE ZERO VALUE IS FAIL-CLOSED. ReviewedOpUnset means "no review stated the semantics",
//     and every consumer must read that as "not read-only". An approval that simply never
//     answered the question can therefore never widen what may execute.
//
// The vocabulary is deliberately BINARY rather than a mirror of the policy operation
// taxonomy. The only question a reviewer is being asked here is the one the read-first gate
// asks — is this exact capability non-mutating? — and a richer enum would invite a reviewer
// to record a distinction (write vs destructive, say) that this fact is not the authority
// for. Non-read-only is one answer with one consequence.

// ReviewedOperationClass is what a human review determined about an exact approved tool's
// effect on the world, at the exact fingerprint the approval binds.
type ReviewedOperationClass uint8

const (
	// ReviewedOpUnset is the invalid zero value: no review stated the semantics. It is never
	// read-only, and a live_execution request that leaves it unset is refused at creation —
	// an approval that may authorize a real side effect must say what it reviewed.
	ReviewedOpUnset ReviewedOperationClass = iota
	// ReviewedOpReadOnly — the review determined this exact capability does not mutate state
	// at the upstream, for ANY admissible invocation of it. This is the ONLY value that can
	// make a tools/call read-first.
	ReviewedOpReadOnly
	// ReviewedOpMutating — the review determined this exact capability can change state (or
	// could not determine that it does not, which is the same answer). It is the honest
	// classification for a tool whose effect depends on its arguments.
	ReviewedOpMutating
)

// String returns a stable wire label.
func (c ReviewedOperationClass) String() string {
	switch c {
	case ReviewedOpReadOnly:
		return "read_only"
	case ReviewedOpMutating:
		return "mutating"
	default:
		return "unset"
	}
}

// ParseReviewedOperationClass resolves a wire label. An unknown label returns
// (ReviewedOpUnset, false) so the caller fails closed rather than guessing — in particular,
// a typo must never land on read_only.
func ParseReviewedOperationClass(s string) (ReviewedOperationClass, bool) {
	switch s {
	case "read_only":
		return ReviewedOpReadOnly, true
	case "mutating":
		return ReviewedOpMutating, true
	default:
		return ReviewedOpUnset, false
	}
}

// Stated reports whether a review actually answered the question. It is the predicate the
// live-request path requires: an approval that may authorize a real upstream side effect
// must carry an explicit determination, in either direction.
func (c ReviewedOperationClass) Stated() bool {
	return c == ReviewedOpReadOnly || c == ReviewedOpMutating
}

// ReadOnly reports whether the review determined this exact capability is non-mutating. It is
// the ONE positive predicate in this file, written once so no consumer re-derives it as
// `!= ReviewedOpMutating` — which would read an UNSET class as read-only and invert the
// fail-closed default.
func (c ReviewedOperationClass) ReadOnly() bool { return c == ReviewedOpReadOnly }
