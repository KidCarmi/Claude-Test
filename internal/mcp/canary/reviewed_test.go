package canary

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// Unit tests for the PURE reviewed-target engine. The end-to-end behaviour — that an activation
// decides drift against this record rather than against an approval, and that the record survives
// restarts — is proven in the root package; what is proven here is the algebra those gates stand
// on: what canonicalizes, what is refused, and what each comparison verdict means.

func rfp(b byte) tooltrust.FingerprintDigest { return tooltrust.FingerprintDigest{b} }

func target(tenant, server, tool string, f byte, identity string) ReviewedTarget {
	return ReviewedTarget{
		Tenant: tenant, ServerID: server, ToolName: tool,
		Fingerprint: rfp(f), FingerprintFormat: 1, ServerIdentity: identity,
	}
}

func canonical(t *testing.T, in ...ReviewedTarget) ReviewedTargetSet {
	t.Helper()
	set, reason := CanonicalizeReviewedTargets(in)
	if reason != ReviewedOK {
		t.Fatalf("expected these targets to canonicalize, got %s", reason)
	}
	return set
}

// Every rejection is a NAMED reason, and the set is empty on every one of them: a caller that
// ignored the reason must not be handed a partially-accepted set to arm from.
func TestCanonicalizeReviewedTargets_RejectionsAreNamedAndEmpty(t *testing.T) {
	ok := target("t1", "s1", "tool", 0xF1, "spiffe://x/s1")
	for _, tc := range []struct {
		name string
		in   []ReviewedTarget
		want ReviewedReason
	}{
		{"nil", nil, ReviewedEmpty},
		{"empty", []ReviewedTarget{}, ReviewedEmpty},
		{"no tenant", []ReviewedTarget{func() ReviewedTarget { x := ok; x.Tenant = ""; return x }()}, ReviewedIncompleteID},
		{"no server", []ReviewedTarget{func() ReviewedTarget { x := ok; x.ServerID = ""; return x }()}, ReviewedIncompleteID},
		{"no tool", []ReviewedTarget{func() ReviewedTarget { x := ok; x.ToolName = ""; return x }()}, ReviewedIncompleteID},
		{"zero fingerprint", []ReviewedTarget{func() ReviewedTarget {
			x := ok
			x.Fingerprint = tooltrust.FingerprintDigest{}
			return x
		}()}, ReviewedZeroFingerprint},
		{"zero format", []ReviewedTarget{func() ReviewedTarget { x := ok; x.FingerprintFormat = 0; return x }()}, ReviewedBadFormat},
		{"no server identity", []ReviewedTarget{func() ReviewedTarget { x := ok; x.ServerIdentity = ""; return x }()}, ReviewedNoServerIdentity},
		{"identical duplicate", []ReviewedTarget{ok, ok}, ReviewedDuplicate},
		{"disagreeing duplicate", []ReviewedTarget{ok, target("t1", "s1", "tool", 0xF2, "spiffe://x/s1")}, ReviewedAmbiguous},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, reason := CanonicalizeReviewedTargets(tc.in)
			if reason != tc.want {
				t.Fatalf("reason = %s, want %s", reason, tc.want)
			}
			if !set.Empty() || set.Len() != 0 {
				t.Fatalf("a rejected input must yield an EMPTY set, got %d entries", set.Len())
			}
		})
	}
}

// Ambiguity is REFUSED, never resolved by ordering. Two different answers to "what was reviewed"
// is exactly the condition that must not be settled by which one happened to come last.
func TestCanonicalizeReviewedTargets_AmbiguityIsNotOrderDependent(t *testing.T) {
	a := target("t1", "s1", "tool", 0xF1, "spiffe://x/s1")
	b := target("t1", "s1", "tool", 0xF2, "spiffe://x/s1")
	if _, r := CanonicalizeReviewedTargets([]ReviewedTarget{a, b}); r != ReviewedAmbiguous {
		t.Fatalf("a,b ⇒ %s, want %s", r, ReviewedAmbiguous)
	}
	if _, r := CanonicalizeReviewedTargets([]ReviewedTarget{b, a}); r != ReviewedAmbiguous {
		t.Fatalf("b,a ⇒ %s, want %s — 'last one wins' would make the reviewed set depend on the "+
			"order the caller happened to resolve its scope in", r, ReviewedAmbiguous)
	}
	// The same tool on a DIFFERENT server is a different key, not ambiguity.
	if _, r := CanonicalizeReviewedTargets([]ReviewedTarget{a, target("t1", "s2", "tool", 0xF2, "spiffe://x/s2")}); r != ReviewedOK {
		t.Fatalf("distinct (tenant,server,tool) keys must coexist, got %s", r)
	}
}

func TestCanonicalizeReviewedTargets_RejectsMoreThanTheBound(t *testing.T) {
	in := make([]ReviewedTarget, 0, MaxReviewedTargets+1)
	for i := 0; i <= MaxReviewedTargets; i++ {
		in = append(in, target("t1", "s1", string(rune('a'+i)), 0xF1, "spiffe://x/s1"))
	}
	if _, r := CanonicalizeReviewedTargets(in); r != ReviewedTooMany {
		t.Fatalf("reason = %s, want %s", r, ReviewedTooMany)
	}
}

// The canonical order is deterministic, so an activation's persisted bytes do not depend on the
// order its scope happened to resolve in — which is what lets two nodes, or one node before and
// after a restart, compare records at all. MaxReviewedTargets is small by design
// (MaxCanaryTenants x MaxCanaryTools), so the largest legal set is what is ordered here.
func TestCanonicalizeReviewedTargets_OrderIsDeterministic(t *testing.T) {
	first := target("t1", "s1", "a", 0xF1, "id1")
	second := target("t1", "s1", "b", 0xF1, "id1")
	forward := canonical(t, first, second)
	reverse := canonical(t, second, first)
	if !forward.Equal(reverse) {
		t.Fatalf("canonical order is input-dependent:\n %+v\n %+v", forward.Targets(), reverse.Targets())
	}
	got := forward.Targets()
	if len(got) != 2 || got[0].ToolName != "a" || got[1].ToolName != "b" {
		t.Fatalf("unexpected canonical order: %+v", got)
	}
	// Ordering is by tenant, then server, then tool — proven one key at a time, because a sort that
	// happened to agree on this input for the wrong reason would still be input-dependent on another.
	bySrv := canonical(t, target("t1", "s2", "a", 0xF1, "id2"), target("t1", "s1", "z", 0xF1, "id1")).Targets()
	if bySrv[0].ServerID != "s1" {
		t.Fatalf("server must outrank tool name in the canonical order: %+v", bySrv)
	}
	byTenant := canonical(t, target("t2", "s1", "a", 0xF1, "id1"), target("t1", "s2", "z", 0xF1, "id2")).Targets()
	if byTenant[0].Tenant != "t1" {
		t.Fatalf("tenant must outrank server in the canonical order: %+v", byTenant)
	}
}

// Targets() hands back a COPY. The set is the activation's immutable memory of what it was
// reviewed for; a caller that could reach into the backing array could rewrite that memory in
// place, which is the whole class of defect this type exists to make unrepresentable.
func TestReviewedTargetSet_TargetsIsACopy(t *testing.T) {
	set := canonical(t, target("t1", "s1", "tool", 0xF1, "id"))
	out := set.Targets()
	out[0].Fingerprint = rfp(0xF2)
	if v := set.Compare(target("t1", "s1", "tool", 0xF2, "id")); v != ReviewedFingerprintDrift {
		t.Fatalf("mutating the returned slice changed the set: compare ⇒ %q", v)
	}
	if v := set.Compare(target("t1", "s1", "tool", 0xF1, "id")); v != ReviewedMatches {
		t.Fatalf("the original reviewed target must still match, got %q", v)
	}
}

func TestReviewedTargetSet_CompareVerdicts(t *testing.T) {
	set := canonical(t, target("t1", "s1", "tool", 0xF1, "spiffe://x/s1"))
	for _, tc := range []struct {
		name string
		cur  ReviewedTarget
		want ReviewedVerdict
	}{
		{"exact", target("t1", "s1", "tool", 0xF1, "spiffe://x/s1"), ReviewedMatches},
		{"fingerprint moved", target("t1", "s1", "tool", 0xF2, "spiffe://x/s1"), ReviewedFingerprintDrift},
		{"identity moved", target("t1", "s1", "tool", 0xF1, "spiffe://x/other"), ReviewedServerIdentityDrift},
		// INVERTED (Codex P1, PR #1360, round 4). This case asserted ReviewedOutOfScope, and in
		// doing so pinned the defect: the lookup key is (tenant, server, tool), so a reviewed pair
		// reassigned A→B misses the key and falls through to "not in the reviewed set", which is
		// deliberately silent. The reviewed target would have crossed a tenancy boundary with
		// nothing recorded, and reassigning it back later would let the original activation resume.
		// A genuinely unrelated target is still out of scope — the two cases below.
		{"same server and tool, another tenant", target("t2", "s1", "tool", 0xF1, "spiffe://x/s1"), ReviewedTenantDrift},
		{"another server", target("t1", "s2", "tool", 0xF1, "spiffe://x/s1"), ReviewedOutOfScope},
		{"another tool", target("t1", "s1", "other", 0xF1, "spiffe://x/s1"), ReviewedOutOfScope},
		// A CURRENT target reporting NO identity is drift, not a match.
		//
		// The reviewed side can never be empty — CanonicalizeReviewedTargets refuses
		// ReviewedNoServerIdentity, pinned above — so the "" == "" match that would make an
		// identity rotation invisible is unreachable from a canonical set. This is the other
		// half: a current read that yields "" (a registry path that bypassed the Add-time
		// rejection, an unpublished pin) must be charged as drift rather than quietly comparing
		// equal to something. The code already does this, because "" != the reviewed identity;
		// what was missing was anything holding it there.
		{"current reports no identity", target("t1", "s1", "tool", 0xF1, ""), ReviewedServerIdentityDrift},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if v := set.Compare(tc.cur); v != tc.want {
				t.Fatalf("verdict = %q, want %q", v, tc.want)
			}
		})
	}
}

// When BOTH moved, the identity is reported. The tool definition and the workload serving it are
// different facts, and the catalog's composite fingerprint folds the identity in — so a
// fingerprint-first ordering would report every identity rotation as a schema change and send an
// operator looking in the wrong place.
func TestReviewedTargetSet_IdentityDriftOutranksFingerprintDrift(t *testing.T) {
	set := canonical(t, target("t1", "s1", "tool", 0xF1, "spiffe://x/s1"))
	if v := set.Compare(target("t1", "s1", "tool", 0xF2, "spiffe://x/other")); v != ReviewedServerIdentityDrift {
		t.Fatalf("verdict = %q, want %q", v, ReviewedServerIdentityDrift)
	}
}

// The fingerprint FORMAT is part of the comparison: the same 32 bytes computed under a different
// scheme are not the same fingerprint, and treating them as equal would silently accept a target
// whose digest was never the reviewed one.
func TestReviewedTargetSet_FormatIsPartOfTheFingerprint(t *testing.T) {
	set := canonical(t, target("t1", "s1", "tool", 0xF1, "id"))
	cur := target("t1", "s1", "tool", 0xF1, "id")
	cur.FingerprintFormat = 2
	if v := set.Compare(cur); v != ReviewedFingerprintDrift {
		t.Fatalf("verdict = %q, want %q", v, ReviewedFingerprintDrift)
	}
}

// The zero-value set — what a disarmed or never-armed runtime holds — matches NOTHING. It is the
// fail-closed default the whole design rests on: an activation that cannot say what it was
// reviewed for authorizes nothing, and reports it request-scoped rather than as a breach.
func TestReviewedTargetSet_ZeroValueMatchesNothing(t *testing.T) {
	var zero ReviewedTargetSet
	if !zero.Empty() || zero.Len() != 0 {
		t.Fatal("the zero value must be empty")
	}
	if v := zero.Compare(target("t1", "s1", "tool", 0xF1, "id")); v != ReviewedOutOfScope {
		t.Fatalf("verdict = %q, want %q — an empty set matching anything would hand a disarmed "+
			"runtime execution authority", v, ReviewedOutOfScope)
	}
	if zero.Targets() != nil && len(zero.Targets()) != 0 {
		t.Fatal("the zero value must expose no targets")
	}
}

func TestReviewedTargetSet_Equal(t *testing.T) {
	a := canonical(t, target("t1", "s1", "tool", 0xF1, "id"))
	same := canonical(t, target("t1", "s1", "tool", 0xF1, "id"))
	fpMoved := canonical(t, target("t1", "s1", "tool", 0xF2, "id"))
	idMoved := canonical(t, target("t1", "s1", "tool", 0xF1, "other"))
	bigger := canonical(t, target("t1", "s1", "tool", 0xF1, "id"), target("t1", "s2", "tool", 0xF1, "id2"))
	if !a.Equal(same) {
		t.Fatal("identical sets must compare equal")
	}
	for name, other := range map[string]ReviewedTargetSet{
		"fingerprint": fpMoved, "identity": idMoved, "size": bigger, "empty": {},
	} {
		if a.Equal(other) {
			t.Fatalf("sets differing by %s must NOT compare equal — the same-generation immutability "+
				"check is exactly this comparison", name)
		}
	}
}
