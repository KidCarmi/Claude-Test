package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mcp_canary_reviewed_durable_test.go — §11 durable-state compatibility for the activation's
// reviewed-target snapshot.
//
// The snapshot is only worth having if it SURVIVES. An activation may outlive several restarts
// (and, on the ceiling, six days of them), so a reviewed set that is lost, silently defaulted, or
// half-decoded on the way back would reopen exactly the blind spot it was added to close.
//
// The governing rule, stated once and applied by every case below:
//
//	an ACTIVE durable record that cannot prove — from its own bytes — what it was reviewed to
//	execute does not restore executable authority.
//
// "Cannot prove" deliberately includes the benign-looking case: a record written by a build that
// predates the field is not malicious and not corrupt, but it still cannot answer the question,
// so it does not come back armed. Fail-closed here costs one operator re-activation; fail-open
// costs an activation that is blind to a rug-pull for the rest of its window.

// durableRecord reads the on-disk activation record.
func durableRecord(t *testing.T, capb rollout.Capability) canaryRuntimeState {
	t.Helper()
	raw, err := os.ReadFile(canaryRuntimeStatePath(capb)) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read durable record: %v", err)
	}
	var st canaryRuntimeState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("decode durable record: %v", err)
	}
	return st
}

// writeDurableRecord replaces the on-disk activation record.
func writeDurableRecord(t *testing.T, capb rollout.Capability, st canaryRuntimeState) {
	t.Helper()
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("encode durable record: %v", err)
	}
	if err := os.WriteFile(canaryRuntimeStatePath(capb), raw, 0o600); err != nil {
		t.Fatalf("write durable record: %v", err)
	}
}

// armForDurability arms a real activation and returns the runtime, capability and generation.
func armForDurability(t *testing.T) (*canaryRuntime, rollout.Capability, uint64) {
	t.Helper()
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	gen, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(10),
		ReviewedTargets: []canary.ReviewedTarget{testReviewedTarget()},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("begin activation: %v", err)
	}
	return rt, capb, gen
}

// restartRuntime replaces the process runtime with a fresh one restored from disk — the whole of
// what a restart does to this subsystem.
func restartRuntime(t *testing.T) *canaryRuntime {
	t.Helper()
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	return fresh
}

// assertNotExecutable proves a restored record carries no execution authority, while the
// monotonic generation is preserved so a fresh activation can never reuse a stale one's number.
func assertNotExecutable(t *testing.T, rt *canaryRuntime, capb rollout.Capability, priorGen uint64, why string) {
	t.Helper()
	if rt.armed(capb) {
		t.Fatalf("SECURITY: %s must NOT restore an armed activation", why)
	}
	if rt.executionEligible(capb, canaryRuntimeTestNow) {
		t.Fatalf("SECURITY: %s must NOT restore execution eligibility", why)
	}
	if set, ok := rt.activeReviewedTargets(capb); ok || !set.Empty() {
		t.Fatalf("SECURITY: %s must leave no reviewed set behind (ok=%v n=%d)", why, ok, set.Len())
	}
	if got := rt.currentGeneration(capb); got < priorGen {
		t.Fatalf("the monotonic generation must not go backwards: got %d, prior %d", got, priorGen)
	}
}

// ── the healthy control ──────────────────────────────────────────────────────────────────────
// A CURRENT, valid record restores the EXACT reviewed set — not a default, not a subset. Without
// this the fail-closed cases below would be satisfied by a restore that never works.
func TestReviewedDurable_ValidRecordRestoresTheExactSet(t *testing.T) {
	rt, capb, gen := armForDurability(t)
	before, ok := rt.activeReviewedTargets(capb)
	if !ok {
		t.Fatal("premise: the armed activation must expose its reviewed set")
	}

	fresh := restartRuntime(t)
	if !fresh.armed(capb) {
		t.Fatal("a valid active record must come back armed")
	}
	if fresh.currentGeneration(capb) != gen {
		t.Fatalf("generation = %d, want the persisted %d", fresh.currentGeneration(capb), gen)
	}
	after, ok := fresh.activeReviewedTargets(capb)
	if !ok {
		t.Fatal("the restored activation must expose its reviewed set")
	}
	if !after.Equal(before) {
		t.Fatalf("the restored reviewed set differs from the persisted one:\n before %+v\n after  %+v",
			before.Targets(), after.Targets())
	}
	// And it is genuinely the deciding record after the restart, not merely readable.
	if v := after.Compare(reviewedAt(fpF2)); v != canary.ReviewedFingerprintDrift {
		t.Fatalf("the restored set must still detect drift, got %q", v)
	}
}

// ── an old record, written before the field existed ──────────────────────────────────────────
// This is the compatibility case the specification calls out by name. Two shapes reach it, and
// BOTH must stay non-executable.
func TestReviewedDurable_OldRecordWithoutReviewedTargetsIsNotExecutable(t *testing.T) {
	t.Run("same schema version, field absent", func(t *testing.T) {
		// The shape a hand-edited or partially-written record has: everything else intact.
		rt, capb, gen := armForDurability(t)
		st := durableRecord(t, capb)
		st.ReviewedTargets = nil
		writeDurableRecord(t, capb, st)
		_ = rt
		assertNotExecutable(t, restartRuntime(t), capb, gen, "an active record with no reviewed-target set")
	})

	t.Run("previous schema version", func(t *testing.T) {
		// The shape a genuinely older BUILD wrote: schema 1, which had no reviewed set at all.
		// The schema fence catches it before any field is trusted, and the record is quarantined.
		rt, capb, _ := armForDurability(t)
		st := durableRecord(t, capb)
		st.SchemaVersion = canaryRuntimeSchemaVersion - 1
		st.ReviewedTargets = nil
		writeDurableRecord(t, capb, st)
		_ = rt
		assertNotExecutable(t, restartRuntime(t), capb, 0, "a record from a previous schema version")
		if _, err := os.Stat(canaryRuntimeStatePath(capb)); !os.IsNotExist(err) {
			t.Fatal("a schema-mismatched record must be quarantined, not left in place to be re-read")
		}
	})
}

// A record from a FUTURE schema is refused for the same reason and in the same direction: this
// build cannot know what a later one meant by those bytes, and guessing would be the one mistake
// that grants authority.
func TestReviewedDurable_UnknownFutureSchemaIsNotExecutable(t *testing.T) {
	rt, capb, _ := armForDurability(t)
	st := durableRecord(t, capb)
	st.SchemaVersion = canaryRuntimeSchemaVersion + 7
	writeDurableRecord(t, capb, st)
	_ = rt
	assertNotExecutable(t, restartRuntime(t), capb, 0, "a record from an unknown future schema")
}

// ── a record whose reviewed set no longer canonicalizes ──────────────────────────────────────
// Persistence is not validation. Bytes on disk can say things the activation path would have
// refused, so the restore re-runs the SAME canonicalization rather than trusting the file — and a
// set that fails it does not come back armed. Each shape here is one the activation path rejects.
func TestReviewedDurable_NonCanonicalReviewedSetIsNotExecutable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets []canary.ReviewedTarget
	}{
		{"duplicate entries", []canary.ReviewedTarget{testReviewedTarget(), testReviewedTarget()}},
		{"ambiguous entries", []canary.ReviewedTarget{reviewedAt(fpF1), reviewedAt(fpF2)}},
		{"unknown fingerprint format", []canary.ReviewedTarget{func() canary.ReviewedTarget {
			x := testReviewedTarget()
			x.FingerprintFormat = 0 // no format ⇒ nothing says how to compare the digest
			return x
		}()}},
		{"zero fingerprint", []canary.ReviewedTarget{func() canary.ReviewedTarget {
			x := testReviewedTarget()
			x.Fingerprint = tooltrustZeroDigest()
			return x
		}()}},
		{"missing server identity", []canary.ReviewedTarget{func() canary.ReviewedTarget {
			x := testReviewedTarget()
			x.ServerIdentity = ""
			return x
		}()}},
		{"incomplete identity", []canary.ReviewedTarget{func() canary.ReviewedTarget {
			x := testReviewedTarget()
			x.ServerID = ""
			return x
		}()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, capb, gen := armForDurability(t)
			st := durableRecord(t, capb)
			st.ReviewedTargets = tc.targets
			writeDurableRecord(t, capb, st)
			_ = rt
			assertNotExecutable(t, restartRuntime(t), capb, gen, "an active record whose reviewed set does not canonicalize")
		})
	}
}

// ── a corrupt record ─────────────────────────────────────────────────────────────────────────
// Strict decode: an unknown field, or bytes that are not a record at all, is quarantined rather
// than partially applied. A half-decoded activation would have a generation and a budget but no
// reviewed set — authority without the evidence that bounds it.
func TestReviewedDurable_CorruptRecordIsQuarantined(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"unknown field", `{"schema_version":2,"capability":"gateway","generation":1,"active":true,"reviewed_targets":[],"smuggled":true}`},
		{"reviewed targets wrong type", `{"schema_version":2,"capability":"gateway","generation":1,"active":true,"reviewed_targets":"all of them"}`},
		{"not json", `{{{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
			capb := rollout.CapabilityGateway
			if err := os.WriteFile(canaryRuntimeStatePath(capb), []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_ = rt
			assertNotExecutable(t, restartRuntime(t), capb, 0, "a corrupt record")
		})
	}
}

// ── a record from a different build ──────────────────────────────────────────────────────────
// The reviewed set says WHAT was reviewed; the build identity says what code was reviewed to
// execute it. A record from another build disarms regardless of how well-formed its reviewed set
// is — and the set must not be left behind either, or a later activation could inherit it.
func TestReviewedDurable_BuildIdentityMismatchDropsTheReviewedSet(t *testing.T) {
	rt, capb, gen := armForDurability(t)
	st := durableRecord(t, capb)
	if len(st.ReviewedTargets) == 0 {
		t.Fatal("premise: the record must carry a reviewed set")
	}
	st.BuildVersion = "v0.0.0-some-other-build+deadbeef"
	writeDurableRecord(t, capb, st)
	_ = rt
	assertNotExecutable(t, restartRuntime(t), capb, gen, "a record from a different build")
}

// ── restart after the Canary aborted ─────────────────────────────────────────────────────────
// An abort is a latch, and a restart is not a way out of it. The reviewed set comes back with the
// record — the activation still knows what it was reviewed for — but nothing executes.
func TestReviewedDurable_RestartAfterAbortStaysStopped(t *testing.T) {
	rt, capb, gen := armForDurability(t)
	if res := rt.tripCanaryAbortForGeneration(capb, gen, "tool_fingerprint_drift", canaryRuntimeTestNow); res != canary.TripCanaryLatched {
		t.Fatalf("premise: the abort must latch the whole Canary, got %s", res)
	}
	fresh := restartRuntime(t)
	if !fresh.abortedNow(capb) {
		t.Fatal("SECURITY: a latched abort must survive a restart")
	}
	if fresh.executionEligible(capb, canaryRuntimeTestNow) {
		t.Fatal("SECURITY: an aborted activation must not become executable again by restarting")
	}
	if code := fresh.abortCodeNow(capb); code != "tool_fingerprint_drift" {
		t.Fatalf("the first cause must survive the restart, got %q", code)
	}
	// The evidence of what it was reviewed for survives too: the restored record can still say
	// why it stopped, which is what an operator needs to act on it.
	if set, ok := fresh.activeReviewedTargets(capb); !ok || set.Len() != 1 {
		t.Fatalf("the reviewed set must survive an abort (ok=%v n=%d)", ok, set.Len())
	}
}

// ── restart after the approval expired ───────────────────────────────────────────────────────
// The closing case, and the one the whole change is for: the reviewed set is durable state of the
// ACTIVATION, so it is entirely unaffected by an approval that has since expired. A restart deep
// into the window restores an activation that can still tell a drifted target from an
// unauthorized one — which is precisely what the approval store can no longer do.
func TestReviewedDurable_RestartAfterApprovalExpiryKeepsDriftDetectable(t *testing.T) {
	rt, capb, gen := armForDurability(t)
	_ = rt
	// Well past canary.MaxInitialCanaryApprovalTTL, still inside canary.FirstCanaryMaxWindowCeiling:
	// the window in which the old approval-pinned inference had nothing left to read.
	late := canaryRuntimeTestNow.Add(72 * time.Hour)
	if late.Sub(canaryRuntimeTestNow) <= canary.MaxInitialCanaryApprovalTTL {
		t.Fatal("premise: the instant under test must be past the maximum approval lifetime")
	}

	fresh := restartRuntime(t)
	set, ok := fresh.activeReviewedTargets(capb)
	if !ok {
		t.Fatal("the restored activation must still carry its reviewed set")
	}
	if fresh.currentGeneration(capb) != gen {
		t.Fatalf("generation = %d, want %d", fresh.currentGeneration(capb), gen)
	}
	if v := set.Compare(reviewedAt(fpF2)); v != canary.ReviewedFingerprintDrift {
		t.Fatalf("SECURITY: after a restart past the approval's lifetime the activation must STILL "+
			"detect that its reviewed tool moved, got %q. If this ever returns 'matches' or "+
			"'out of scope', drift detection has gone back to expiring with the approval", v)
	}
	if v := set.Compare(testReviewedTarget()); v != canary.ReviewedMatches {
		t.Fatalf("the unchanged reviewed target must still match after the restart, got %q", v)
	}
}
