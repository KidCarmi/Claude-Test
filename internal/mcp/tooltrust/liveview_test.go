package tooltrust

import (
	"errors"
	"os"
	"testing"
	"time"
)

const liveViewTenant = "tenant-a"

var errLiveViewDisk = errors.New("no space left on device")

// liveViewStore builds a store holding exactly one ACTIVE live-execution approval, plus the
// instant it is active at.
func liveViewStore(t *testing.T) (*Store, time.Time) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	in.Purpose = PurposeLiveExecution
	exp := clk.t.Add(time.Hour)
	in.ExpiresAt = &exp
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("create live request: %v", err)
	}
	if _, err := s.Approve(a.ApprovalID, "approver@corp", matchingTarget(in)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	return s, clk.now()
}

// liveview_test.go — the lock-free live-approval read snapshot.
//
// ActiveLiveApprovals is consulted on the live-execution admission path, INSIDE the Canary
// activation critical section. That section also latches automatic aborts and gates demotion, so a
// read that can block on this store's mutex puts a stuck disk in front of the controls whose job is
// to stop the experiment. Every mutation here holds mu across persistLocked's atomic file write,
// so the read must not take mu at all.

// TestLiveView_ActiveLiveApprovalsTakesNoStoreLock is STRUCTURAL, not timing-based: it holds the
// store's write lock and requires the read to answer anyway. Deterministic on any hardware, under
// any load, with or without -race — a ratio or latency gate here would flake and get muted.
func TestLiveView_ActiveLiveApprovalsTakesNoStoreLock(t *testing.T) {
	s, now := liveViewStore(t)
	if got := s.ActiveLiveApprovals(now); len(got) != 1 {
		t.Fatalf("premise: want exactly one active live approval, got %d", len(got))
	}

	s.mu.Lock()
	done := make(chan int, 1)
	go func() { done <- len(s.ActiveLiveApprovals(now)) }()
	select {
	case n := <-done:
		s.mu.Unlock()
		if n != 1 {
			t.Fatalf("read under a held write lock returned %d approvals, want 1", n)
		}
	case <-time.After(5 * time.Second):
		s.mu.Unlock()
		t.Fatal("SECURITY (§5): ActiveLiveApprovals BLOCKED on the store mutex. Every mutation " +
			"holds that mutex across persistLocked's file write, so this read now couples the " +
			"Canary activation critical section — automatic abort, demotion, generation " +
			"revalidation — to disk health")
	}
}

// TestLiveView_EveryMutatorRepublishes is the invariant that makes the snapshot safe to trust.
// A mutator that does not republish is a SECURITY failure, not a staleness one: a revoked approval
// that keeps authorizing live execution. The publish lives at the single commit chokepoint
// (persistLocked, plus Load), so this drives each mutator end to end rather than asserting on the
// call site.
func TestLiveView_EveryMutatorRepublishes(t *testing.T) {
	s, now := liveViewStore(t)

	// CreateRequest + Approve, via persistLocked.
	live := s.ActiveLiveApprovals(now)
	if len(live) != 1 {
		t.Fatalf("Approve did not republish: the lock-free view serves %d live approvals, want 1",
			len(live))
	}
	id := live[0].ApprovalID

	// Load. This assertion is deliberately for a PRESENT approval, not an absent one: a store
	// that never publishes serves an empty view, so "expect 0" would pass against exactly the
	// defect. A recovered store that cannot serve its restored grants would leave every approval
	// silently unable to authorize execution until the next admin write.
	s2, err := NewStore(Config{Path: s.path, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s2.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := s2.ActiveLiveApprovals(now); len(got) != 1 {
		t.Fatalf("Load did not republish: a RECOVERED store serves %d live approvals, want 1 — "+
			"every restored grant would be unable to authorize execution", len(got))
	}

	// Revoke, via persistLocked.
	if _, err := s.Revoke(id, "admin2", liveViewTenant, "no longer needed"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := s.ActiveLiveApprovals(now); len(got) != 0 {
		t.Fatalf("SECURITY: a REVOKED live approval is still served by the lock-free view (%d "+
			"entries) — it would keep authorizing live execution", len(got))
	}
}

// TestLiveView_SnapshotHoldsClonesNotStoredPointers pins the reason the PUBLISHED SNAPSHOT clones,
// which is a separate invariant from the one below and is no longer observable through
// ActiveLiveApprovals — that now clones on the way out, so it would mask this.
//
// The lock-free reader walks the snapshot calling activeLiveAsOf, which reads Status and ExpiresAt,
// BEFORE any outbound copy is made. If the snapshot aliased the stored records, those reads would
// race an in-place mutation under the store lock (Reject sets a.Status on the live pointer) — a
// reader could see a half-applied transition and admit against it. So the snapshot is inspected
// directly here rather than through the accessor.
func TestLiveView_SnapshotHoldsClonesNotStoredPointers(t *testing.T) {
	s, now := liveViewStore(t)
	if got := s.ActiveLiveApprovals(now); len(got) != 1 {
		t.Fatalf("premise: want one active live approval, got %d", len(got))
	}

	view := s.liveView.Load()
	if view == nil || len(*view) == 0 {
		t.Fatal("premise: the published snapshot must be non-empty")
	}
	s.mu.Lock()
	stored := s.byID
	s.mu.Unlock()

	for _, a := range *view {
		if stored[a.ApprovalID] == a {
			t.Fatalf("SECURITY: the published snapshot ALIASES the stored record %q — the "+
				"lock-free filter reads Status and ExpiresAt off these pointers, so an in-place "+
				"mutation under the store lock would race it and a reader could admit against a "+
				"half-applied transition", a.ApprovalID)
		}
	}
}

// TestLiveView_ReturnedRecordsAreCallerOwned pins that a caller mutating a returned approval
// cannot affect any later read. The snapshot's entries are already copies of the stored records, so
// the store itself is safe either way — but handing out the SNAPSHOT's pointers would let one
// caller's mutation change the target or status every other reader sees, for every admission and
// preflight, until the next publication. The pre-snapshot implementation cloned per call; this
// keeps that contract (Codex round 23).
func TestLiveView_ReturnedRecordsAreCallerOwned(t *testing.T) {
	s, now := liveViewStore(t)
	first := s.ActiveLiveApprovals(now)
	if len(first) != 1 {
		t.Fatalf("premise: want one active live approval, got %d", len(first))
	}
	original := first[0].ToolName

	first[0].ToolName = "mutated-by-a-caller"
	first[0].Status = StatusRevoked

	second := s.ActiveLiveApprovals(now)
	if len(second) != 1 {
		t.Fatalf("SECURITY: a caller's mutation removed an approval from every later read (%d "+
			"remain) — the view is handing out shared records", len(second))
	}
	if second[0].ToolName != original {
		t.Fatalf("SECURITY: a caller's mutation changed the tool a later read authorizes against "+
			"(%q, want %q) — the view is handing out shared records", second[0].ToolName, original)
	}
	if second[0] == first[0] {
		t.Fatal("SECURITY: two reads returned the SAME record pointer")
	}
}

// TestLiveView_PersistFailureDoesNotPublish pins durable-before-effect: a mutation whose durable
// write failed is reverted in memory, and must not be visible through the lock-free view either.
func TestLiveView_PersistFailureDoesNotPublish(t *testing.T) {
	s, now := liveViewStore(t)
	live := s.ActiveLiveApprovals(now)
	if len(live) != 1 {
		t.Fatalf("premise: want one approval, got %d", len(live))
	}
	s.writeFile = func(string, []byte, os.FileMode) error { return errLiveViewDisk }
	if _, err := s.Revoke(live[0].ApprovalID, "admin2", liveViewTenant, "disk is broken"); err == nil {
		t.Fatal("premise: the revoke must fail when the durable write fails")
	}
	if got := s.ActiveLiveApprovals(now); len(got) != 1 {
		t.Fatalf("a revoke whose durable write FAILED was published to the lock-free view "+
			"(%d entries) — the in-memory state was reverted, so the view must be too", len(got))
	}
}
