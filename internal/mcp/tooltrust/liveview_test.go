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

// TestLiveView_SnapshotHoldsClonesNotStoredPointers pins the reason the snapshot clones. Mutators
// edit records IN PLACE, so publishing the stored pointers would let a lock-free reader observe a
// half-applied mutation.
func TestLiveView_SnapshotHoldsClonesNotStoredPointers(t *testing.T) {
	s, now := liveViewStore(t)
	snap := s.ActiveLiveApprovals(now)
	if len(snap) != 1 {
		t.Fatalf("premise: want one approval, got %d", len(snap))
	}
	s.mu.Lock()
	stored := s.byID[snap[0].ApprovalID]
	s.mu.Unlock()
	if stored == snap[0] {
		t.Fatal("SECURITY: the lock-free view aliases the STORED record — an in-place mutation " +
			"(Reject sets a.Status on the live pointer) would be observable half-applied")
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
