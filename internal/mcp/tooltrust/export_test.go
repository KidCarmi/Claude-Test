package tooltrust

// export_test.go — hooks that exist only for this package's tests.
//
// They live here rather than in store.go so they are compiled ONLY into the test binary: a
// production type should not carry an exported mutex-manipulation API just because a test needs
// one, and an exported method whose whole purpose is testing invites a caller that has no business
// taking this lock.

// LockForTest takes the store mutex so a test can prove that a reader which must never block on it
// does not (see TestLiveView_ActiveLiveApprovalsTakesNoStoreLock).
func (s *Store) LockForTest() { s.mu.Lock() }

// UnlockForTest releases the mutex taken by LockForTest.
func (s *Store) UnlockForTest() { s.mu.Unlock() }
