package lockout

import (
	"sync"
	"testing"
)

// FE-6A.0 correction (Blocker 4): the fenced reset decides against the
// lock-set generation UNDER the limiter lock, so of N administrators who
// listed the same state and reset concurrently exactly ONE clears it; the
// rest are told the set moved (stale) and mutate nothing.
func TestResetUserIfGeneration_ConcurrentResetsExactlyOneWins(t *testing.T) {
	l := NewLoginLimiter()
	for range MaxAttempts {
		l.RecordFailure("198.51.100.9", "victim")
	}
	gen := l.Generation()
	const n = 16
	var wg sync.WaitGroup
	results := make([]ResetStatus, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = l.ResetUserIfGeneration("victim", gen)
		}(i)
	}
	wg.Wait()
	ok, stale, nf := 0, 0, 0
	for _, r := range results {
		switch r {
		case ResetOK:
			ok++
		case ResetStale:
			stale++
		case ResetNotFound:
			nf++
		}
	}
	if ok != 1 || stale != n-1 || nf != 0 {
		t.Fatalf("ok=%d stale=%d notfound=%d, want exactly one winner and %d stale", ok, stale, nf, n-1)
	}
	if locked, _ := l.Check("198.51.100.9", "victim"); locked {
		t.Fatal("the winning reset must have cleared the lock")
	}
	if l.Generation() <= gen {
		t.Fatal("a successful reset must advance the generation")
	}
}

func TestResetUserIfGeneration_StaleAfterAnyMutationAndNotFoundOnUnknown(t *testing.T) {
	l := NewLoginLimiter()
	l.RecordFailure("198.51.100.10", "alice")
	gen := l.Generation()
	l.RecordSuccess("198.51.100.10", "alice") // removes the pair → generation moves
	if st, cur := l.ResetUserIfGeneration("alice", gen); st != ResetStale || cur <= gen {
		t.Fatalf("reset with an observed generation after a success = %v (cur %d), want stale", st, cur)
	}
	gen = l.Generation()
	if st, cur := l.ResetUserIfGeneration("nobody", gen); st != ResetNotFound || cur != gen {
		t.Fatalf("reset of an unknown user = %v (cur %d), want not_found with an unchanged generation", st, cur)
	}
	l.RecordFailure("198.51.100.11", "bob")
	gen = l.Generation()
	l.Cleanup() // nothing removable yet → no move
	if l.Generation() != gen {
		t.Fatal("a cleanup that removed nothing must not move the generation")
	}
}
