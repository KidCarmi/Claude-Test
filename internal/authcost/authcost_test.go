package authcost

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// newTestGate builds a gate whose wait deadline is driven by the caller rather
// than by the clock, so every timeout assertion below is deterministic. The
// house rule (connlimit, threatfeed, socks5) is that a regression gate must
// not be able to flake on a shared runner.
func newTestGate(t *testing.T, maxConcurrent, maxPerClient int) (gate *Gate, fireTimer chan time.Time) {
	t.Helper()
	fire := make(chan time.Time, 64)
	g := New(maxConcurrent, maxPerClient, time.Hour)
	g.newTimer = func(time.Duration) (<-chan time.Time, func() bool) {
		return fire, func() bool { return true }
	}
	return g, fire
}

func mustAdmit(t *testing.T, g *Gate, client string) {
	t.Helper()
	if r, _ := g.Admit(client); r != Admitted {
		t.Fatalf("Admit(%q) = %v, want Admitted", client, r)
	}
}

// ── The bound that did not exist ────────────────────────────────────────────

// DEFECT GATE. The pre-fix path had no ceiling at all: every concurrent
// request ran its own bcrypt. This is the property that stops a credential
// flood from consuming the whole machine, so it is asserted directly on the
// only observable that matters — how many verifications can be in flight.
func TestCeilingBoundsConcurrentVerifications(t *testing.T) {
	const ceiling = 3
	// DISTINCT clients throughout, so the per-client rule never binds and the
	// only thing under test is the global ceiling.
	g, fire := newTestGate(t, ceiling, 1)

	for i := 0; i < ceiling; i++ {
		mustAdmit(t, g, fmt.Sprintf("client-%d", i))
	}
	if got := g.Stats().InFlight; got != ceiling {
		t.Fatalf("InFlight = %d, want %d", got, ceiling)
	}

	// One more, from a client with its own budget free: it can only be waiting
	// on the ceiling, and when its budget runs out it must be refused rather
	// than admitted past it.
	extra := make(chan Refusal, 1)
	go func() { r, _ := g.Admit("client-extra"); extra <- r }()
	waitForQueued(t, g, 1)
	if got := g.Stats().InFlight; got != ceiling {
		t.Fatalf("InFlight = %d while a caller waits, want %d — the ceiling was exceeded", got, ceiling)
	}
	fire <- time.Now()
	if r := <-extra; r == Admitted {
		t.Fatal("admitted past the global ceiling — credential verification is unbounded")
	}
}

// A released slot is reusable: the ceiling must bound concurrency, not total
// work. A gate that leaked slots would degrade into a permanent outage of the
// login path, which is worse than the defect it replaces.
func TestReleaseReturnsTheSlot(t *testing.T) {
	g, _ := newTestGate(t, 1, 1)

	mustAdmit(t, g, "a")
	if got := g.Stats().InFlight; got != 1 {
		t.Fatalf("InFlight after admit = %d, want 1", got)
	}
	g.Release("a")
	if got := g.Stats().InFlight; got != 0 {
		t.Fatalf("InFlight after release = %d, want 0 — the slot leaked", got)
	}
	// The freed slot is reusable on the FAST path (no queueing), which is what
	// proves it was actually returned rather than merely un-counted.
	mustAdmit(t, g, "b")
	if s := g.Stats(); s.Waited != 0 {
		t.Fatalf("Waited = %d, want 0: the second admit should not have needed the queue", s.Waited)
	}
	g.Release("b")
}

// ── Fairness: one source must not be able to hold the whole ceiling ─────────

// DEFECT GATE. Without the per-client rule the global ceiling contains the CPU
// but not the OUTAGE: a single flooding source occupies every slot and denies
// every other user. This asserts the property that makes the difference —
// after one client saturates its own budget, capacity remains for others.
func TestOneClientCannotOccupyEverySlot(t *testing.T) {
	g, fire := newTestGate(t, 4, DefaultMaxPerClient)

	mustAdmit(t, g, "flooder")

	// The flooder's SECOND concurrent request parks on its own budget — it is
	// not refused on the spot (see reserveClient) — so it never occupies a
	// second slot while the first is outstanding.
	second := make(chan Refusal, 1)
	go func() { r, _ := g.Admit("flooder"); second <- r }()
	waitForQueued(t, g, 1)

	// THE PROPERTY: three slots remain, and they are available to everybody
	// else even while the flooder is waiting for more.
	for _, c := range []string{"alice", "bob", "carol"} {
		mustAdmit(t, g, c)
	}
	if got := g.Stats().InFlight; got != 4 {
		t.Fatalf("InFlight = %d, want 4 — the flooder took a slot it should have had to wait for", got)
	}

	// And when its wait runs out it is refused by the FAIRNESS rule, not by the
	// global one: the two reasons point at different operator actions.
	fire <- time.Now()
	if r := <-second; r != RefusedPerClient {
		t.Fatalf("the flooder's parked request = %v, want RefusedPerClient", r)
	}
}

// The fairness reservation must be released on EVERY refusal path, not just on
// Release. A leaked reservation would permanently bar a client that once hit a
// queue-full or timeout refusal — a self-inflicted denial of service that only
// shows up under the load the gate exists to survive.
func TestRefusalDoesNotLeakTheClientReservation(t *testing.T) {
	t.Run("queue_full", func(t *testing.T) {
		g, _ := newTestGate(t, 1, 1)
		mustAdmit(t, g, "holder")
		g.maxWaiters = 0 // force the queue-full branch
		if r, _ := g.Admit("victim"); r != RefusedQueueFull {
			t.Fatalf("Admit = %v, want RefusedQueueFull", r)
		}
		g.Release("holder")
		mustAdmit(t, g, "victim") // would fail if the reservation leaked
	})

	t.Run("timeout", func(t *testing.T) {
		g, fire := newTestGate(t, 1, 1)
		mustAdmit(t, g, "holder")
		done := make(chan Refusal, 1)
		go func() { r, _ := g.Admit("victim"); done <- r }()
		waitForQueued(t, g, 1)
		fire <- time.Now()
		if r := <-done; r != RefusedTimeout {
			t.Fatalf("Admit = %v, want RefusedTimeout", r)
		}
		g.Release("holder")
		mustAdmit(t, g, "victim") // would fail if the reservation leaked
	})

	t.Run("per_client", func(t *testing.T) {
		g, fire := newTestGate(t, 4, 1)
		mustAdmit(t, g, "c")
		done := make(chan Refusal, 1)
		go func() { r, _ := g.Admit("c"); done <- r }()
		waitForQueued(t, g, 1)
		fire <- time.Now()
		if r := <-done; r != RefusedPerClient {
			t.Fatalf("Admit = %v, want RefusedPerClient", r)
		}
		g.Release("c")
		mustAdmit(t, g, "c") // the refusal must not have consumed a second unit
	})
}

// ── The bounded queue ───────────────────────────────────────────────────────

// A legitimate burst waits rather than being refused: graceful degradation is
// the house preference, and refusing a valid credential because two other
// people happened to log in at the same moment is a real availability cost.
func TestAWaiterIsAdmittedWhenASlotFrees(t *testing.T) {
	g, _ := newTestGate(t, 1, 1)
	mustAdmit(t, g, "holder")

	got := make(chan Refusal, 1)
	go func() { r, _ := g.Admit("waiter"); got <- r }()
	waitForQueued(t, g, 1)

	g.Release("holder")
	if r := <-got; r != Admitted {
		t.Fatalf("queued waiter = %v, want Admitted", r)
	}
	if s := g.Stats(); s.Waited != 1 {
		t.Fatalf("Waited = %d, want 1 (the leading indicator must count the queueing)", s.Waited)
	}
}

// CONTROL. The queue must itself be bounded. An unbounded one would trade the
// CPU-exhaustion vector for a goroutine/memory one — the attacker simply parks
// waiters instead of burning cores — so "it absorbs bursts" must not mean "it
// absorbs anything".
func TestQueueIsBounded(t *testing.T) {
	g, fire := newTestGate(t, 1, 1)
	mustAdmit(t, g, "holder")

	// Distinct clients, because the per-client rule (correctly) stops any one
	// of them from filling the queue on its own.
	var wg sync.WaitGroup
	results := make(chan Refusal, g.maxWaiters)
	for i := 0; i < g.maxWaiters; i++ {
		c := fmt.Sprintf("waiter-%d", i)
		wg.Add(1)
		go func() { defer wg.Done(); r, _ := g.Admit(c); results <- r }()
	}
	waitForQueued(t, g, g.maxWaiters)

	// The queue is now full; the next arrival must be refused immediately
	// rather than joining it. An unbounded queue would let an attacker park
	// goroutines for free — the same exhaustion in a different resource.
	if r, _ := g.Admit("one-too-many"); r != RefusedQueueFull {
		t.Fatalf("Admit with a full queue = %v, want RefusedQueueFull", r)
	}

	// Drain: release every waiter through the timeout branch, then confirm the
	// queue is empty again and a newcomer is admitted on the fast path.
	for i := 0; i < g.maxWaiters; i++ {
		fire <- time.Now()
	}
	for i := 0; i < g.maxWaiters; i++ {
		if r := <-results; r != RefusedTimeout {
			t.Fatalf("drained waiter = %v, want RefusedTimeout", r)
		}
	}
	wg.Wait()
	g.Release("holder")
	mustAdmit(t, g, "after")
}

// ── Bookkeeping ─────────────────────────────────────────────────────────────

// The per-client map must not grow with the number of distinct keys ever seen.
// An unbounded map keyed by an attacker-supplied value is the defect this
// codebase has closed repeatedly (WK-12's dedup map, topHosts, the auth result
// cache); the governor must not reintroduce it.
func TestPerClientMapDoesNotGrowWithDistinctKeys(t *testing.T) {
	g, _ := newTestGate(t, 2, 1)
	for i := 0; i < 10_000; i++ {
		c := fmt.Sprintf("client-%d", i)
		if r, _ := g.Admit(c); r == Admitted {
			g.Release(c)
		}
	}
	g.mu.Lock()
	n := len(g.perClient)
	g.mu.Unlock()
	if n != 0 {
		t.Fatalf("perClient retained %d entries after every caller released; want 0", n)
	}
}

// Refusals are counted BY REASON, because the three point at different
// operator actions: per_client is one noisy source, queue_full/timeout is
// genuine capacity. A single undifferentiated counter would make the alert
// unactionable.
func TestRefusalsAreCountedByReason(t *testing.T) {
	g, fire := newTestGate(t, 1, 1)
	mustAdmit(t, g, "holder")

	perClient := make(chan Refusal, 1)
	go func() { r, _ := g.Admit("holder"); perClient <- r }()
	waitForQueued(t, g, 1)
	fire <- time.Now()
	if r := <-perClient; r != RefusedPerClient {
		t.Fatalf("got %v", r)
	}
	done := make(chan Refusal, 1)
	go func() { r, _ := g.Admit("waiter"); done <- r }()
	waitForQueued(t, g, 1)
	fire <- time.Now()
	<-done

	g.maxWaiters = 0
	if r, _ := g.Admit("third"); r != RefusedQueueFull {
		t.Fatalf("got %v", r)
	}

	s := g.Stats()
	if s.RefusedPerClient != 1 || s.RefusedTimeout != 1 || s.RefusedQueueFull != 1 {
		t.Fatalf("per_client=%d timeout=%d queue_full=%d, want 1/1/1",
			s.RefusedPerClient, s.RefusedTimeout, s.RefusedQueueFull)
	}
	if s.Refusals() != 3 {
		t.Fatalf("Refusals() = %d, want 3", s.Refusals())
	}
}

// Peak marks survive the incident. A contract row that can only read "right
// now" would report a fully-drained gate as healthy minutes after an episode
// that denied hundreds of authentications.
func TestPeaksSurviveTheIncident(t *testing.T) {
	g, _ := newTestGate(t, 2, 2)
	mustAdmit(t, g, "a")
	mustAdmit(t, g, "a")
	g.Release("a")
	g.Release("a")
	if got := g.Stats().PeakInFlight; got != 2 {
		t.Fatalf("PeakInFlight = %d, want 2", got)
	}
	if got := g.Stats().InFlight; got != 0 {
		t.Fatalf("InFlight = %d, want 0", got)
	}
}

// ── Construction ────────────────────────────────────────────────────────────

// A misconfigured gate must never degrade into one that admits everything.
// New's fallbacks are the fail-closed half of the contract.
func TestNewNeverBuildsAnUnboundedGate(t *testing.T) {
	for _, tc := range []struct{ maxC, maxP int }{{0, 0}, {-1, -1}, {0, 99}} {
		g := New(tc.maxC, tc.maxP, 0)
		if g.maxConcurrent <= 0 {
			t.Fatalf("New(%d,%d) built maxConcurrent=%d", tc.maxC, tc.maxP, g.maxConcurrent)
		}
		if g.maxPerClient > g.maxConcurrent {
			t.Fatalf("New(%d,%d): per-client ceiling %d exceeds the global %d — a bound that cannot bind",
				tc.maxC, tc.maxP, g.maxPerClient, g.maxConcurrent)
		}
		if g.maxWait <= 0 {
			t.Fatalf("New(%d,%d) built maxWait=%v", tc.maxC, tc.maxP, g.maxWait)
		}
	}
}

// The default ceiling must leave the machine capacity to do its actual job.
// A ceiling of GOMAXPROCS bounds the fault without preventing the outage.
func TestDefaultCeilingLeavesHeadroom(t *testing.T) {
	k := DefaultMaxConcurrent()
	if k < 1 {
		t.Fatalf("DefaultMaxConcurrent() = %d, must be at least 1", k)
	}
	if p := runtime.GOMAXPROCS(0); k > p/2 && p > 1 {
		t.Fatalf("DefaultMaxConcurrent() = %d on GOMAXPROCS=%d — credential verification may occupy more than half the machine", k, p)
	}
}

// A Release without a matching Admit must not deadlock the authentication
// path. It is defensive rather than expected, which is exactly why it needs a
// gate: the failure mode of getting it wrong is a hung proxy.
func TestUnmatchedReleaseDoesNotBlock(t *testing.T) {
	g, _ := newTestGate(t, 1, 1)
	done := make(chan struct{})
	go func() { g.Release("nobody"); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Release without Admit blocked — the auth path would hang")
	}
	mustAdmit(t, g, "a") // the ceiling must be intact
}

// ── helpers ─────────────────────────────────────────────────────────────────

// waitForQueued blocks until exactly n callers are parked in the wait queue.
// Polling on the gate's own accounting keeps the concurrent tests
// synchronisation-driven rather than sleep-driven.
func waitForQueued(t *testing.T, g *Gate, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		q := g.queued
		g.mu.Unlock()
		if q == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d queued callers", n)
}

// The EMPTY key means "the peer could not be identified", not "a client". It
// is exempt from the per-client rule so that a deployment whose client-address
// resolution is misconfigured loses FAIRNESS rather than being denied
// authentication wholesale — the outage class this engine exists to prevent,
// caused by the engine.
//
// It is NOT exempt from the global ceiling, which is the bound that actually
// caps CPU. Both halves are asserted, because only the pair is safe.
func TestEmptyClientKeyIsExemptFromFairnessButNotFromTheCeiling(t *testing.T) {
	g, _ := newTestGate(t, 3, 1)

	// Fairness: several unidentified callers must not contend with each other.
	for i := 0; i < 3; i++ {
		if r, _ := g.Admit(""); r != Admitted {
			t.Fatalf("unidentified caller %d = %v, want Admitted — the empty bucket is throttling unrelated requests", i, r)
		}
	}
	// Ceiling: the fourth must still be bounded, not admitted.
	g.maxWaiters = 0
	if r, _ := g.Admit(""); r == Admitted {
		t.Fatal("the empty key escaped the GLOBAL ceiling — credential verification is unbounded for unidentified peers")
	}

	// And releasing must be symmetric: no reservation was taken, so none may be
	// returned. A mismatch here leaks the fairness budget for real clients.
	for i := 0; i < 3; i++ {
		g.Release("")
	}
	g.mu.Lock()
	n := len(g.perClient)
	g.mu.Unlock()
	if n != 0 {
		t.Fatalf("perClient holds %d entries after only empty-key traffic", n)
	}
	if got := g.Stats().InFlight; got != 0 {
		t.Fatalf("InFlight = %d after releasing every empty-key admission, want 0", got)
	}
}

// DEFECT GATE, raised against this engine's own first shape.
//
// The per-client rule originally REFUSED a client that was already at its cap,
// on the spot. That is wrong, and the measurement is unambiguous: a single
// workstation opening its normal parallel connection pool — six requests whose
// cached results expired together — had FIVE of six VALID credentials denied,
// with no attacker anywhere and no flood in progress. A governor built to stop
// an attacker denying service was denying it on its own.
//
// The fix is that a client at its cap WAITS for its own earlier verification
// instead of being refused. Fairness is untouched: the cap still bounds how
// many slots one source holds AT ONCE. Only the excess changes — serialised
// behind its predecessor rather than rejected.
func TestClientAtItsCapWaitsRatherThanBeingRefused(t *testing.T) {
	// Real (short) deadline: the point is that the waiters get through on a
	// release, long before any deadline is reached.
	g := New(2, 1, 5*time.Second)

	const n = 6
	var wg sync.WaitGroup
	results := make(chan Refusal, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := g.Admit("one-workstation")
			results <- r
			if r == Admitted {
				g.Release("one-workstation")
			}
		}()
	}
	wg.Wait()
	close(results)

	admitted := 0
	for r := range results {
		if r != Admitted {
			t.Errorf("a concurrent request from one client was refused: %v", r)
			continue
		}
		admitted++
	}
	if admitted != n {
		t.Fatalf("%d/%d concurrent requests from ONE client were admitted; the rest were denied valid service", admitted, n)
	}
	if s := g.Stats(); s.Refusals() != 0 {
		t.Fatalf("Refusals() = %d, want 0", s.Refusals())
	}
}

// CONTROL for the gate above. Waiting must not mean the cap stopped binding:
// at no instant may one client hold more slots than its cap allows. Asserted
// by holding the cap and requiring the in-flight count to stay put while
// another request from the same client is parked.
func TestWaitingDoesNotWidenThePerClientCap(t *testing.T) {
	g, fire := newTestGate(t, 4, 1)
	mustAdmit(t, g, "c")

	parked := make(chan Refusal, 1)
	go func() { r, _ := g.Admit("c"); parked <- r }()
	waitForQueued(t, g, 1)

	if got := g.Stats().InFlight; got != 1 {
		t.Fatalf("InFlight = %d while one client is parked on its own cap, want 1 — the cap stopped binding", got)
	}
	fire <- time.Now()
	if r := <-parked; r != RefusedPerClient {
		t.Fatalf("parked request = %v, want RefusedPerClient", r)
	}
}
