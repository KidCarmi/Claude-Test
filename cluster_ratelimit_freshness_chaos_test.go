package main

// CHAOS-57 gates — the Data Plane's cluster rate-limit broadcast under a
// Control Plane outage.
//
// The defect: clusterCountStore.Apply is reached ONLY from the DP gossip loop's
// success branch, so a failed SyncRateLimits left the last broadcast frozen in
// the map for the rest of the process lifetime while AllowClusterAware kept
// adding it to every local count. An IP whose remote total was at or near the
// limit when the CP went away was denied on this node PERMANENTLY.
//
// Every DEFECT gate below (StaleBroadcast*, FrozenBroadcast*) was verified
// failing against the pre-fix shape — clusterCounts.Get(ip) with no expiry — and
// the CONTROL gates exist because the cheapest way to pass the defect gates is
// to stop consulting remote counts at all, which would silently delete the
// distributed rate limiter.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// withClusterRateLimiter installs a fresh limiter + clean freshness state for
// one test and restores the globals afterwards.
func withClusterRateLimiter(t *testing.T, limit int, window time.Duration) {
	t.Helper()
	oldRL := rl
	oldArmed := clusterRateLimitEnabled.Load()
	rl = newRateLimiter()
	rl.Configure(limit, window)
	clusterRateLimitEnabled.Store(true)
	resetClusterRateLimitFreshnessForTest()
	t.Cleanup(func() {
		rl = oldRL
		clusterRateLimitEnabled.Store(oldArmed)
		resetClusterRateLimitFreshnessForTest()
	})
}

// ── Defect gates ────────────────────────────────────────────────────────────

// TestChaos57_StaleBroadcastNoLongerDeniesForever is THE defect gate. A
// broadcast that put an IP at the limit, then aged past the rate-limit window,
// must stop denying that IP. Pre-fix this loops false forever.
func TestChaos57_StaleBroadcastNoLongerDeniesForever(t *testing.T) {
	const limit = 10
	window := time.Minute
	withClusterRateLimiter(t, limit, window)

	const ip = "198.51.100.7"
	// The Control Plane's last word before it went away: this IP had already
	// used the whole cluster-wide budget on OTHER nodes.
	clusterCounts.applyAtForTest(map[string]int{ip: limit}, time.Now())
	if rl.AllowClusterAware(ip) {
		t.Fatal("a CURRENT broadcast at the limit must deny — the distributed limit is not working")
	}

	// The CP goes away. No further Apply ever happens; the broadcast ages.
	clusterCounts.applyAtForTest(map[string]int{ip: limit}, time.Now().Add(-window-time.Second))

	for i := 0; i < 5; i++ {
		if !rl.AllowClusterAware(ip) {
			t.Fatalf("request %d denied by a broadcast older than the %s window: "+
				"the node is enforcing a frozen snapshot of the past", i+1, window)
		}
	}
}

// TestChaos57_FrozenBroadcastDoesNotShrinkTheLocalBudget covers the quieter
// half of the same defect: even a remote count well BELOW the limit permanently
// shrinks this node's local allowance once it can no longer be refreshed.
func TestChaos57_FrozenBroadcastDoesNotShrinkTheLocalBudget(t *testing.T) {
	const limit = 10
	window := time.Minute
	withClusterRateLimiter(t, limit, window)

	const ip = "198.51.100.8"
	clusterCounts.applyAtForTest(map[string]int{ip: limit / 2}, time.Now().Add(-window-time.Second))

	allowed := 0
	for i := 0; i < limit; i++ {
		if rl.AllowClusterAware(ip) {
			allowed++
		}
	}
	if allowed != limit {
		t.Fatalf("allowed %d of %d requests; a stale remote count is still consuming the local budget", allowed, limit)
	}
}

// ── Control gates ───────────────────────────────────────────────────────────

// TestChaos57_FreshBroadcastStillSuppresses is the control for the two defect
// gates: on a HEALTHY cluster the distributed limit must behave exactly as it
// did before. A "fix" that simply ignored remote counts passes every defect
// gate above and fails here.
func TestChaos57_FreshBroadcastStillSuppresses(t *testing.T) {
	const limit = 10
	window := time.Minute
	withClusterRateLimiter(t, limit, window)

	const ip = "198.51.100.9"
	remote := 6
	clusterCounts.applyAtForTest(map[string]int{ip: remote}, time.Now())

	allowed := 0
	for i := 0; i < limit; i++ {
		if rl.AllowClusterAware(ip) {
			allowed++
		}
	}
	if allowed != limit-remote {
		t.Fatalf("allowed %d requests with a fresh remote count of %d and limit %d; want %d — "+
			"the distributed rate limiter is no longer suppressing", allowed, remote, limit, limit-remote)
	}
}

// TestChaos57_BroadcastAppliesForTheWholeWindow pins the boundary from the
// other side: a broadcast is honoured right up to the window, not clipped early
// by a shorter ad-hoc constant.
func TestChaos57_BroadcastAppliesForTheWholeWindow(t *testing.T) {
	const limit = 10
	window := time.Minute
	withClusterRateLimiter(t, limit, window)

	const ip = "198.51.100.10"
	clusterCounts.applyAtForTest(map[string]int{ip: limit}, time.Now().Add(-window/2))
	if rl.AllowClusterAware(ip) {
		t.Fatalf("a broadcast %s old was ignored inside a %s window — the distributed limit expires too early", window/2, window)
	}
}

// TestChaos57_MaxAgeIsDerivedFromTheLimiterWindow proves the expiry rule tracks
// the live limiter rather than a hardcoded minute: a longer window must keep a
// broadcast applicable for longer.
func TestChaos57_MaxAgeIsDerivedFromTheLimiterWindow(t *testing.T) {
	const limit = 10
	window := 10 * time.Minute
	withClusterRateLimiter(t, limit, window)

	const ip = "198.51.100.11"
	// Five minutes old: stale under a one-minute window, fresh under this one.
	clusterCounts.applyAtForTest(map[string]int{ip: limit}, time.Now().Add(-5*time.Minute))
	if rl.AllowClusterAware(ip) {
		t.Fatal("a 5m-old broadcast was ignored under a 10m window — the max-age is not derived from the limiter")
	}

	if got, want := clusterRemoteCountMaxAge(window), window; got != want {
		t.Fatalf("clusterRemoteCountMaxAge(%s) = %s, want %s", window, got, want)
	}
	if got := clusterRemoteCountMaxAge(0); got != clusterRemoteCountFallbackMaxAge {
		t.Fatalf("clusterRemoteCountMaxAge(0) = %s, want the %s fallback", got, clusterRemoteCountFallbackMaxAge)
	}
}

// TestChaos57_NeverAppliedBroadcastContributesNothing covers the cold-start
// node: no broadcast has ever landed, so there is nothing to add.
func TestChaos57_NeverAppliedBroadcastContributesNothing(t *testing.T) {
	withClusterRateLimiter(t, 10, time.Minute)
	if got := clusterCounts.FreshCount("203.0.113.5", time.Now(), time.Minute); got != 0 {
		t.Fatalf("FreshCount on a node that never received a broadcast = %d, want 0", got)
	}
	st := clusterRateLimitFreshness()
	if st.Applied {
		t.Fatal("Applied is true with no broadcast ever received")
	}
	if !st.Stale {
		t.Fatal("a node with no broadcast must report stale — the remote half contributes nothing")
	}
	if got := clusterRateLimitBroadcastAgeMetric(st); got != -1 {
		t.Fatalf("broadcast age metric = %g with no broadcast, want -1 (0 would read as 'just landed')", got)
	}
}

// TestChaos57_ClockRollbackDegradesToLocal pins the fail-toward-local direction
// for a negative age: honouring a future-stamped broadcast would extend its life
// by however far the clock moved back.
func TestChaos57_ClockRollbackDegradesToLocal(t *testing.T) {
	const limit = 10
	withClusterRateLimiter(t, limit, time.Minute)

	const ip = "203.0.113.6"
	clusterCounts.applyAtForTest(map[string]int{ip: limit}, time.Now().Add(2*time.Hour))
	st := clusterRateLimitFreshness()
	if !st.Stale {
		t.Fatal("a future-stamped broadcast (clock rollback) must be treated as stale")
	}
	if !rl.AllowClusterAware(ip) {
		t.Fatal("a future-stamped broadcast is still suppressing traffic")
	}
}

// ── Freshness reporting ─────────────────────────────────────────────────────

// TestChaos57_StaleEpisodeIsCountedOncePerEpisode proves the transition is
// reported per EPISODE, not per gossip tick — the gossip loop calls this every
// 5s, so a per-tick counter would report an hour-long outage as 720 episodes.
func TestChaos57_StaleEpisodeIsCountedOncePerEpisode(t *testing.T) {
	withClusterRateLimiter(t, 10, time.Minute)

	clusterCounts.applyAtForTest(map[string]int{}, time.Now().Add(-2*time.Minute))
	for i := 0; i < 12; i++ { // one minute of gossip ticks during the outage
		noteClusterRateLimitFreshness(clusterRateLimitFreshness())
	}
	if got := clusterRLStaleEpisodes.Load(); got != 1 {
		t.Fatalf("stale episodes after 12 ticks of one outage = %d, want 1", got)
	}

	// The CP comes back: a fresh broadcast lands and the next tick clears.
	clusterCounts.Apply(map[string]int{})
	noteClusterRateLimitFreshness(clusterRateLimitFreshness())
	if got := clusterRLStaleEpisodes.Load(); got != 1 {
		t.Fatalf("recovery changed the episode count to %d, want 1", got)
	}

	// A SECOND outage is a second episode.
	clusterCounts.applyAtForTest(map[string]int{}, time.Now().Add(-2*time.Minute))
	noteClusterRateLimitFreshness(clusterRateLimitFreshness())
	if got := clusterRLStaleEpisodes.Load(); got != 2 {
		t.Fatalf("stale episodes after a second outage = %d, want 2", got)
	}
}

// TestChaos57_FreshnessIsEvaluatedNotLatched proves recovery needs no explicit
// clearing path: the state is derived from the stamp on every read, so a gossip
// loop that stops running entirely still reports the truth to /metrics.
func TestChaos57_FreshnessIsEvaluatedNotLatched(t *testing.T) {
	withClusterRateLimiter(t, 10, time.Minute)

	clusterCounts.applyAtForTest(map[string]int{}, time.Now().Add(-2*time.Minute))
	if !clusterRateLimitFreshness().Stale {
		t.Fatal("an aged broadcast is not reported stale")
	}
	// No noteClusterRateLimitFreshness call at all — nothing to clear.
	clusterCounts.Apply(map[string]int{})
	if clusterRateLimitFreshness().Stale {
		t.Fatal("freshness stayed stale after a new broadcast landed — the state is latched, not evaluated")
	}
}

// TestChaos57_MetricsOnlyOnAnArmedNode pins the emission rule: `remote_stale 0`
// on a standalone proxy that never had a Control Plane is indistinguishable
// from a healthy clustered node, and the paging rule is `== 1`.
func TestChaos57_MetricsOnlyOnAnArmedNode(t *testing.T) {
	withClusterRateLimiter(t, 10, time.Minute)

	clusterRateLimitEnabled.Store(false)
	if body := renderMetrics(t); strings.Contains(body, "culvert_cluster_ratelimit_remote_stale") {
		t.Fatal("cluster rate-limit gauges emitted on a node where cluster rate limiting is not armed")
	}

	clusterRateLimitEnabled.Store(true)
	clusterCounts.applyAtForTest(map[string]int{}, time.Now().Add(-2*time.Minute))
	body := renderMetrics(t)
	if !strings.Contains(body, "culvert_cluster_ratelimit_remote_stale 1") {
		t.Fatalf("armed + stale did not render remote_stale 1:\n%s", extractClusterRLMetrics(body))
	}
	if !strings.Contains(body, "culvert_cluster_ratelimit_stale_episodes_total") {
		t.Fatal("stale-episode counter missing from the exposition")
	}
	if !strings.Contains(body, "culvert_cluster_ratelimit_broadcast_age_seconds") {
		t.Fatal("broadcast-age gauge missing from the exposition")
	}
}

func extractClusterRLMetrics(body string) string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "cluster_ratelimit") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// ── Concurrency ─────────────────────────────────────────────────────────────

// TestChaos57_FreshCountRacesApply runs the hot-path reader against the gossip
// writer under -race: the stamp is an atomic outside the mutex, so the
// publication order (map under the lock, stamp after) has to be correct.
func TestChaos57_FreshCountRacesApply(t *testing.T) {
	withClusterRateLimiter(t, 100, time.Minute)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				clusterCounts.Apply(map[string]int{"203.0.113.9": 1})
			}
		}
	}()
	for i := 0; i < 2000; i++ {
		_ = clusterCounts.FreshCount("203.0.113.9", time.Now(), time.Minute)
		_ = clusterRateLimitFreshness()
	}
	close(stop)
	wg.Wait()
}

// ── The DP→CP audit push queue ──────────────────────────────────────────────

// TestChaos57_AuditPushQueueOverflowIsCounted is the second defect gate. The
// bound is correct; the silence was not. Pre-fix there is no counter at all.
func TestChaos57_AuditPushQueueOverflowIsCounted(t *testing.T) {
	restore := audit.ResetPendingForTest()
	defer restore()

	const overflow = 250
	for i := 0; i < audit.MaxPendingForTest()+overflow; i++ {
		audit.QueueForClusterForTest(audit.Entry{Action: "policy.add"})
	}
	if got := audit.PendingDrops(); got != int64(overflow) {
		t.Fatalf("PendingDrops = %d after overflowing the queue by %d, want %d — "+
			"the centralized audit trail loses entries with no counter", got, overflow, overflow)
	}
	if got := len(audit.Drain()); got != audit.MaxPendingForTest() {
		t.Fatalf("queue held %d entries, want the cap %d", got, audit.MaxPendingForTest())
	}
}

// TestChaos57_AuditRequeueOverflowIsCounted covers the path an actual CP outage
// takes: Drain, push fails, Requeue — repeatedly. The requeued (older) events
// are the ones discarded, and that loss must be charged too.
func TestChaos57_AuditRequeueOverflowIsCounted(t *testing.T) {
	restore := audit.ResetPendingForTest()
	defer restore()

	queueCap := audit.MaxPendingForTest()
	for i := 0; i < queueCap; i++ {
		audit.QueueForClusterForTest(audit.Entry{Action: "policy.add", Object: "old"})
	}
	events := audit.Drain()
	if audit.PendingDrops() != 0 {
		t.Fatalf("drops charged before any overflow: %d", audit.PendingDrops())
	}
	// New activity arrives while the push is in flight, then the push fails.
	const fresh = 40
	for i := 0; i < fresh; i++ {
		audit.QueueForClusterForTest(audit.Entry{Action: "policy.add", Object: "new"})
	}
	audit.Requeue(events)

	if got := audit.PendingDrops(); got != fresh {
		t.Fatalf("PendingDrops after a failed push = %d, want %d", got, fresh)
	}
	// The trim keeps the newest: every "new" entry survived, and exactly the
	// oldest unsent history was discarded.
	held := audit.Drain()
	if len(held) != queueCap {
		t.Fatalf("queue held %d entries, want the cap %d", len(held), queueCap)
	}
	newest := held[len(held)-1]
	if newest.Object != "new" {
		t.Fatalf("newest retained entry Object = %q, want %q (the trim must keep the newest)", newest.Object, "new")
	}
}

// TestChaos57_AuditPushDropsSurfaceOnHealthz pins the operator surface: the
// field appears only when non-zero, so an unaffected node's /healthz body is
// byte-identical to before.
func TestChaos57_AuditPushDropsSurfaceOnHealthz(t *testing.T) {
	restore := audit.ResetPendingForTest()
	defer restore()

	resp := map[string]any{}
	addRequestLogHealth(resp)
	if _, ok := resp["auditClusterPushDrops"]; ok {
		t.Fatal("auditClusterPushDrops present with zero drops — existing probe consumers see a changed body")
	}

	for i := 0; i < audit.MaxPendingForTest()+1; i++ {
		audit.QueueForClusterForTest(audit.Entry{Action: "policy.add"})
	}
	resp = map[string]any{}
	addRequestLogHealth(resp)
	if _, ok := resp["auditClusterPushDrops"]; !ok {
		t.Fatal("auditClusterPushDrops missing from /healthz after the push queue dropped entries")
	}
}
