package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// CHAOS-57 — the GeoIP resolution warmer and its health plane
//
// The per-request policy path (matchDestNorm → geo.LookupCached) must answer
// from cache only: it runs inside the request goroutine, holds the client
// connection and a per-IP connection slot while it runs, and has no deadline
// of its own. Filling those caches is therefore someone else's job, and this
// file is that someone.
//
// Three properties are load-bearing and must not be relaxed:
//
//  1. BOUNDED. net.LookupHost takes no context, so one resolution can run to
//     the system resolver's full budget (resolv.conf timeout × attempts ×
//     nameservers — commonly 10–40 s on a blackholed resolver). The bound is a
//     semaphore with DROP-ON-FULL, never a queue: a queue converts a resolver
//     outage into unbounded memory and unbounded staleness, whereas a drop
//     costs one host one warm window and is counted.
//
//     Deliberately NOT a context deadline. Under the cgo resolver a cancelled
//     lookup returns to the caller while the OS thread stays blocked in
//     getaddrinfo, so a deadline would release the semaphore slot without
//     releasing the thread — converting a bounded goroutine pool into an
//     unbounded thread pool, which is worse than the fault it treats. Holding
//     the slot for the TRUE duration of the call is what makes the bound real.
//
//  2. SINGLE-FLIGHTED. resolvedHostCache collapses concurrent misses for one
//     host into one resolution, and the warmer skips spawning entirely when a
//     resolution for that host is already in flight. Without this, a reconnect
//     storm against one host multiplies into one DNS query per request.
//
//  3. OBSERVABLE. A dropped warm means a country-scoped rule did not enforce
//     on that request. That is a security-relevant degradation, so it is
//     counted, exported, and logged on onset — never silent.
// ---------------------------------------------------------------------------

// geoWarmConcurrency bounds resolutions in flight for the policy warmer. It is
// deliberately far below the tracker's 256: the tracker samples every allowed
// request, while the warmer fires only on a cache MISS for a host a
// country-scoped rule actually asked about, and each slot can be held for tens
// of seconds by a blackholed resolver.
const geoWarmConcurrency = 64

// geoWarmLogInterval rate-limits the saturation log line: the FIRST drop of an
// episode logs immediately, then at most one line per interval, then one
// recovery line naming the count the gate suppressed. Same discipline as the
// SOCKS5 accept loop (socks5_health.go) — signal in the log, magnitude in the
// counter.
const geoWarmLogInterval = time.Minute

var geoWarmSem = make(chan struct{}, geoWarmConcurrency)

// geoWarmHook, when non-nil, is invoked as each warm goroutine exits (both the
// completed and the dropped path). Test-only, so a test can join the
// goroutines it caused; nil in production, where the only cost is one pointer
// compare off the request path.
var geoWarmHook func()

var geoWarm struct {
	started    atomic.Int64 // warms actually spawned
	inflight   atomic.Int64 // warm goroutines currently running
	dropped    atomic.Int64 // warms refused because the pool was saturated
	failed     atomic.Int64 // warms whose resolution yielded no usable public IP
	unresolved atomic.Int64 // country-rule evaluations that fell through on an unknown country

	mu         sync.Mutex
	logAt      time.Time
	suppressed int64
	saturated  bool
}

// warmGeoHost arms an off-path resolution + country lookup for host so that a
// later evaluation of a country-scoped rule can answer from cache.
//
// It never blocks the caller: a saturated pool drops the warm (counted), and a
// host already being resolved is skipped rather than queued behind itself.
func warmGeoHost(host string) {
	key := geoHostKey(host)
	if resolvedHostCache.resolving(key) {
		// A resolution is already in flight; a second goroutine would only
		// wait on it and then repeat a lookup the first one will perform.
		return
	}
	// Capture the semaphore rather than reading the global again on release:
	// a slot must always be returned to the channel it was taken from, so a
	// goroutine outliving a swap of geoWarmSem cannot release into a channel
	// it never acquired.
	sem := geoWarmSem
	select {
	case sem <- struct{}{}:
	default:
		geoWarm.dropped.Add(1)
		noteGeoWarmSaturated()
		if h := geoWarmHook; h != nil {
			h()
		}
		return
	}
	geoWarm.started.Add(1)
	geoWarm.inflight.Add(1)
	go func() {
		defer geoWarm.inflight.Add(-1)
		defer func() { <-sem }()
		if h := geoWarmHook; h != nil {
			defer h()
		}
		// Detached goroutine: no request-plane recover reaches here, and a
		// panic in the resolver seam must cost one warm, not the process.
		defer recoverGoroutine("geo-warm")
		noteGeoWarmProgress()
		ip := resolveHost(key)
		if ip == nil {
			geoWarm.failed.Add(1)
			return
		}
		// Populates the IP→country cache that the policy path reads. The
		// return value is deliberately discarded — the cache write is the
		// whole point of the call.
		geoLookupIPFn(ip)
	}()
}

// noteGeoCountryUnresolved records one country-scoped rule evaluation that
// could not be decided because the destination's country was unknown. The rule
// did NOT match (fail-closed), so on an allow-rule this is a user-visible
// block and on a deny-rule it is traffic that fell through to a lower-priority
// rule — either way it is the operator's only signal that a geo rule is
// evaluating against an unknown country. Hot path: one atomic add, no alloc,
// on the miss branch only.
func noteGeoCountryUnresolved() { geoWarm.unresolved.Add(1) }

// noteGeoWarmSaturated logs the onset of a saturation episode and rate-limits
// the rest of it.
func noteGeoWarmSaturated() {
	geoWarm.mu.Lock()
	now := time.Now()
	first := !geoWarm.saturated
	geoWarm.saturated = true
	if !first && now.Sub(geoWarm.logAt) < geoWarmLogInterval {
		geoWarm.suppressed++
		geoWarm.mu.Unlock()
		return
	}
	suppressed := geoWarm.suppressed
	geoWarm.suppressed = 0
	geoWarm.logAt = now
	geoWarm.mu.Unlock()

	if first {
		logger.Printf("GeoIP: resolution pool saturated (%d in flight) — country-scoped policy rules will not match hosts whose country is not yet cached", geoWarmConcurrency)
		return
	}
	logger.Printf("GeoIP: resolution pool still saturated — %d further warm requests dropped since the last line", suppressed)
}

// noteGeoWarmProgress clears the saturation state on OBSERVED evidence (a warm
// that actually got a slot), never on elapsed time — the same recovery
// discipline as storage_health.go and socks5_health.go.
func noteGeoWarmProgress() {
	geoWarm.mu.Lock()
	if !geoWarm.saturated {
		geoWarm.mu.Unlock()
		return
	}
	geoWarm.saturated = false
	suppressed := geoWarm.suppressed
	geoWarm.suppressed = 0
	geoWarm.mu.Unlock()
	logger.Printf("GeoIP: resolution pool recovered (%d warm requests were dropped while saturated)", suppressed)
}

// geoResolveHealth is the read model for /metrics and the diagnostics surface.
type geoResolveHealth struct {
	Started    int64
	Dropped    int64
	Failed     int64
	Unresolved int64
	Saturated  bool
	InFlight   int64
}

func geoResolveState() geoResolveHealth {
	geoWarm.mu.Lock()
	saturated := geoWarm.saturated
	geoWarm.mu.Unlock()
	return geoResolveHealth{
		Started:    geoWarm.started.Load(),
		Dropped:    geoWarm.dropped.Load(),
		Failed:     geoWarm.failed.Load(),
		Unresolved: geoWarm.unresolved.Load(),
		Saturated:  saturated,
		InFlight:   geoWarm.inflight.Load(),
	}
}

// swapGeoWarmSemForTest replaces the warm semaphore with a private one of
// capacity n and returns a restore func. Test support only: it gives a test
// that deliberately saturates the pool a channel no other test's in-flight
// goroutine can drain. Warms already running keep their own captured channel.
func swapGeoWarmSemForTest(n int) func() {
	orig := geoWarmSem
	geoWarmSem = make(chan struct{}, n)
	return func() { geoWarmSem = orig }
}

// resetGeoResolveHealthForTest isolates the process-global warm record between
// tests. Test support only.
func resetGeoResolveHealthForTest() {
	geoWarm.started.Store(0)
	geoWarm.dropped.Store(0)
	geoWarm.failed.Store(0)
	geoWarm.unresolved.Store(0)
	geoWarm.mu.Lock()
	geoWarm.logAt = time.Time{}
	geoWarm.suppressed = 0
	geoWarm.saturated = false
	geoWarm.mu.Unlock()
}
