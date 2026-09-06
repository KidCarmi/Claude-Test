// Package authcost is the admission governor for the ONE deliberately
// expensive operation on Culvert's per-request authentication path: the bcrypt
// comparison that validates a presented proxy credential against the local
// account. It is a self-contained stdlib-only leaf per ADR-0002.
//
// # Why this is its own engine
//
// bcrypt is expensive ON PURPOSE — that is the whole point of a password hash.
// At the cost factor Culvert stores (`bcrypt.DefaultCost`) one comparison
// measures **~80 ms of exclusive CPU** on the reference 4-core box. On a
// gateway that authenticates on EVERY request, that constant is not a
// property of the login form; it is a property of the data path, and it is
// reachable by anybody who can send the proxy a TCP connection.
//
// The pre-fix path had no bound on it of any kind:
//
//   - The wrong-username branch runs a comparison against a fixed dummy hash
//     (RISK-008 — so a wrong username is not distinguishable from a wrong
//     password by timing). That branch is reached BEFORE the result cache and
//     never populates it, so a flood of DISTINCT usernames is a guaranteed
//     cache miss every time.
//   - The three front-door limiters that would otherwise cap the arrival rate
//     — the per-IP connection limiter, the request rate limiter and the IP
//     filter — all ship DISABLED by default (`-rate-limit 0`, connlimit
//     disabled, no filter configured). In the shipped posture nothing at all
//     stood in front of this.
//   - Nothing capped CONCURRENCY, so N simultaneous requests put N goroutines
//     into bcrypt at once and the scheduler shared every core between them.
//
// Measured on the pre-fix tree (4 cores, `zz` probe reproduced as the defect
// gates in this package and in the root `auth_cost_chaos_test.go`):
//
//	one wrong-username attempt          79.6 ms of CPU
//	one cached successful auth           1.5 µs
//	amplification                       51,631x
//	rate that saturates all four cores  66 req/s  (~13 KB/s on the wire)
//	degradation to other CPU work       15.6x, at 64 attacker connections
//
// So ~13 KB/s of traffic from one unauthenticated source consumes 100% of a
// four-core gateway, and everything else the appliance must do per request —
// TLS handshakes, DPI scanning, policy evaluation, relay copying — is
// competing for what is left. That is a remotely triggerable denial of service
// against the data plane, in the DEFAULT configuration, requiring no
// credentials and no knowledge of the deployment.
//
// # The policy
//
// Two bounds, both fail-closed, and one fairness rule.
//
//  1. A GLOBAL CEILING on concurrent verifications, sized as a fraction of
//     GOMAXPROCS (see DefaultMaxConcurrent). Credential verification can
//     therefore never consume more than roughly half the machine, whatever the
//     arrival rate and however many distinct sources it comes from. This is
//     the bound that holds against a DISTRIBUTED flood, where no per-client
//     rule can help.
//
//  2. A PER-CLIENT CEILING (DefaultMaxPerClient = 1) on how many of those
//     slots one client key may occupy. Without it a single source could hold
//     every slot and the global ceiling would bound the CPU while still
//     denying every other user — the fault would be contained and the outage
//     would not. With it, one source can consume at most one slot's worth of
//     CPU and the remaining capacity stays available to everyone else. A
//     legitimate workstation authenticates serially, so it never notices; a
//     source with many verifications genuinely in flight at once is already
//     anomalous.
//
//  3. A BOUNDED WAIT (DefaultMaxWait) with a BOUNDED QUEUE (maxWaiters). A
//     legitimate burst — a fleet of clients whose cached results expired
//     together, a password rotation — is absorbed rather than refused, because
//     graceful degradation is the house preference. The queue is capped
//     because an unbounded one would convert a CPU-exhaustion vector into a
//     goroutine-and-memory one: an attacker who can park an unlimited number
//     of waiters for free has simply been handed a different resource to
//     exhaust. Trading one exhaustion for another is not a fix, so both are
//     bounded explicitly.
//
// Refusal DENIES the request. That is the fail-closed direction and it is the
// safe one: the cost of a spurious refusal is a 407 the client retries, and
// the cost of admitting is the outage above. It is never silent — every
// refusal is counted by reason, and the root health plane
// (`auth_cost_health.go`) turns those counters into a contract row, a
// rate-limited log line and an alert.
//
// # What this deliberately does NOT do
//
// It does not cache, memoise or otherwise decide anything about the CREDENTIAL.
// It knows nothing about usernames, passwords or verdicts, and it must not:
// the admission decision is taken by the caller BEFORE the username is
// compared, precisely so that being over budget cannot leak whether a username
// exists. A gate whose behaviour depended on the credential would reintroduce
// the username-enumeration oracle RISK-008 closed. See the call site in
// store.go.
package authcost

import (
	"runtime"
	"sync"
	"time"
)

// Refusal classifies why a verification was not admitted. The set is small,
// closed and stable because it reaches a metric label: an unbounded reason
// string on a per-request path is the WK-12/RS-5 cardinality defect.
type Refusal uint8

const (
	// Admitted is the zero value: the caller holds a slot and MUST Release it.
	Admitted Refusal = iota
	// RefusedPerClient — this client key already holds its maximum number of
	// concurrent verifications.
	RefusedPerClient
	// RefusedQueueFull — every slot is busy and the bounded wait queue is full.
	RefusedQueueFull
	// RefusedTimeout — the caller waited its full budget without a slot
	// becoming free.
	RefusedTimeout
)

// String renders the refusal as the stable metric-label / log token.
func (r Refusal) String() string {
	switch r {
	case Admitted:
		return "admitted"
	case RefusedPerClient:
		return "per_client"
	case RefusedQueueFull:
		return "queue_full"
	case RefusedTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

const (
	// DefaultMaxPerClient is how many concurrent verifications one client key
	// may have in flight. One, because a single client that genuinely needs a
	// second concurrent credential check while the first is still running is
	// either a flood or a misconfiguration, and in both cases making it wait
	// is correct. Raising this directly widens the share of the global ceiling
	// a single source can occupy.
	DefaultMaxPerClient = 1

	// DefaultMaxWait bounds how long a caller will wait for a slot. It is
	// sized against the queue: with the default ceiling and queue depth the
	// deepest legitimate wait is (maxWaiters/maxConcurrent) x ~80 ms, so one
	// second covers a completely full queue with headroom, while still being
	// far below any client's proxy timeout.
	DefaultMaxWait = 1 * time.Second

	// waitersPerSlot sets the queue depth as a multiple of the ceiling. Eight
	// is chosen so the queue drains within DefaultMaxWait at the measured
	// bcrypt cost; it also keeps the worst-case parked-goroutine count at
	// 8 x maxConcurrent, which is single digits on any machine Culvert runs on.
	waitersPerSlot = 8
)

// DefaultMaxConcurrent is the global ceiling on concurrent credential
// verifications: half of GOMAXPROCS, floored at one.
//
// Half, not all, because the gateway's REAL work — TLS handshakes, scanning,
// policy evaluation, relaying — has to keep running while somebody is
// authenticating. A ceiling equal to GOMAXPROCS bounds the fault in the sense
// that it stops being unbounded, but still permits credential verification to
// occupy every core, which is the outage this engine exists to prevent.
//
// Floored at one rather than two so the guarantee holds on a single-core
// appliance, where two concurrent bcrypts is already 100% of the machine.
//
// Sizing sanity for the other direction: at ~80 ms per verification a ceiling
// of K sustains K/0.08 verifications per second — 25/s on a four-core box.
// Successful results are cached for `authCacheTTL` (5 minutes), so a
// deployment's steady-state UNCACHED rate is (active users / 300 s): even
// 500 users behind one gateway is ~1.7/s, better than an order of magnitude
// below the ceiling. The ceiling bites under attack, not under load.
func DefaultMaxConcurrent() int {
	if n := runtime.GOMAXPROCS(0) / 2; n > 0 {
		return n
	}
	return 1
}

// Stats is the reporting snapshot consumed by the root health plane.
type Stats struct {
	// MaxConcurrent / MaxPerClient are the effective bounds, reported so an
	// operator reading a saturation alert can see what it saturated against.
	MaxConcurrent int
	MaxPerClient  int

	// InFlight and Queued are instantaneous.
	InFlight int
	Queued   int

	// Admitted counts verifications that were allowed to run bcrypt.
	Admitted uint64

	// Refused* count fail-closed denials by reason. Their sum is the blast
	// radius of the governor: requests that were denied WITHOUT their
	// credential ever being checked.
	RefusedPerClient uint64
	RefusedQueueFull uint64
	RefusedTimeout   uint64

	// Waited counts admissions that had to queue for a slot. It is the leading
	// indicator: a climbing Waited with no refusals means the ceiling is being
	// approached but is still absorbing, which is exactly when an operator
	// wants to look rather than after users start seeing 407s.
	Waited uint64

	// PeakInFlight / PeakQueued are high-water marks since startup, so an
	// incident that has already drained is still visible on a contract row
	// that only ever sees "right now".
	PeakInFlight int
	PeakQueued   int
}

// Refusals is the total number of fail-closed denials across all reasons.
func (s Stats) Refusals() uint64 {
	return s.RefusedPerClient + s.RefusedQueueFull + s.RefusedTimeout
}

// Gate is the admission governor. Construct with New; the zero value is not
// usable. All methods are safe for concurrent use.
type Gate struct {
	// slots is the global ceiling, held as a buffered channel so a waiter can
	// select against a timer. Capacity is fixed at construction.
	slots chan struct{}

	maxConcurrent int
	maxPerClient  int
	maxWaiters    int
	maxWait       time.Duration

	// newTimer is an injection seam for the wait deadline. Nil in production.
	// Tests that must exercise the timeout branch deterministically replace it
	// rather than sleeping.
	newTimer func(time.Duration) (<-chan time.Time, func() bool)

	mu sync.Mutex
	// perClient counts in-flight-or-queued verifications per client key. An
	// entry is deleted at zero, so the map's cardinality tracks ACTIVE clients
	// and cannot grow with the number of distinct keys ever seen — the
	// unbounded-map defect this codebase has closed repeatedly (WK-12,
	// topHosts, the auth result cache).
	perClient map[string]int

	queued       int
	peakQueued   int
	peakInFlight int

	admitted         uint64
	refusedPerClient uint64
	refusedQueueFull uint64
	refusedTimeout   uint64
	waited           uint64
}

// New builds a Gate. Non-positive arguments fall back to the defaults, so a
// caller can pass a partially-specified configuration without ever
// constructing a gate that admits everything (maxConcurrent <= 0) or nothing.
func New(maxConcurrent, maxPerClient int, maxWait time.Duration) *Gate {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent()
	}
	if maxPerClient <= 0 {
		maxPerClient = DefaultMaxPerClient
	}
	if maxPerClient > maxConcurrent {
		// A per-client ceiling above the global one cannot bind, and silently
		// keeping it would report a fairness bound that does not exist.
		maxPerClient = maxConcurrent
	}
	if maxWait <= 0 {
		maxWait = DefaultMaxWait
	}
	return &Gate{
		slots:         make(chan struct{}, maxConcurrent),
		maxConcurrent: maxConcurrent,
		maxPerClient:  maxPerClient,
		maxWaiters:    maxConcurrent * waitersPerSlot,
		maxWait:       maxWait,
		perClient:     make(map[string]int),
	}
}

// Admit asks permission to run one credential verification on behalf of
// client.
//
// On Admitted the caller holds a slot and MUST call Release(client) exactly
// once, on every path out including panics — use `defer`. On any refusal the
// caller holds nothing and MUST NOT call Release.
//
// queued reports whether the admission had to wait for a slot. It is
// meaningful only when the refusal is Admitted, and it is returned rather than
// derived from a counter because the caller uses it to decide RECOVERY: an
// admission that had to queue is not evidence that capacity has returned.
//
// client is an eviction-fairness key, not an identity: it is never used for
// lookup, authentication or authorization, and the empty string is a valid key
// (all callers that cannot resolve a peer share one bucket, which can only
// throttle each other). See authStateClientKey in the root package for the
// derivation and why it goes through realClientIP.
func (g *Gate) Admit(client string) (result Refusal, queued bool) {
	// Reserve the per-client budget first. It covers the queued state as well
	// as the in-flight one: a client that could queue without limit would hold
	// an unbounded share of the (bounded) queue and starve everyone else out
	// of it, which is the same unfairness one level down.
	//
	// The EMPTY key is exempt from the per-client rule (but never from the
	// global ceiling). It does not mean "a client"; it means "the peer could
	// not be identified", and lumping every unidentifiable caller into one
	// bucket of size one would make unrelated requests contend — so a
	// deployment whose realClientIP resolution is misconfigured would see the
	// governor DENY authentication for everybody rather than merely lose
	// fairness. That is the outage class this engine exists to prevent, caused
	// by the engine.
	//
	// It gives an attacker nothing. Reaching an empty key at all requires
	// making the resolved address unparseable, which on both production call
	// sites means controlling a forwarded header — and a peer that can do that
	// is behind a trusted proxy and can already mint unlimited DISTINCT keys,
	// which defeats the per-client rule outright and is strictly better for
	// them than sharing one. The bound that actually caps CPU, the global
	// ceiling, still applies either way.
	g.mu.Lock()
	if client != "" {
		if g.perClient[client] >= g.maxPerClient {
			g.refusedPerClient++
			g.mu.Unlock()
			return RefusedPerClient, false
		}
		g.perClient[client]++
	}
	g.mu.Unlock()

	// Fast path: a free slot, no queueing, no timer.
	select {
	case g.slots <- struct{}{}:
		g.noteAdmitted(false)
		return Admitted, false
	default:
	}

	// Slow path: join the bounded queue, or be refused by it.
	g.mu.Lock()
	if g.queued >= g.maxWaiters {
		g.refusedQueueFull++
		g.releaseClientLocked(client)
		g.mu.Unlock()
		return RefusedQueueFull, false
	}
	g.queued++
	if g.queued > g.peakQueued {
		g.peakQueued = g.queued
	}
	g.mu.Unlock()

	timeout, stop := g.timer(g.maxWait)
	select {
	case g.slots <- struct{}{}:
		stop()
		g.leaveQueue()
		g.noteAdmitted(true)
		return Admitted, true
	case <-timeout:
		g.leaveQueue()
		g.mu.Lock()
		g.refusedTimeout++
		g.releaseClientLocked(client)
		g.mu.Unlock()
		return RefusedTimeout, true
	}
}

// Release returns the slot held by an Admitted caller.
func (g *Gate) Release(client string) {
	select {
	case <-g.slots:
	default:
		// Defensive: a Release without a matching Admit would otherwise block
		// forever on an empty channel. Dropping it keeps the accounting wrong
		// in the SAFE direction (the ceiling stays tight) rather than
		// deadlocking the auth path.
		return
	}
	g.mu.Lock()
	g.releaseClientLocked(client)
	g.mu.Unlock()
}

// releaseClientLocked drops one unit of client's reservation. Caller holds mu.
//
// The empty key never took a reservation (see Admit), so releasing it is a
// no-op — spelled out rather than relying on delete-of-a-missing-key, because
// a silent mismatch between the reserve and release rules is how a fairness
// budget leaks.
func (g *Gate) releaseClientLocked(client string) {
	if client == "" {
		return
	}
	if n := g.perClient[client]; n > 1 {
		g.perClient[client] = n - 1
	} else {
		delete(g.perClient, client)
	}
}

func (g *Gate) leaveQueue() {
	g.mu.Lock()
	g.queued--
	g.mu.Unlock()
}

func (g *Gate) noteAdmitted(queued bool) {
	g.mu.Lock()
	g.admitted++
	if queued {
		g.waited++
	}
	if n := len(g.slots); n > g.peakInFlight {
		g.peakInFlight = n
	}
	g.mu.Unlock()
}

func (g *Gate) timer(d time.Duration) (<-chan time.Time, func() bool) {
	if g.newTimer != nil {
		return g.newTimer(d)
	}
	t := time.NewTimer(d)
	return t.C, t.Stop
}

// Stats returns a snapshot for the reporting surfaces.
func (g *Gate) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Stats{
		MaxConcurrent:    g.maxConcurrent,
		MaxPerClient:     g.maxPerClient,
		InFlight:         len(g.slots),
		Queued:           g.queued,
		Admitted:         g.admitted,
		RefusedPerClient: g.refusedPerClient,
		RefusedQueueFull: g.refusedQueueFull,
		RefusedTimeout:   g.refusedTimeout,
		Waited:           g.waited,
		PeakInFlight:     g.peakInFlight,
		PeakQueued:       g.peakQueued,
	}
}

// saturationProbe is a cheap, lock-free "is the ceiling currently full?" read
// for the health plane, which polls it far more often than anything mutates
// the gate. It is intentionally approximate: len() on a buffered channel is a
// snapshot, and a saturation signal that is one verification stale is still
// the correct signal.
func (g *Gate) saturationProbe() bool { return len(g.slots) >= g.maxConcurrent }

// Saturated reports whether every verification slot is currently occupied.
func (g *Gate) Saturated() bool { return g.saturationProbe() }
