package main

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// RateLimiter.IsExempt is the FIRST decision inside Allow/AllowClusterAware,
// which proxy.go (handleRequest) and socks5.go reach on every proxied request
// once a rate limit is configured. These benchmarks pin its cost on the two
// axes that matter:
//
//	CORE COUNT  — a shared read lock taken per request is an atomic
//	              read-modify-write on ONE cache line, which turns a constant
//	              cost into a throughput CEILING that gets worse as cores are
//	              added. Run the *Parallel forms with -cpu=1,2,4; the SHAPE
//	              across that list is the measurement, not any single number.
//	CIDR COUNT  — the exempt-CIDR side is a linear net.IPNet.Contains scan, so
//	              an operator's exempt list is the price of the gate, paid on
//	              every request from every non-exempt client.
//
// newBenchRateLimiter builds an isolated limiter so these never touch the
// package global `rl` that the rest of the suite mutates.
func newBenchRateLimiter(entries []string) *RateLimiter {
	r := newRateLimiter()
	for _, e := range entries {
		if err := r.AddExemption(e); err != nil {
			panic("bench fixture: " + e + ": " + err.Error())
		}
	}
	return r
}

// benchExemptCIDRs returns n distinct, non-overlapping /24s that never contain
// the probe IP, so the lookup always walks the whole list — the worst case,
// and the only one that is stable across runs.
func benchExemptCIDRs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	return out
}

// benchExemptRealistic is the shape a real exempt list takes: a couple of
// monitoring hosts plus the management ranges.
var benchExemptRealistic = []string{"198.51.100.7", "198.51.100.8", "192.0.2.0/24", "10.0.0.0/8"}

const benchExemptProbeIP = "203.0.113.47" // TEST-NET-3: never inside any fixture above

var benchExemptSink bool

// ─── Core-count axis ────────────────────────────────────────────────────────

func BenchmarkIsExempt_NoExemptionsParallel(b *testing.B) {
	r := newBenchRateLimiter(nil)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sink bool // per-worker sink: a shared one is false sharing, not the measurement
		for pb.Next() {
			sink = r.IsExempt(benchExemptProbeIP)
		}
		benchExemptSink = sink
	})
}

func BenchmarkIsExempt_RealisticParallel(b *testing.B) {
	r := newBenchRateLimiter(benchExemptRealistic)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sink bool
		for pb.Next() {
			sink = r.IsExempt(benchExemptProbeIP)
		}
		benchExemptSink = sink
	})
}

// ─── CIDR-count axis (serial: this axis is about work, not contention) ──────

func BenchmarkIsExempt_CIDRScale(b *testing.B) {
	for _, n := range []int{0, 1, 4, 16, 64, 256} {
		b.Run(fmt.Sprintf("cidrs=%d", n), func(b *testing.B) {
			r := newBenchRateLimiter(benchExemptCIDRs(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchExemptSink = r.IsExempt(benchExemptProbeIP)
			}
		})
	}
}

// BenchmarkIsExempt_Hit measures the exempt-client path (a monitoring host that
// IS on the list) so a change cannot make the miss path cheap by making the hit
// path expensive.
func BenchmarkIsExempt_Hit(b *testing.B) {
	r := newBenchRateLimiter(benchExemptRealistic)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchExemptSink = r.IsExempt("198.51.100.7")
	}
}

func BenchmarkIsExempt_CIDRHit(b *testing.B) {
	r := newBenchRateLimiter(benchExemptCIDRs(256))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchExemptSink = r.IsExempt("10.255.255.1") // last /24 in the fixture
	}
}

// ─── End-to-end gate cost ───────────────────────────────────────────────────

// BenchmarkRateLimitAllow_WithExemptions measures what the request path
// actually pays: the whole Allow call, exempt check included, across distinct
// client IPs so the sharded window is exercised the way real traffic does.
func BenchmarkRateLimitAllow_WithExemptions(b *testing.B) {
	for _, n := range []int{0, 16, 256} {
		b.Run(fmt.Sprintf("cidrs=%d", n), func(b *testing.B) {
			r := newBenchRateLimiter(benchExemptCIDRs(n))
			r.Configure(1<<30, time.Minute) // effectively never deny
			ips := benchClientIPs(256)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				var sink bool
				i := 0
				for pb.Next() {
					sink = r.Allow(ips[i&255])
					i++
				}
				benchExemptSink = sink
			})
		})
	}
}

// benchClientIPs returns n distinct TEST-NET-3 addresses, none of which is
// inside any exempt fixture above.
func benchClientIPs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, net.IPv4(203, 0, 113, byte(i)).String())
	}
	return out
}
