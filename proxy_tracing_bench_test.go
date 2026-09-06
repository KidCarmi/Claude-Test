package main

// proxy_tracing_bench_test.go — before/after benchmarks for the per-request
// tracing setup (setupRequestTracing, proxy.go).
//
// setupRequestTracing is the SECOND statement in handleRequest — ahead of the
// connection limiter, the IP filter and authentication — so it runs on 100% of
// proxied traffic across every protocol (HTTP, CONNECT, WebSocket). On the
// end-to-end proxy benchmark it accounted for 13.8% of every allocation
// handleRequest made (alloc_objects profile at memprofilerate=1,
// BenchmarkPerfQual_ProxyHTTPForward/rules=100: 13,228 of 96,072 objects).
//
// Two costs were being paid for nothing:
//
//  1. "X-Request-ID" is NOT the canonical MIME spelling — Go canonicalises it
//     to "X-Request-Id" — so every Get/Set on that literal took
//     textproto.CanonicalMIMEHeaderKey's SLOW path and allocated a rewritten
//     key. The function does one Get and two Sets on it per request.
//  2. The request ID and the traceparent were drawn and encoded separately:
//     two crypto/rand.Read calls (each carrying ~27 ns of fixed cost) and two
//     string allocations, where one draw and one allocation cover both.
//
// The *Legacy benchmarks drive legacySetupRequestTracing
// (proxy_tracing_test.go) — a verbatim copy of the pre-change body — so the
// comparison is reproducible in-tree rather than a number in a commit message.
// Measured on the CI dev-container class (linux/amd64, 4 vCPU Xeon @2.8GHz),
// median of n=7:
//
//	                                       ns/op   B/op  allocs/op
//	SetupRequestTracing_Fresh                584    128      4
//	SetupRequestTracing_FreshLegacy          969    192      8     (-40% / -4 allocs)
//	SetupRequestTracing_ClientIDs            164     16      1
//	SetupRequestTracing_ClientIDsLegacy      320     48      3     (-49% / -2 allocs)
//	SetupRequestTracing_FreshParallel        213    128      4
//	SetupRequestTracing_FreshParallelLegacy  362    192      8     (-41%)
//	GenerateTraceIDs                         190     80      1
//	GenerateTraceIDs_Separate                255     80      2     (-25% / -1 alloc)
//	HeaderKey_CanonicalGet                    29      0      0
//	HeaderKey_NonCanonicalGet                 96     16      1
//	HeaderKey_CanonicalSet                    66     16      1
//	HeaderKey_NonCanonicalSet                145     32      2
//
// End to end, BenchmarkPerfQual_ProxyHTTPForward/rules=100 goes from 191 to
// 187 allocs/op — the same 4 allocations, now visible against the whole
// client + proxy + backend loop. Its ns/op is loopback- and scheduler-bound
// and is NOT the evidence for this change; the isolated numbers above are.
//
// The allocation contract is pinned by TestBenchGate_RequestTracingAllocs and
// the before/after relationship by TestBenchGate_RequestTracingBeatsLegacy
// (bench_regression_test.go, -tags benchgate).

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// benchTracingSink keeps the returned request ID observable so the compiler
// cannot elide the call.
var benchTracingSink string

// benchTracingWriter is a minimal http.ResponseWriter over one reusable header
// map. httptest.NewRecorder costs ~3.8 µs and ~18 allocations per construction
// — ten times the function under test — which would bury the signal these
// benchmarks exist to show. Only Header() is ever called.
type benchTracingWriter struct{ h http.Header }

func (w *benchTracingWriter) Header() http.Header         { return w.h }
func (w *benchTracingWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *benchTracingWriter) WriteHeader(int)             {}

func newBenchTracingWriter() *benchTracingWriter {
	return &benchTracingWriter{h: http.Header{}}
}

// benchTracingRequest builds a request carrying the given headers. The map is
// reused across iterations by the benchmark bodies below, which reset only
// what the function under test stamped.
func benchTracingRequest(h http.Header) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.Header = h
	return r
}

// benchTracingFresh is the shape a direct client sends: neither tracing header
// present, so both IDs are generated. This is the case essentially all proxied
// traffic takes.
//
// The two deletes reset what the previous iteration stamped — without them,
// iteration 2 onward would take the "already traced" path and measure the
// wrong thing. They are two map deletes on canonical keys, identical on the
// new and legacy benchmarks, so they are a constant that cancels out of the
// comparison.
func benchTracingFresh(b *testing.B, fn func(http.ResponseWriter, *http.Request) string) {
	w := newBenchTracingWriter()
	r := benchTracingRequest(http.Header{})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		delete(r.Header, headerRequestID)
		delete(r.Header, headerTraceparent)
		benchTracingSink = fn(w, r)
	}
}

// benchTracingClientIDs is the shape a request arrives in behind another proxy
// or a service mesh that already stamped both headers. Nothing is generated,
// so this isolates the header-key cost alone — and setupRequestTracing is
// idempotent for it (it only writes the response header), so no reset is
// needed and nothing but the function under test is inside the timer.
func benchTracingClientIDs(b *testing.B, fn func(http.ResponseWriter, *http.Request) string) {
	w := newBenchTracingWriter()
	r := benchTracingRequest(http.Header{
		headerRequestID:   {"upstream-request-id"},
		headerTraceparent: {"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchTracingSink = fn(w, r)
	}
}

func BenchmarkSetupRequestTracing_Fresh(b *testing.B) {
	benchTracingFresh(b, setupRequestTracing)
}

func BenchmarkSetupRequestTracing_FreshLegacy(b *testing.B) {
	benchTracingFresh(b, legacySetupRequestTracing)
}

func BenchmarkSetupRequestTracing_ClientIDs(b *testing.B) {
	benchTracingClientIDs(b, setupRequestTracing)
}

func BenchmarkSetupRequestTracing_ClientIDsLegacy(b *testing.B) {
	benchTracingClientIDs(b, legacySetupRequestTracing)
}

// BenchmarkSetupRequestTracing_FreshParallel is the concurrency shape: a
// gateway runs this on every core at once. Each goroutine owns its own request
// and writer, exactly as a real connection does, so this measures the shared
// costs — the CSPRNG and the allocator — rather than contention the production
// path does not have.
func BenchmarkSetupRequestTracing_FreshParallel(b *testing.B) {
	benchTracingParallel(b, setupRequestTracing)
}

func BenchmarkSetupRequestTracing_FreshParallelLegacy(b *testing.B) {
	benchTracingParallel(b, legacySetupRequestTracing)
}

func benchTracingParallel(b *testing.B, fn func(http.ResponseWriter, *http.Request) string) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		w := newBenchTracingWriter()
		r := benchTracingRequest(http.Header{})
		var sink string
		for pb.Next() {
			delete(r.Header, headerRequestID)
			delete(r.Header, headerTraceparent)
			sink = fn(w, r)
		}
		benchTracingSink = sink
	})
}

// BenchmarkGenerateTraceIDs measures the combined generator against the two
// separate ones it replaces on the common path. The saving is one
// crypto/rand.Read call's fixed cost plus one string allocation.
func BenchmarkGenerateTraceIDs(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		id, tp := generateTraceIDs()
		if len(id) != requestIDHexLen || len(tp) != traceparentLen {
			b.Fatalf("bad ids %q / %q", id, tp)
		}
	}
}

// BenchmarkGenerateTraceIDs_Separate is the frozen pre-change shape: two
// independent draws and two allocations for the same pair of IDs.
func BenchmarkGenerateTraceIDs_Separate(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		id := generateRequestID()
		tp := legacyGenerateTraceparent()
		if len(id) != requestIDHexLen || len(tp) != traceparentLen {
			b.Fatalf("bad ids %q / %q", id, tp)
		}
	}
}

// BenchmarkHeaderKey_* isolate the single cause behind most of the win, so a
// reader can see it without reconstructing the profile: the same logical
// operation, differing only in how the constant is spelled.
func BenchmarkHeaderKey_CanonicalGet(b *testing.B)    { benchHeaderGet(b, headerRequestID) }
func BenchmarkHeaderKey_NonCanonicalGet(b *testing.B) { benchHeaderGet(b, "X-Request-ID") }
func BenchmarkHeaderKey_CanonicalSet(b *testing.B)    { benchHeaderSet(b, headerRequestID) }
func BenchmarkHeaderKey_NonCanonicalSet(b *testing.B) { benchHeaderSet(b, "X-Request-ID") }

func benchHeaderGet(b *testing.B, key string) {
	h := http.Header{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchTracingSink = h.Get(key)
	}
}

func benchHeaderSet(b *testing.B, key string) {
	h := http.Header{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Set(key, "0123456789abcdef")
	}
}
