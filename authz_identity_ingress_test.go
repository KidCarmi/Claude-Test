package main

// Ingress trust boundary for the internal X-User-Identity header (F1, security
// review docs/security-reviews/2026-08-13-x-user-identity-ingress-trust.md).
//
// The product invariant under test: NO client-controlled X-User-Identity value
// may influence policy evaluation, authorization semantics, or log attribution.
// The existing spoof test (TestAuthzMatrix_IdentityHeaderSpoofIgnored) covers
// the auth-required posture, where the request 407s before evaluation. These
// tests cover the identity-free postures — default-Exempt and no-backend inert
// — where the request DOES reach Stage-2 evaluation and, before the F1 fix,
// a client-supplied header value flowed into policyStore.Evaluate as the
// SourceIdentity input (proxy.go read the header back after conditionally
// stamping it, and nothing scrubbed it on ingress).
//
// Each e2e case asserts all three planes: proxy response, upstream reach, and
// request-log attribution.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// spoofedGet sends a GET through the proxy with a client-supplied
// X-User-Identity header and no credentials.
func spoofedGet(t *testing.T, proxyURL *url.URL, targetURL, spoof string) int {
	t.Helper()
	p := *proxyURL
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&p)},
		Timeout:   5 * time.Second,
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-User-Identity", spoof)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("spoofed GET: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// requestLogMark returns a baseline for scoping a later request-log assertion to
// entries THIS test produced. See assertNoIdentityAttributionSince.
func requestLogMark() int64 { return time.Now().UnixMilli() }

// assertNoIdentityAttributionSince scans the request-log ring for entries about the
// given destination host, recorded at or after mark, and fails if any carries a
// non-empty identity: the only identity source on these test paths would be the
// spoofed header.
//
// THE MARK IS NOT OPTIONAL. The ring is process-global and never reset between
// tests, and the destination is an httptest server on 127.0.0.1:<ephemeral>, whose
// port the kernel recycles freely within one test binary. So an UNSCOPED scan
// matches entries a completely different test logged for the same host:port — and
// a test that legitimately authenticated as alice leaves exactly the entry this
// assertion is looking for. That is what failed CI under -shuffle -count=2, with
// this test's OWN entry correctly carrying an empty identity: the security
// property held and the assertion reported otherwise, which is the worst direction
// for a spoofing gate to be wrong in.
//
// Scoping by TS (not by ring index) is deliberate: the ring is a fixed-capacity
// circular buffer that saturates at MaxRing, so once full its length stops
// changing and an index delta silently stops meaning anything. This is the same
// baseline-TS discipline CLAUDE.md requires for the audit ring, for the same
// reason.
func assertNoIdentityAttributionSince(t *testing.T, mark int64, destHost string) {
	t.Helper()
	entries := logGet()
	scanned := 0
	for i := range entries { // index-based: LogEntry is a large struct (rangeValCopy)
		if entries[i].TS < mark || entries[i].Host != destHost {
			continue
		}
		scanned++
		if entries[i].Identity != "" {
			t.Errorf("log entry for %s attributed to identity %q — client-controlled header must never reach log attribution", destHost, entries[i].Identity)
		}
	}
	// Anti-vacuity: the request under test is logged, so finding nothing to scan
	// means the assertion proved nothing rather than proving the property.
	if scanned == 0 {
		t.Errorf("no request-log entry for %s at or after the mark — the spoof assertion scanned nothing", destHost)
	}
}

// TestIdentityIngress_ExemptSpoofDenied: default-Exempt (open) posture with a
// SourceIdentity-scoped allow rule. The unauthenticated request reaches
// Stage-2 with an EMPTY identity; a spoofed X-User-Identity: alice must not
// satisfy the alice-scoped rule, so the default-deny applies (403), the
// upstream is never reached, and no log entry is attributed to "alice".
func TestIdentityIngress_ExemptSpoofDenied(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), []PolicyRule{{
		Priority: 1, Name: "alice-allow", DestFQDN: "*", SourceIdentity: "alice", Action: ActionAllow,
	}})
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })

	mark := requestLogMark()
	got := spoofedGet(t, proxyURL, backend.URL+"/", "alice")
	if got != http.StatusForbidden {
		t.Errorf("exempt + spoofed X-User-Identity: status %d, want 403 — the spoofed header must not satisfy a SourceIdentity rule", got)
	}
	if cb.hitCount() != 0 {
		t.Errorf("spoofed-identity request reached upstream %d times, want 0", cb.hitCount())
	}
	if u, err := url.Parse(backend.URL); err == nil {
		assertNoIdentityAttributionSince(t, mark, u.Host)
	}
}

// TestIdentityIngress_NoBackendSpoofDenied: the no-backend inert posture (no
// local user, no legacy provider, no enabled IdP, Default outcome). Stage-1 is
// skipped entirely, so the request reaches Stage-2 with an empty identity; a
// spoofed header must not satisfy the identity-scoped rule.
func TestIdentityIngress_NoBackendSpoofDenied(t *testing.T) {
	backend, cb := startCountingBackend(t)
	setupProxyTest(t) // fresh cfg: no local user, no provider; default deny

	origReg := idpRegistry
	idpRegistry = &IdPRegistry{}
	t.Cleanup(func() { idpRegistry = origReg })

	policyStore.Add(PolicyRule{
		Priority: 1, Name: "alice-allow", DestFQDN: "*", SourceIdentity: "alice", Action: ActionAllow,
	})

	srv := httptest.NewServer(http.HandlerFunc(handleRequest))
	t.Cleanup(srv.Close)
	proxyURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	mark := requestLogMark()
	got := spoofedGet(t, proxyURL, backend.URL+"/", "alice")
	if got != http.StatusForbidden {
		t.Errorf("no-backend + spoofed X-User-Identity: status %d, want 403 (default deny)", got)
	}
	if cb.hitCount() != 0 {
		t.Errorf("spoofed-identity request reached upstream %d times, want 0", cb.hitCount())
	}
	if u, err := url.Parse(backend.URL); err == nil {
		assertNoIdentityAttributionSince(t, mark, u.Host)
	}
}

// TestIdentityIngress_AuthenticatedIdentityStillAttributed: regression guard
// for the fix itself — the server-stamped identity channel must keep working.
// An authenticated request in the right group is allowed and its log entry
// carries the REAL identity, proving the ingress scrub removed only the
// client-supplied value, not the internal stamping.
func TestIdentityIngress_AuthenticatedIdentityStillAttributed(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), engRule())

	p := *proxyURL
	p.User = url.UserPassword("alice", "eng-token")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&p)}, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, backend.URL+"/", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-User-Identity", "mallory") // spoof attempt alongside real creds
	mark := requestLogMark()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("authenticated GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request: status %d, want 200", resp.StatusCode)
	}
	if cb.hitCount() == 0 {
		t.Fatalf("authenticated request should reach upstream")
	}

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	// Scoped to THIS test's entries for the same reason as the spoof assertions
	// above — and here an unscoped scan is worse than a false failure: a stale
	// "alice" entry another test left for a recycled 127.0.0.1:<port> would set
	// found and pass this test even if identity stamping were completely broken.
	entries := logGet()
	found := false
	for i := range entries { // index-based: LogEntry is a large struct (rangeValCopy)
		if entries[i].TS < mark || entries[i].Host != u.Host {
			continue
		}
		if entries[i].Identity == "mallory" {
			t.Fatalf("log entry attributed to the SPOOFED identity %q", entries[i].Identity)
		}
		if entries[i].Identity == "alice" {
			found = true
		}
	}
	if !found {
		t.Errorf("no log entry attributed to the authenticated identity 'alice' — internal identity stamping must survive the ingress scrub")
	}
}

// TestIdentityIngress_LateTrailerCannotResurrectScrubbedKeys (Codex round 7):
// the early trailer deletion alone is defeated by net/http itself — for a
// chunked request with declared trailers, the server merges the RECEIVED
// trailer values back into r.Trailer when the body reaches EOF, AFTER
// scrubForwardedHeaders ran, and the forward paths (client.Do(r), r.Write)
// emit trailers from that same map. The scrub's body wrapper must re-delete
// the banned keys at EOF, so the map the outbound writer reads is clean.
func TestIdentityIngress_LateTrailerCannotResurrectScrubbedKeys(t *testing.T) {
	type result struct{ pre, post string }
	got := make(chan result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scrubForwardedHeaders(r) // as every forward path does before sending upstream
		pre := r.Trailer.Get("X-User-Identity")
		// Reading the body to EOF is exactly what the upstream transport does
		// before writing the trailer section from r.Trailer.
		_, _ = io.Copy(io.Discard, r.Body)
		got <- result{pre: pre, post: r.Trailer.Get("X-User-Identity")}
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.ContentLength = -1 // chunked, so the trailer section exists
	req.Trailer = http.Header{}
	req.Trailer.Set("X-User-Identity", "mallory@evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	resp.Body.Close()

	r := <-got
	if r.pre != "" {
		t.Fatalf("early scrub failed outright: %q", r.pre)
	}
	if r.post != "" {
		t.Fatalf("late trailer resurrected the scrubbed identity key after body EOF: %q — the forwarded trailer map is poisoned", r.post)
	}
}

// TestIdentityIngress_TrailerScrubbed: scrubForwardedHeaders must strip the
// identity/topology keys from request TRAILERS too — Go forwards r.Trailer on
// r.Write, and the 2026-07-11 security review noted the scrub was Header-only.
func TestIdentityIngress_TrailerScrubbed(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Trailer = http.Header{
		"X-User-Identity": []string{"spoof@evil.example"},
		"X-Forwarded-For": []string{"10.0.0.1"},
		"X-Real-Ip":       []string{"10.0.0.2"},
	}
	scrubForwardedHeaders(req)
	for _, k := range []string{"X-User-Identity", "X-Forwarded-For", "X-Real-Ip"} {
		if got := req.Trailer.Get(k); got != "" {
			if strings.Contains(k, "Identity") {
				t.Errorf("trailer %s survived scrubForwardedHeaders: %q — identity claims must not ride through as trailers", k, got)
			} else {
				t.Errorf("trailer %s survived scrubForwardedHeaders: %q", k, got)
			}
		}
	}
}

// TestIdentityIngress_TrailerRescrubBodyExposesNoBypassInterface pins the
// structural precondition of the late-trailer rescrub above. The rescrub runs
// ONLY from trailerRescrubBody.Read, and every outbound path writes the body
// with io.Copy, which prefers src.(io.WriterTo) — and, through a bufio-backed
// destination, dst.(io.ReaderFrom) — over Read. A wrapper exposing such a
// method would be drained to EOF without Read running once: the merged
// trailer map would never be re-scrubbed and a client could smuggle
// X-User-Identity upstream as a late trailer. The wrapper must therefore
// expose Read/Close and nothing else, whatever the body it wraps implements.
func TestIdentityIngress_TrailerRescrubBodyExposesNoBypassInterface(t *testing.T) {
	// A body that implements every copy fast path io.Copy consults. If the
	// wrapper promoted them, the assertions below would succeed.
	var w any = &trailerRescrubBody{body: &copyFastPathBody{}, trailer: http.Header{}}
	if _, ok := w.(io.WriterTo); ok {
		t.Error("trailerRescrubBody exposes io.WriterTo — io.Copy would bypass Read and never re-scrub the trailers")
	}
	if _, ok := w.(io.ReaderFrom); ok {
		t.Error("trailerRescrubBody exposes io.ReaderFrom — a copy fast path would bypass Read")
	}
	if _, ok := w.(io.Seeker); ok {
		t.Error("trailerRescrubBody exposes io.Seeker — the body must not be rewindable past the rescrub")
	}
	// The two methods it MUST expose still work, and Read still re-scrubs.
	tr := http.Header{"X-User-Identity": []string{"mallory@evil.example"}}
	b := &trailerRescrubBody{body: io.NopCloser(strings.NewReader("")), trailer: tr}
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected EOF from an empty body")
	}
	if got := tr.Get("X-User-Identity"); got != "" {
		t.Errorf("Read at EOF did not re-scrub the trailer: %q", got)
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// copyFastPathBody implements the optional interfaces io.Copy prefers, so the
// promotion check above is meaningful rather than vacuous.
type copyFastPathBody struct{}

func (*copyFastPathBody) Read([]byte) (int, error)          { return 0, io.EOF }
func (*copyFastPathBody) Close() error                      { return nil }
func (*copyFastPathBody) WriteTo(io.Writer) (int64, error)  { return 0, nil }
func (*copyFastPathBody) ReadFrom(io.Reader) (int64, error) { return 0, nil }
func (*copyFastPathBody) Seek(int64, int) (int64, error)    { return 0, nil }
