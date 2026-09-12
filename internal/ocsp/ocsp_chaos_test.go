package ocsp

// ocsp_chaos_test.go — CHAOS-65 gates for the OCSP revocation path.
//
// Every DEFECT gate below was verified failing against the pre-fix tree before
// the fix was written; the CONTROL gates exist because the cheapest way to pass
// every defect gate is to stop trusting responders at all, which would convert
// a revocation check into a fleet-wide HTTPS outage.
//
// The responder URL in these tests is an httptest server on 127.0.0.1, which
// the SSRF guard refuses in production — hence ssrf.AllowLoopbackForTest.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoocsp "golang.org/x/crypto/ocsp"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// ── fixtures ────────────────────────────────────────────────────────────────

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// issueLeaf mints a leaf under ca carrying the given serial and AIA responders.
func (ca *testCA) issueLeaf(t *testing.T, serial int64, responders ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		OCSPServer:   responders,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

// sign produces a genuine, CA-signed OCSP response body.
func (ca *testCA) sign(t *testing.T, r cryptoocsp.Response) []byte {
	t.Helper()
	if r.ThisUpdate.IsZero() {
		r.ThisUpdate = time.Now().Add(-time.Minute)
	}
	if r.NextUpdate.IsZero() {
		r.NextUpdate = time.Now().Add(time.Hour)
	}
	b, err := cryptoocsp.CreateResponse(ca.cert, ca.cert, r, ca.key)
	if err != nil {
		t.Fatalf("sign ocsp response: %v", err)
	}
	return b
}

// staticResponder serves the same DER body to every request and counts hits.
func staticResponder(t *testing.T, body func() []byte) (url string, hits *atomic.Int64) {
	t.Helper()
	hits = &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(body())
	}))
	t.Cleanup(srv.Close)
	return srv.URL, hits
}

// blackholeListener accepts connections and never answers — the half-open peer
// that a per-responder timeout can only bound one responder at a time.
func blackholeListener(t *testing.T) string {
	t.Helper()
	// (*net.ListenConfig).Listen, not net.Listen — repo lint policy (noctx).
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
	})
	return "http://" + ln.Addr().String()
}

func allowLoopback(t *testing.T) {
	t.Helper()
	t.Cleanup(ssrf.AllowLoopbackForTest())
}

// ── DEFECT gates ────────────────────────────────────────────────────────────

// TestChaos65_ResponseForAnotherCertificateIsNotAVerdict is the sharpest gate.
//
// The responder URL is read from the AIA extension of the PEER's certificate,
// so the party being checked chooses which responder is asked. x/crypto's
// ParseResponse (cert == nil) takes SingleResponse[0] and never matches the
// serial, so a genuine, CA-signed "good" response about a DIFFERENT certificate
// of the same issuer — trivially obtained by asking that CA about any live cert
// — was accepted as this certificate's verdict. A revoked certificate is then
// accepted: the revocation control is bypassed end to end by its own subject.
func TestChaos65_ResponseForAnotherCertificateIsNotAVerdict(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")
	other := ca.issueLeaf(t, 99) // a healthy sibling certificate of the same CA

	var body []byte
	url, _ := staticResponder(t, func() []byte { return body })
	revoked := ca.issueLeaf(t, 42, url)

	// A genuine CA-signed GOOD response — but for the sibling's serial.
	body = ca.sign(t, cryptoocsp.Response{
		Status:       cryptoocsp.Good,
		SerialNumber: other.SerialNumber,
	})

	oc := New()
	oc.Enable()
	err := oc.VerifyPeerCertificate([][]byte{revoked.Raw}, [][]*x509.Certificate{{revoked, ca.cert}})
	if err == nil {
		t.Fatal("a response about a DIFFERENT certificate was accepted as this certificate's verdict — " +
			"revocation bypass: the peer chooses the responder URL, so it chooses the answer")
	}
}

// TestChaos65_StaleResponseIsNotAVerdict — OCSP rides plaintext HTTP and the
// request carries no nonce, so a response is replayable by anyone on the path
// (and by the peer itself, which picked the responder). ThisUpdate/NextUpdate
// are the only replay defence, and they were parsed and never read: a "good"
// response captured before the certificate was revoked stays valid forever.
func TestChaos65_StaleResponseIsNotAVerdict(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	url, _ := staticResponder(t, func() []byte { return body })
	leaf := ca.issueLeaf(t, 7, url)

	// A pre-revocation "good" response that expired a year ago.
	body = ca.sign(t, cryptoocsp.Response{
		Status:       cryptoocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-2 * 365 * 24 * time.Hour),
		NextUpdate:   time.Now().Add(-365 * 24 * time.Hour),
	})

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
		t.Fatal("a year-expired OCSP response was accepted as a current verdict — replay defeats revocation")
	}
}

// TestChaos65_UnknownStatusIsNotAffirmativeGood — the engine failed CLOSED when
// no responder could be REACHED, and fail-OPEN when a responder answered
// "I have never heard of this certificate". Under the CA/Browser Forum baseline
// requirements a CA must not answer "good" for a certificate it did not issue,
// so "unknown" is precisely the answer a forged or mis-issued certificate
// draws — the one case where accepting is worst. Same rule as CHAOS-53: a
// verdict must be AFFIRMATIVE.
func TestChaos65_UnknownStatusIsNotAffirmativeGood(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	url, _ := staticResponder(t, func() []byte { return body })
	leaf := ca.issueLeaf(t, 11, url)
	body = ca.sign(t, cryptoocsp.Response{
		Status:       cryptoocsp.Unknown,
		SerialNumber: leaf.SerialNumber,
	})

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
		t.Fatal(`the issuer answered "unknown" — it does not recognise this certificate — and it was accepted`)
	}
}

// TestChaos65_VerdictCacheIsKeyedByIssuerNotSerialAlone — a serial number is
// unique only WITHIN an issuer, which is exactly why RFC 6960's CertID carries
// the issuer name and key hashes alongside it. Keying the verdict cache on the
// serial alone lets one issuer's verdict answer for another's. The dangerous
// direction is this one: a cached "good" admits a genuinely REVOKED certificate
// from a different CA without a single responder query. Sequential serials are
// the norm in enterprise PKI (ADCS), so collisions are ordinary, not exotic.
func TestChaos65_VerdictCacheIsKeyedByIssuerNotSerialAlone(t *testing.T) {
	allowLoopback(t)
	good := newTestCA(t, "issuer-A")
	evil := newTestCA(t, "issuer-B")

	var goodBody, evilBody []byte
	goodURL, _ := staticResponder(t, func() []byte { return goodBody })
	evilURL, evilHits := staticResponder(t, func() []byte { return evilBody })

	const sharedSerial = 5
	healthy := good.issueLeaf(t, sharedSerial, goodURL)
	revoked := evil.issueLeaf(t, sharedSerial, evilURL)

	goodBody = good.sign(t, cryptoocsp.Response{Status: cryptoocsp.Good, SerialNumber: healthy.SerialNumber})
	evilBody = evil.sign(t, cryptoocsp.Response{
		Status:           cryptoocsp.Revoked,
		SerialNumber:     revoked.SerialNumber,
		RevokedAt:        time.Now().Add(-time.Hour),
		RevocationReason: cryptoocsp.KeyCompromise,
	})

	oc := New()
	oc.Enable()
	// Warm the cache with issuer-A's legitimate "good".
	if err := oc.VerifyPeerCertificate([][]byte{healthy.Raw}, [][]*x509.Certificate{{healthy, good.cert}}); err != nil {
		t.Fatalf("healthy certificate should be accepted: %v", err)
	}
	// Now present issuer-B's REVOKED certificate carrying the same serial.
	err := oc.VerifyPeerCertificate([][]byte{revoked.Raw}, [][]*x509.Certificate{{revoked, evil.cert}})
	if err == nil {
		t.Fatal("a revoked certificate was accepted from another issuer's cached verdict — " +
			"the cache key must be the RFC 6960 CertID, not the serial alone")
	}
	if evilHits.Load() == 0 {
		t.Fatal("issuer-B's responder was never asked — the verdict came from issuer-A's cache entry")
	}
}

// TestChaos65_ResponderURLIsSSRFGuarded — the responder URL comes from the
// peer's certificate, i.e. from the party being checked. Any operator of any
// destination this gateway reaches can name an arbitrary internal address and
// have the proxy POST to it from inside the trust boundary. CLAUDE.md states
// the convention this path never followed: inline url.Parse + scheme check +
// isPrivateHost before any outbound request.
func TestChaos65_ResponderURLIsSSRFGuarded(t *testing.T) {
	// Deliberately NOT allowLoopback: this gate asserts the guard is armed.
	ca := newTestCA(t, "issuer")
	internal, hits := staticResponder(t, func() []byte { return nil })
	leaf := ca.issueLeaf(t, 3, internal)

	oc := New()
	oc.Enable()
	_ = oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}})
	if n := hits.Load(); n != 0 {
		t.Fatalf("the proxy made %d request(s) to a private-range address named by the PEER's certificate — SSRF", n)
	}
}

// TestChaos65_ResponderRedirectIsRefused — a guard on the initial URL alone is
// bypassed by a redirect, and http.DefaultClient follows up to ten of them. An
// OCSP responder has no legitimate reason to redirect.
func TestChaos65_ResponderRedirectIsRefused(t *testing.T) {
	ca := newTestCA(t, "issuer")
	internal, hits := staticResponder(t, func() []byte { return nil })

	// A public-looking front that bounces to the internal address. The front
	// itself is on loopback (there is no public address to test against), so
	// loopback is permitted for the hop that must be allowed and the gate
	// asserts on whether the REDIRECT target was followed.
	allowLoopback(t)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	leaf := ca.issueLeaf(t, 4, redirector.URL)
	oc := New()
	oc.Enable()
	_ = oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}})
	if n := hits.Load(); n != 0 {
		t.Fatalf("followed %d redirect(s) from an OCSP responder — a redirect bypasses any URL-level guard", n)
	}
}

// TestChaos65_ResponderFanOutIsBounded — leaf.OCSPServer is attacker-controlled
// and was walked in full, each entry under its OWN 5 s timeout. A certificate
// listing 200 blackholed responders therefore parked the request goroutine (and
// its connection, FD and per-IP limiter slot) for ~17 minutes inside one TLS
// handshake, while aiming 200 outbound POSTs at whatever hosts it named.
// CHAOS-58's rule: one ENVELOPE, not a per-step allowance.
func TestChaos65_ResponderFanOutIsBounded(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	sink := blackholeListener(t)
	responders := make([]string, 200)
	for i := range responders {
		responders[i] = sink
	}
	leaf := ca.issueLeaf(t, 8, responders...)

	oc := New()
	oc.Enable()
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}})
	}()
	select {
	case <-done:
	case <-time.After(queryBudget + 10*time.Second):
		t.Fatalf("a certificate listing %d blackholed responders held the handshake for over %v "+
			"— the fan-out is unbounded and so is the stall", len(responders), queryBudget)
	}
	if elapsed := time.Since(start); elapsed > queryBudget+10*time.Second {
		t.Fatalf("handshake stalled %v, want bounded by the %v envelope", elapsed, queryBudget)
	}
}

// TestChaos65_ConcurrentHandshakesSingleFlight — N simultaneous handshakes to
// one host all miss the same cold cache entry and each launched its own query,
// so the gateway amplified client request rate 1:1 into load on a responder
// that is, by hypothesis, already the slow dependency. Same leader/follower
// shape as hostIPCache and jwksCache.
func TestChaos65_ConcurrentHandshakesSingleFlight(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	url, hits := staticResponder(t, func() []byte {
		time.Sleep(80 * time.Millisecond) // a responder under load
		return body
	})
	leaf := ca.issueLeaf(t, 9, url)
	body = ca.sign(t, cryptoocsp.Response{Status: cryptoocsp.Good, SerialNumber: leaf.SerialNumber})

	oc := New()
	oc.Enable()
	const n = 24
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}})
		}()
	}
	wg.Wait()
	if got := hits.Load(); got > 2 {
		t.Fatalf("%d concurrent handshakes produced %d responder queries — no single-flight; "+
			"the gateway amplifies client rate into load on a failing dependency", n, got)
	}
}

// TestChaos65_SingleFlightStillCountsEveryRefusedHandshake — found in
// self-review of the single-flight fix, not in the original sweep.
//
// Collapsing N queries into one must not collapse N REFUSALS into one.
// culvert_ocsp_fail_closed_total means "handshakes refused for want of a usable
// verdict" and is what an operator alerts on; the pre-existing cached
// fail-closed path already charges every hit for exactly this reason, so a
// follower that inherits a fail-closed verdict has to charge it as well. Left
// unfixed, a fail-closed storm would have under-reported itself by however many
// handshakes happened to arrive concurrently — worst exactly when the storm is
// worst.
func TestChaos65_SingleFlightStillCountsEveryRefusedHandshake(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	// A responder that answers slowly with nothing usable, so every caller
	// lands on the fail-closed path and the late ones join the flight.
	url, _ := staticResponder(t, func() []byte {
		time.Sleep(80 * time.Millisecond)
		return []byte("not an ocsp response")
	})
	leaf := ca.issueLeaf(t, 31, url)

	oc := New()
	oc.Enable()
	const n = 12
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
				t.Error("an unusable response must fail closed")
			}
		}()
	}
	wg.Wait()

	if oc.SingleFlightJoinedTotal() == 0 {
		t.Fatal("no handshake joined an in-flight query — the test did not exercise the follower path")
	}
	if got := oc.FailClosedTotal(); got != n {
		t.Fatalf("FailClosedTotal() = %d after %d refused handshakes, want %d — "+
			"single-flight collapsed the refusals along with the queries, so a "+
			"fail-closed storm under-reports itself exactly when it is worst", got, n, n)
	}
	if got := oc.RevokedTotal(); got != 0 {
		t.Fatalf("RevokedTotal() = %d — it counts responder CONFIRMATIONS, and none were made", got)
	}
}

// TestChaos65_SSRFGuardIsBoundedByTheQueryBudget — also from self-review.
//
// ssrf.PrivateHost resolves under context.Background(). Reaching for it from a
// TLS handshake on the request goroutine would have made the GUARD the
// unbounded call — the CHAOS-64 fault re-imported through the fix for
// CHAOS-65's SSRF hole, and worse than what it replaced, because the hostname
// is written by the peer. The guard now runs under the same envelope as the
// query it guards.
func TestChaos65_SSRFGuardIsBoundedByTheQueryBudget(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	// A hostname under .invalid never resolves; on a host whose resolver
	// blackholes rather than answering NXDOMAIN this is where the unbounded
	// wait happened. The assertion is the bound, not the verdict.
	leaf := ca.issueLeaf(t, 32,
		"http://ocsp.chaos65-nonexistent.invalid/",
		"http://ocsp.chaos65-nonexistent-2.invalid/",
		"http://ocsp.chaos65-nonexistent-3.invalid/",
		"http://ocsp.chaos65-nonexistent-4.invalid/",
	)

	oc := New()
	oc.Enable()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}})
	}()
	select {
	case <-done:
	case <-time.After(queryBudget + 10*time.Second):
		t.Fatalf("the SSRF pre-check outlived the %v query envelope — it must not be "+
			"the unbounded call inside a TLS handshake", queryBudget)
	}
}

// ── CONTROL gates ───────────────────────────────────────────────────────────
//
// A checker that simply refused every certificate would pass every defect gate
// above while being a fleet-wide HTTPS outage. These pin the other direction.

func TestChaos65_Control_HealthyGoodResponseIsStillAccepted(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	url, hits := staticResponder(t, func() []byte { return body })
	leaf := ca.issueLeaf(t, 21, url)
	body = ca.sign(t, cryptoocsp.Response{Status: cryptoocsp.Good, SerialNumber: leaf.SerialNumber})

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err != nil {
		t.Fatalf("a fresh, correctly-bound GOOD response must be accepted: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("responder queried %d times, want exactly 1", hits.Load())
	}
	if oc.FailClosedTotal() != 0 || oc.RevokedTotal() != 0 {
		t.Fatalf("healthy path moved a failure counter: failClosed=%d revoked=%d",
			oc.FailClosedTotal(), oc.RevokedTotal())
	}
	// The second handshake must come from cache, not a second query.
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err != nil {
		t.Fatalf("cached GOOD verdict must still be accepted: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("cached handshake re-queried the responder (%d hits)", hits.Load())
	}
}

func TestChaos65_Control_GenuineRevocationStillBlocks(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	url, _ := staticResponder(t, func() []byte { return body })
	leaf := ca.issueLeaf(t, 22, url)
	body = ca.sign(t, cryptoocsp.Response{
		Status:           cryptoocsp.Revoked,
		SerialNumber:     leaf.SerialNumber,
		RevokedAt:        time.Now().Add(-time.Hour),
		RevocationReason: cryptoocsp.KeyCompromise,
	})

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
		t.Fatal("a genuine revocation must still block")
	}
	if oc.RevokedTotal() != 1 {
		t.Fatalf("RevokedTotal() = %d, want 1", oc.RevokedTotal())
	}
	if oc.FailClosedTotal() != 0 {
		t.Fatalf("a confirmed revocation must not be counted as fail-closed (got %d)", oc.FailClosedTotal())
	}
}

func TestChaos65_Control_DisabledCheckerNeverQueries(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")
	url, hits := staticResponder(t, func() []byte { return nil })
	leaf := ca.issueLeaf(t, 23, url)

	oc := New() // not enabled
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err != nil {
		t.Fatalf("a disabled checker must be a no-op: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("a disabled checker queried the responder %d time(s)", hits.Load())
	}
}

// ── Codex review gates (PR #1369) ───────────────────────────────────────────
//
// Four findings on the CHAOS-65 engine, each verified reachable against the
// tree that shipped it. The first defeats the CHAOS-65 fix outright.

// issueDelegate mints a leaf under ca, optionally carrying the OCSP-signing EKU,
// and returns it with its private key so a test can sign a response with it.
func (ca *testCA) issueDelegate(t *testing.T, serial int64, ocspSigning bool, responders ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return ca.issueDelegateUntil(t, serial, ocspSigning, time.Now().Add(time.Hour), responders...)
}

// issueDelegateUntil is issueDelegate with an explicit NotAfter, so a test can
// mint a signer that is valid NOW but expires well before the response it signs.
func (ca *testCA) issueDelegateUntil(t *testing.T, serial int64, ocspSigning bool, notAfter time.Time, responders ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("delegate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "delegate"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		OCSPServer:   responders,
	}
	if ocspSigning {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("delegate cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse delegate: %v", err)
	}
	return cert, key
}

// TestChaos65_SelfSignedResponseIsNotAVerdict — Codex P1, and it defeats the
// CHAOS-65 fix outright.
//
// Binding the response to the certificate (ParseResponseForCert) closed the
// "borrowed response from a sibling" vector and left a strictly EASIER one
// open. x/crypto verifies an embedded responder certificate only by asking
// whether the ISSUER signed it — it never checks RFC 6960 §4.2.2.2's
// id-kp-OCSPSigning EKU. The peer's own leaf is, by definition, a certificate
// the issuer signed, and the peer holds its private key. So the peer can sign
// a fresh "good" response for ITS OWN serial, embed its own leaf as the
// responder certificate, and serve it from the responder URL in its own AIA.
// A revoked certificate is accepted, with no other response needed from
// anyone.
func TestChaos65_SelfSignedResponseIsNotAVerdict(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	url, _ := staticResponder(t, func() []byte { return body })
	// An ORDINARY leaf: no OCSP-signing EKU, exactly what a peer holds.
	leaf, leafKey := ca.issueDelegate(t, 71, false, url)

	// The peer signs a "good" verdict about itself with its own key and
	// embeds its own certificate as the responder.
	selfSigned, err := cryptoocsp.CreateResponse(ca.cert, leaf, cryptoocsp.Response{
		Status:       cryptoocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
		Certificate:  leaf,
	}, leafKey)
	if err != nil {
		t.Fatalf("create self-signed response: %v", err)
	}
	body = selfSigned

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
		t.Fatal("a certificate signed its OWN 'good' OCSP response and was accepted — " +
			"the responder was never checked for the id-kp-OCSPSigning EKU, so binding " +
			"the response to the certificate bought nothing")
	}
}

// TestChaos65_Control_AuthorizedDelegateIsStillAccepted — the control for the
// gate above. Delegated OCSP responders are ordinary and widely deployed;
// refusing every embedded responder certificate would pass the defect gate
// while breaking revocation checking against most public CAs.
func TestChaos65_Control_AuthorizedDelegateIsStillAccepted(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	url, _ := staticResponder(t, func() []byte { return body })
	leaf := ca.issueLeaf(t, 72, url)
	delegate, delegateKey := ca.issueDelegate(t, 73, true) // carries the EKU

	signed, err := cryptoocsp.CreateResponse(ca.cert, delegate, cryptoocsp.Response{
		Status:       cryptoocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
		Certificate:  delegate,
	}, delegateKey)
	if err != nil {
		t.Fatalf("create delegated response: %v", err)
	}
	body = signed

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err != nil {
		t.Fatalf("an RFC 6960 authorized delegated responder must be accepted: %v", err)
	}
}

// TestChaos65_CachedVerdictExpiresAtTheResponseDeadline — Codex P1.
//
// Freshness was checked only at the moment of receipt, then every confirmed
// verdict was cached for the fixed one-hour cacheTTL. A "good" whose NextUpdate
// is a minute away therefore kept admitting the certificate for another 59
// minutes after the responder stopped vouching for it — the replay window
// CHAOS-65 closed on the wire, reopened in the cache.
func TestChaos65_CachedVerdictExpiresAtTheResponseDeadline(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	url, _ := staticResponder(t, func() []byte { return body })
	leaf := ca.issueLeaf(t, 74, url)

	nextUpdate := time.Now().Add(time.Minute)
	body = ca.sign(t, cryptoocsp.Response{
		Status:       cryptoocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   nextUpdate,
	})

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err != nil {
		t.Fatalf("a fresh GOOD response must be accepted: %v", err)
	}

	entry, ok := oc.cache[certKey(leaf, ca.cert)]
	if !ok {
		t.Fatal("the verdict should be cached")
	}
	limit := nextUpdate.Add(responseClockSkew)
	if entry.expiresAt.After(limit) {
		t.Fatalf("verdict cached until %v, past the responder's own NextUpdate+skew %v "+
			"— the cache outlives the authorization it is built on",
			entry.expiresAt.UTC(), limit.UTC())
	}
}

// TestChaos65_MalformedResponseIsNotCountedAsBorrowed — Codex P2.
//
// Every ParseResponseForCert error charged notForCertTotal, whose metric help
// and red panel banner both claim "something is answering with borrowed
// responses". A responder returning an HTML error page therefore raised a
// standing accusation of attack. A surface whose job is to be believed must
// not cry wolf at a broken upstream.
func TestChaos65_MalformedResponseIsNotCountedAsBorrowed(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	url, _ := staticResponder(t, func() []byte {
		return []byte("<html><body>502 Bad Gateway</body></html>")
	})
	leaf := ca.issueLeaf(t, 75, url)

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
		t.Fatal("an unintelligible response must fail closed")
	}
	if got := oc.NotForCertificateTotal(); got != 0 {
		t.Fatalf("NotForCertificateTotal() = %d after a malformed response — "+
			"a broken responder must not be reported as an issuer-signed response "+
			"about another certificate", got)
	}
	if got := oc.MalformedTotal(); got == 0 {
		t.Fatal("a malformed response must still be counted under its own reason")
	}
}

// TestChaos65_Control_BorrowedResponseIsStillCountedAsBorrowed — the control
// for the gate above: narrowing the counter must not silence the real signal.
func TestChaos65_Control_BorrowedResponseIsStillCountedAsBorrowed(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")
	other := ca.issueLeaf(t, 76)

	var body []byte
	url, _ := staticResponder(t, func() []byte { return body })
	leaf := ca.issueLeaf(t, 77, url)
	body = ca.sign(t, cryptoocsp.Response{Status: cryptoocsp.Good, SerialNumber: other.SerialNumber})

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
		t.Fatal("a response about another certificate must fail closed")
	}
	if got := oc.NotForCertificateTotal(); got != 1 {
		t.Fatalf("NotForCertificateTotal() = %d, want 1 — a genuinely borrowed, "+
			"issuer-signed response is exactly what this counter is for", got)
	}
}

// TestChaos65_LateArrivalUsesTheCacheNotANewFlight — Codex P2.
//
// The cache was consulted before resolve, and the no-flight branch then created
// a query without looking again. A handshake that missed the cache, was
// descheduled while the leader finished and removed its flight, and then woke
// up would start a SECOND query for a verdict already sitting in the cache —
// defeating the collapsing precisely during the cold-cache burst it exists for.
func TestChaos65_LateArrivalUsesTheCacheNotANewFlight(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	url, hits := staticResponder(t, func() []byte { return body })
	leaf := ca.issueLeaf(t, 78, url)
	body = ca.sign(t, cryptoocsp.Response{Status: cryptoocsp.Good, SerialNumber: leaf.SerialNumber})

	oc := New()
	oc.Enable()
	key := certKey(leaf, ca.cert)

	// The leader's round: one query, verdict cached, flight removed.
	if revoked, _ := oc.resolve(key, leaf, ca.cert); revoked {
		t.Fatal("the healthy response should not be revoked")
	}
	if hits.Load() != 1 {
		t.Fatalf("responder queried %d times on the first round, want 1", hits.Load())
	}

	// The late arrival: it already missed the cache in VerifyPeerCertificate
	// and reaches resolve after the flight is gone.
	if revoked, _ := oc.resolve(key, leaf, ca.cert); revoked {
		t.Fatal("the cached verdict should not be revoked")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("a late arrival started a second responder query (%d hits total) — "+
			"resolve must re-check the cache before opening a flight", got)
	}
}

// TestChaos65_RevokedWinsOverAnEarlierGood — Codex P1, round 2.
//
// A SECURITY POSTURE CHANGED AS A SIDE EFFECT OF A COST CHANGE. The pre-CHAOS-65
// loop continued past every non-revoked answer and returned revoked if ANY
// responder said so; the rewrite added `case Good: return` to save queries, so
// the FIRST responder decides. The peer writes the AIA list and its ORDER, so
// that hands the verdict back to the party being checked — the exact failure
// this sweep is named for — and it also accepts a certificate during ordinary
// responder replication lag.
func TestChaos65_RevokedWinsOverAnEarlierGood(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var goodBody, revokedBody []byte
	goodURL, goodHits := staticResponder(t, func() []byte { return goodBody })
	revokedURL, revokedHits := staticResponder(t, func() []byte { return revokedBody })

	// The peer lists the agreeable responder FIRST.
	leaf := ca.issueLeaf(t, 81, goodURL, revokedURL)
	goodBody = ca.sign(t, cryptoocsp.Response{Status: cryptoocsp.Good, SerialNumber: leaf.SerialNumber})
	revokedBody = ca.sign(t, cryptoocsp.Response{
		Status:           cryptoocsp.Revoked,
		SerialNumber:     leaf.SerialNumber,
		RevokedAt:        time.Now().Add(-time.Hour),
		RevocationReason: cryptoocsp.KeyCompromise,
	})

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
		t.Fatal("an earlier responder's GOOD short-circuited a later responder's REVOKED — " +
			"the peer orders its own AIA list, so first-wins hands it the verdict")
	}
	if goodHits.Load() == 0 || revokedHits.Load() == 0 {
		t.Fatalf("both responders must be consulted (good=%d revoked=%d)",
			goodHits.Load(), revokedHits.Load())
	}
	if oc.RevokedTotal() != 1 {
		t.Fatalf("RevokedTotal() = %d, want 1", oc.RevokedTotal())
	}
}

// TestChaos65_Control_GoodStillAcceptedAcrossSeveralResponders — the control:
// restoring "revoked wins" must not turn a healthy multi-responder certificate
// into a refusal.
func TestChaos65_Control_GoodStillAcceptedAcrossSeveralResponders(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	a, _ := staticResponder(t, func() []byte { return body })
	b, _ := staticResponder(t, func() []byte { return body })
	leaf := ca.issueLeaf(t, 82, a, b)
	body = ca.sign(t, cryptoocsp.Response{Status: cryptoocsp.Good, SerialNumber: leaf.SerialNumber})

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err != nil {
		t.Fatalf("a certificate every responder calls good must be accepted: %v", err)
	}
	if oc.FailClosedTotal() != 0 {
		t.Fatalf("FailClosedTotal() = %d on the healthy path", oc.FailClosedTotal())
	}
}

// TestChaos65_DNSRebindingRefusalIsCounted — Codex P2, round 2.
//
// ssrf.SafeDialContext re-checks the resolved address immediately before
// connect(2), which is the whole point of having it under the pre-flight
// ssrf.PrivateHost check. But its refusal surfaced as an ordinary transport
// error and was charged to nothing, so the DNS-rebinding attack the dialer
// exists to catch moved neither the API field nor
// culvert_ocsp_response_rejected_total{reason="responder_blocked"} — invisible
// on exactly the surface built to expose it.
//
// The rebind is simulated by priming the SSRF package's own DNS verdict cache
// so the pre-flight check passes, while the dial-time Control still sees a
// loopback address. That is precisely the public-then-private sequence.
func TestChaos65_DNSRebindingRefusalIsCounted(t *testing.T) {
	ssrf.CacheReset()
	t.Cleanup(ssrf.CacheReset)
	ca := newTestCA(t, "issuer")

	url, hits := staticResponder(t, func() []byte { return nil })
	leaf := ca.issueLeaf(t, 83, url)

	// Pre-flight says public (the attacker's first DNS answer)...
	ssrf.CacheStore("127.0.0.1", false)

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
		t.Fatal("a responder that rebinds to a private address must fail closed")
	}
	// ...and the dial must have been refused, not completed.
	if n := hits.Load(); n != 0 {
		t.Fatalf("the rebound dial reached the private address %d time(s)", n)
	}
	if got := oc.ResponderBlockedTotal(); got != 1 {
		t.Fatalf("ResponderBlockedTotal() = %d, want 1 — a connect-time SSRF refusal "+
			"is invisible on the surface built to expose it", got)
	}
}

// TestChaos65_CachedVerdictExpiresAtTheSignersDeadline — Codex P1, round 3.
//
// Two checks bound a verdict at PARSE time and only one of them was carried
// into the cache. responseFresh bounds the ASSERTION (NextUpdate); the earlier
// Codex round made the cache respect it. responderAuthorized bounds the SIGNER
// (the delegate's own validity window) and the cache ignored it entirely.
//
// So a delegate expiring in seconds could sign a "good" whose NextUpdate is a
// day out: the handshake that parsed it cached the verdict, and every later
// handshake kept accepting the certificate for the rest of the cache TTL — while
// a re-parse of those identical bytes would have refused them as an unauthorized
// responder. A verdict outliving the authority it rests on.
//
// The delegate here is valid now and expires long before both the response's
// NextUpdate and the cache TTL, so the signer's deadline is the only thing that
// can produce a correct expiry.
//
// No new CONTROL accompanies this gate, deliberately, and both halves of that
// were checked rather than assumed. The dangerous wrong fix is capping so
// aggressively that nothing caches at all; reintroducing it (responseValidUntil
// returning ThisUpdate outright) fails three gates that already exist —
// TestChaos65_Control_HealthyGoodResponseIsStillAccepted,
// TestChaos65_CachedVerdictExpiresAtTheResponseDeadline and
// TestChaos65_LateArrivalUsesTheCacheNotANewFlight — plus this one, so it is
// covered several times over. The other candidate wrong fix — capping
// unconditionally instead of mirroring responderAuthorized's branches — turns
// out not to be harmful at all: it can differ only while the ISSUER itself has
// less than cacheTTL remaining, i.e. while the whole chain is hours from dying,
// and the cost is then a few extra responder queries. A gate pinning against it
// would block a reasonable simplification rather than catch a defect, so there
// isn't one. (The control written for it first was vacuous for exactly this
// reason: the fixture CA's lifetime equals cacheTTL, so the issuer cap could
// never bite and the test passed against the mutation it was meant to catch.)
func TestChaos65_CachedVerdictExpiresAtTheSignersDeadline(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")

	var body []byte
	url, _ := staticResponder(t, func() []byte { return body })
	leaf := ca.issueLeaf(t, 91, url)

	// Authorized delegate, valid right now, gone in 30s.
	delegateExpiry := time.Now().Add(30 * time.Second)
	delegate, delegateKey := ca.issueDelegateUntil(t, 92, true, delegateExpiry)

	// ...signing a response the responder claims is good for a whole day.
	resp, err := cryptoocsp.CreateResponse(ca.cert, delegate, cryptoocsp.Response{
		Status:       cryptoocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(24 * time.Hour),
		Certificate:  delegate,
	}, delegateKey)
	if err != nil {
		t.Fatalf("create delegated response: %v", err)
	}
	body = resp

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err != nil {
		t.Fatalf("a currently-valid delegate's GOOD response must be accepted: %v", err)
	}

	entry, ok := oc.cache[certKey(leaf, ca.cert)]
	if !ok {
		t.Fatal("the verdict should be cached")
	}
	limit := delegateExpiry.Add(responseClockSkew)
	if entry.expiresAt.After(limit) {
		t.Fatalf("verdict cached until %v, past the delegate's own NotAfter+skew %v — "+
			"the cache keeps admitting a certificate on a signer that a re-parse "+
			"would reject as unauthorized",
			entry.expiresAt.UTC(), limit.UTC())
	}
}

// TestChaos65_ResolutionFailureIsNotCountedAsAnSSRFRefusal — Codex P2, round 4.
//
// ssrf.PrivateHostContext has THREE outcomes and the call site treated it as
// two: allowed, refused-as-private, and could-not-determine (DNS failure, or
// this query's budget expiring mid-lookup). Charging blockedTotal for "the
// guard returned an error" meant an ordinary DNS outage inflated
// culvert_ocsp_response_rejected_total{reason="responder_blocked"} — a counter
// whose runbook tells the operator the responder resolved to a private address
// and points them at a different remediation entirely.
//
// Same rule as the not_for_certificate finding earlier in this PR, one counter
// over: an accusation is charged only when it is demonstrable.
//
// The responder host here is unresolvable, so the guard fails without ever
// establishing anything about it.
func TestChaos65_ResolutionFailureIsNotCountedAsAnSSRFRefusal(t *testing.T) {
	allowLoopback(t)
	ca := newTestCA(t, "issuer")
	// RFC 6761 reserves .invalid as guaranteed-not-to-resolve.
	leaf := ca.issueLeaf(t, 94, "http://responder.invalid./ocsp")

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
		t.Fatal("an unreachable responder must still fail closed")
	}

	if got := oc.ResponderBlockedTotal(); got != 0 {
		t.Fatalf("responder_blocked charged %d for a DNS failure — the operator is told "+
			"this responder resolved to a private address, and it did not; nothing "+
			"about the host was established", got)
	}
	// It IS a refused handshake, and that accounting must still be there.
	if got := oc.FailClosedTotal(); got == 0 {
		t.Fatal("an unresolvable responder must still be counted as a fail-closed handshake")
	}
}

// TestChaos65_Control_PrivateResponderIsStillCountedAsBlocked is the CONTROL
// for the gate above, and it is not optional: the cheapest way to stop
// miscounting DNS failures is to stop charging blockedTotal at all, which would
// silently delete the only signal that a certificate is steering this appliance
// at its own internal network.
func TestChaos65_Control_PrivateResponderIsStillCountedAsBlocked(t *testing.T) {
	ca := newTestCA(t, "issuer")
	// NOT allowLoopback: the guard must genuinely refuse this one.
	leaf := ca.issueLeaf(t, 95, "http://127.0.0.1:9/ocsp")

	oc := New()
	oc.Enable()
	if err := oc.VerifyPeerCertificate([][]byte{leaf.Raw}, [][]*x509.Certificate{{leaf, ca.cert}}); err == nil {
		t.Fatal("a private-address responder must fail closed")
	}

	if got := oc.ResponderBlockedTotal(); got == 0 {
		t.Fatal("a responder resolving to a private address must still charge " +
			"responder_blocked — narrowing the counter must not silence the real signal")
	}
}
