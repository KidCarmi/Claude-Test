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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
