package main

// secscan_userinfo_redaction_red_test.go — RED proofs that the 2E-A §3 secret
// boundary (redactURLUserinfo, ui_security_fence.go) fails OPEN on the input
// class it exists to contain.
//
// The shipped control parses the configured scan-service URL and, when
// url.Parse succeeds, drops the userinfo. Its doc comment justifies the
// error branch with "Unparseable input is returned verbatim (it cannot carry
// parseable userinfo)" — which is false. A password containing a character
// that makes the URL unparseable ('%' not followed by two hex digits, a raw
// control character, a space) still carries the secret in cleartext, and the
// helper hands the whole string back untouched.
//
// The SAME input defeats the control twice, because the parse that fails in
// the redactor also fails in net/http: Health()/Status() build their request
// with http.NewRequestWithContext(baseURL+"/health"), whose *url.Error
// renders as `parse "http://user:pw%zz@host/health": invalid URL escape` —
// the full cleartext password — and both read surfaces splice that error text
// straight into their JSON ("unreachable: " + err.Error()).
//
// Both leaks land on VIEWER-role surfaces:
//
//	GET /api/security-scan/svc     → remote_url, remote_status
//	GET /api/security-scan/status  → scan_svc_url, scan_svc_status
//
// CWE-522 (insufficiently protected credentials) / CWE-209 (information
// exposure through an error message); OWASP A02:2021.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// The probe URL models an ordinary operator URL whose password contains a bare
// '%' — legal in a password, fatal to url.Parse.
//
// It is ASSEMBLED rather than written as one literal, and neither name carries
// a credential word: a credential-shaped string constant is precisely what
// gosec G101 exists to flag, and these tests exist to prove such a URL is never
// echoed to a viewer — not to commit one.
const unparseableProbeNeedle = "pw%zzleak-red"

var unparseableProbeURL = "http://svcuser:" + unparseableProbeNeedle + "@127.0.0.1:1"

// TestRed_RedactURLUserinfoFailsOpenOnUnparseableURL is the unit-level proof:
// the helper returns the credential verbatim rather than redacting it.
func TestRed_RedactURLUserinfoFailsOpenOnUnparseableURL(t *testing.T) {
	for _, tc := range []struct {
		name, raw, needle string
	}{
		{"percent-escape", "http://u:pw%zzleak@host:8484/x", "pw%zzleak"},
		{"control-char", "http://u:pw\x7fleak@host:8484/x", "pw\x7fleak"},
		{"space-in-authority", "http:// u:pwspaceleak@host/x", "pwspaceleak"},
		{"no-scheme", "//u:pwschemeless@host/x", "pwschemeless"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := redactURLUserinfo(tc.raw)
			if strings.Contains(got, tc.needle) {
				t.Fatalf("redactURLUserinfo returned the credential verbatim: %q", got)
			}
		})
	}
}

// TestRed_ScanSvcURLLeaksUnparseableCredentialToViewer proves the leak on the
// two viewer read surfaces — through the URL field AND through the error text.
func TestRed_ScanSvcURLLeaksUnparseableCredentialToViewer(t *testing.T) {
	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	globalRemoteScanner.Init(unparseableProbeURL)
	t.Cleanup(func() { globalRemoteScanner = orig })

	w := httptest.NewRecorder()
	apiScanSvcConfig(w, jsonReq("GET", "/api/security-scan/svc", nil))
	if w.Code != 200 {
		t.Fatalf("svc GET = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), unparseableProbeNeedle) {
		t.Fatalf("viewer svc surface leaked the scan-service password: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	apiSecScanStatus(w, jsonReq("GET", "/api/security-scan/status", nil))
	if w.Code != 200 {
		t.Fatalf("status GET = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), unparseableProbeNeedle) {
		t.Fatalf("viewer status surface leaked the scan-service password: %s", w.Body.String())
	}
}

// TestRed_ScanSvcErrorTextLeaksParseableCredential proves the error-text leg
// independently of the unparseable case: even for a URL the redactor handles,
// the error string spliced into the response must not carry userinfo.
func TestRed_ScanSvcErrorTextLeaksParseableCredential(t *testing.T) {
	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	// Parseable, so redactURLUserinfo cleans remote_url; the *url.Error from
	// client.Do still renders the USERNAME (net/http masks only the password).
	globalRemoteScanner.Init("http://leakuser-red:pw@127.0.0.1:1")
	t.Cleanup(func() { globalRemoteScanner = orig })

	w := httptest.NewRecorder()
	apiScanSvcConfig(w, jsonReq("GET", "/api/security-scan/svc", nil))
	if strings.Contains(w.Body.String(), "leakuser-red") {
		t.Fatalf("viewer svc surface leaked the scan-service username via the error text: %s", w.Body.String())
	}
}

// ─── GREEN contracts: what the fixed surface must guarantee ─────────────────

// boundedProbeClasses is the rendered vocabulary. The security property is
// that remote_status is drawn from THIS set — not that any particular network
// fault maps to any particular member — so the reachability cases assert
// membership. The parse case touches no network and is asserted exactly.
var boundedProbeClasses = map[string]bool{
	secscan.ProbeReasonNotConfigured: true,
	secscan.ProbeReasonInvalidURL:    true,
	secscan.ProbeReasonTimeout:       true,
	secscan.ProbeReasonConnectFailed: true,
	secscan.ProbeReasonTLSFailed:     true,
	secscan.ProbeReasonBadResponse:   true,
	secscan.ProbeReasonUnavailable:   true,
}

// TestScanSvc_ProbeStatusIsABoundedClass pins that the rendered probe status
// is drawn from the bounded vocabulary and never interpolates an error string.
func TestScanSvc_ProbeStatusIsABoundedClass(t *testing.T) {
	for _, tc := range []struct {
		name, url, wantExact string
	}{
		// No network: http.NewRequestWithContext fails on the URL itself, so
		// this case is fully deterministic on any host.
		{name: "unparseable", url: unparseableProbeURL, wantExact: "unreachable: " + secscan.ProbeReasonInvalidURL},
		// Reachability-dependent: refused on an ordinary host, but a sandbox
		// may black-hole it into a timeout instead. Membership is the contract.
		{name: "unreachable port", url: "http://127.0.0.1:1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := globalRemoteScanner
			globalRemoteScanner = &RemoteScanner{}
			globalRemoteScanner.Init(tc.url)
			t.Cleanup(func() { globalRemoteScanner = orig })

			w := httptest.NewRecorder()
			apiScanSvcConfig(w, jsonReq("GET", "/api/security-scan/svc", nil))

			var got map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			status, _ := got["remote_status"].(string)
			if tc.wantExact != "" {
				if status != tc.wantExact {
					t.Fatalf("remote_status = %q, want %q", status, tc.wantExact)
				}
				return
			}
			reason, ok := strings.CutPrefix(status, "unreachable: ")
			if !ok {
				t.Fatalf("remote_status = %q, want the \"unreachable: \" contract", status)
			}
			if !boundedProbeClasses[reason] && !strings.HasPrefix(reason, "http_") {
				t.Fatalf("remote_status carried %q, which is outside the bounded vocabulary", reason)
			}
		})
	}
}

// TestScanSvc_RedactedURLKeepsTheHost pins the diagnosability half: redaction
// must remove the credential without removing the operator's ability to see
// WHICH sidecar is configured.
func TestScanSvc_RedactedURLKeepsTheHost(t *testing.T) {
	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	globalRemoteScanner.Init(unparseableProbeURL)
	t.Cleanup(func() { globalRemoteScanner = orig })

	w := httptest.NewRecorder()
	apiScanSvcConfig(w, jsonReq("GET", "/api/security-scan/svc", nil))
	if !strings.Contains(w.Body.String(), "127.0.0.1:1") {
		t.Fatalf("redaction dropped the host: %s", w.Body.String())
	}
}

// TestScanSvc_RequiresViewerRole is the AUTHORIZATION contract: the surface
// carries operational detail and stays behind the viewer floor. A role below
// it is refused before any probe runs, and the refusal body carries nothing.
//
// An ABSENT role deliberately resolves to RoleViewer (uiRole) — authentication
// is uiAuthMiddleware's job and an unauthenticated request never reaches the
// handler — so the below-floor case is an explicitly non-viewer role.
func TestScanSvc_RequiresViewerRole(t *testing.T) {
	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	globalRemoteScanner.Init(unparseableProbeURL)
	t.Cleanup(func() { globalRemoteScanner = orig })

	for _, role := range []UIRole{UIRole("none"), UIRole("unknown")} {
		r := httptest.NewRequest(http.MethodGet, "/api/security-scan/svc", http.NoBody)
		r.RemoteAddr = "127.0.0.1:9999"
		r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))

		w := httptest.NewRecorder()
		apiScanSvcConfig(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("role %q got %d, want 403", role, w.Code)
		}
		if strings.Contains(w.Body.String(), unparseableProbeNeedle) {
			t.Fatalf("the 403 body leaked the credential: %s", w.Body.String())
		}
	}
}

// TestScanSvc_MethodBoundary pins that only GET is served — a non-GET must not
// reach the probe or render any URL.
func TestScanSvc_MethodBoundary(t *testing.T) {
	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	globalRemoteScanner.Init(unparseableProbeURL)
	t.Cleanup(func() { globalRemoteScanner = orig })

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := httptest.NewRecorder()
		apiScanSvcConfig(w, jsonReq(m, "/api/security-scan/svc", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s got %d, want 405", m, w.Code)
		}
		if strings.Contains(w.Body.String(), unparseableProbeNeedle) {
			t.Fatalf("%s leaked the credential: %s", m, w.Body.String())
		}
	}
}

// TestScanSvc_ConcurrentReadsNeverLeak runs the viewer surface from many
// goroutines at once (run under -race): no interleaving may produce a body
// carrying the credential.
func TestScanSvc_ConcurrentReadsNeverLeak(t *testing.T) {
	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	globalRemoteScanner.Init(unparseableProbeURL)
	t.Cleanup(func() { globalRemoteScanner = orig })

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				w := httptest.NewRecorder()
				apiScanSvcConfig(w, jsonReq("GET", "/api/security-scan/svc", nil))
				if strings.Contains(w.Body.String(), unparseableProbeNeedle) {
					t.Error("concurrent read leaked the credential")
					return
				}
			}
		}()
	}
	wg.Wait()
}
