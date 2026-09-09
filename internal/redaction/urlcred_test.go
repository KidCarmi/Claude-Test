package redaction

import (
	"strings"
	"sync"
	"testing"
)

// TestURLUserinfo_RemovesCredentials is the POSITIVE contract: a parseable URL
// carrying userinfo loses it, and the host stays identifiable for diagnosis.
func TestURLUserinfo_RemovesCredentials(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"user and password", "http://u:pw@host:8484/scan", "http://host:8484/scan"},
		{"user only", "http://u@host:8484/scan", "http://host:8484/scan"},
		{"https", "https://u:pw@host/scan?q=1", "https://host/scan?q=1"},
		{"at in password", "http://u:p@ss@host/x", "http://host/x"},
		{"scheme relative", "//u:pw@host/x", "//host/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := URLUserinfo(tc.in); got != tc.want {
				t.Fatalf("URLUserinfo(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestURLUserinfo_FailsClosedOnUnparseableInput is the REGRESSION gate: the
// first shipped shape returned unparseable input verbatim, which leaked every
// password containing a character url.Parse rejects.
func TestURLUserinfo_FailsClosedOnUnparseableInput(t *testing.T) {
	for _, tc := range []struct{ name, in, secret string }{
		{"bare percent", "http://u:pw%zz@host:8484/x", "pw%zz"},
		{"control char", "http://u:pw\x7f@host:8484/x", "pw\x7f"},
		{"space in authority", "http:// u:pwspace@host/x", "pwspace"},
		{"tab in authority", "http://u:pw\tspace@host/x", "pw\tspace"},
		{"no scheme", "u:pwbare%zz@host:8484", "pwbare%zz"},
		{"nul byte", "http://u:pw\x00null@host/x", "pw\x00null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := URLUserinfo(tc.in)
			if strings.Contains(got, tc.secret) {
				t.Fatalf("URLUserinfo(%q) = %q — credential survived", tc.in, got)
			}
			if strings.Contains(got, "@") {
				t.Fatalf("URLUserinfo(%q) = %q — authority still carries an '@'", tc.in, got)
			}
		})
	}
}

// TestURLUserinfo_LeavesCredentialFreeInputAlone is the NEGATIVE contract: the
// redactor must not mangle input that carries no userinfo, and must not treat
// an '@' outside the authority as a credential.
func TestURLUserinfo_LeavesCredentialFreeInputAlone(t *testing.T) {
	for _, in := range []string{
		"",
		"http://host:8484/scan",
		"https://scan-svc.internal/health",
		"http://host/path/user@example.com",
		"http://host/x?contact=user@example.com",
		"http://host/x#user@example.com",
		"not a url at all",
		"/relative/path",
	} {
		t.Run(in, func(t *testing.T) {
			if got := URLUserinfo(in); got != in {
				t.Fatalf("URLUserinfo(%q) = %q, want it unchanged", in, got)
			}
		})
	}
}

// TestURLUserinfo_UnparseableKeepsAuthorityOutsideCredential proves the
// lexical fallback strips the credential WITHOUT eating the host or the path —
// a redactor that returned a bare marker would be safe but undiagnosable.
func TestURLUserinfo_UnparseableKeepsAuthorityOutsideCredential(t *testing.T) {
	got := URLUserinfo("http://u:pw%zz@scan-svc.internal:8484/health?x=1")
	if got != "http://scan-svc.internal:8484/health?x=1" {
		t.Fatalf("lexical fallback = %q", got)
	}
}

// TestURLUserinfo_ConcurrentUseIsSafe runs the redactor from many goroutines:
// it must be pure and hold no shared state (run under -race).
func TestURLUserinfo_ConcurrentUseIsSafe(t *testing.T) {
	const secret = "pw%zzconcurrent"
	in := "http://u:" + secret + "@host:8484/x"
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if strings.Contains(URLUserinfo(in), secret) {
					t.Error("credential survived under concurrent use")
					return
				}
			}
		}()
	}
	wg.Wait()
}
