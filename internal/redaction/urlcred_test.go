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
	for _, tc := range []struct{ name, in, needle string }{
		{"bare percent", "http://u:pw%zz@host:8484/x", "pw%zz"},
		{"control char", "http://u:pw\x7f@host:8484/x", "pw\x7f"},
		{"space in authority", "http:// u:pwspace@host/x", "pwspace"},
		{"tab in authority", "http://u:pw\tspace@host/x", "pw\tspace"},
		{"no scheme", "u:pwbare%zz@host:8484", "pwbare%zz"},
		{"nul byte", "http://u:pw\x00null@host/x", "pw\x00null"},
		// Codex P1: a password carrying an AUTHORITY DELIMITER. The first fix
		// bounded its search at the first '/', '?' or '#', which on a string
		// url.Parse rejected proves nothing — the search stopped before the '@'
		// and the whole input, password included, was handed back.
		{"question mark in password", "http://user:pw?part@host", "pw?part"},
		{"slash in password", "http://user:pw/part@host", "pw/part"},
		{"hash in password", "http://user:pw#part@host", "pw#part"},
		{"all three delimiters", "http://user:p/w?x#y@host:8484", "p/w?x#y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := URLUserinfo(tc.in)
			if strings.Contains(got, tc.needle) {
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
	const needle = "pw%zzconcurrent"
	in := "http://u:" + needle + "@host:8484/x"
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if strings.Contains(URLUserinfo(in), needle) {
					t.Error("credential survived under concurrent use")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestURLUserinfo_NoDelimiterInAPasswordCanDefeatIt is the PROPERTY behind the
// Codex P1: the first fix leaked for exactly the characters it used as its
// authority bound, so pinning the three known ones would leave the class open.
// This sweeps every ASCII byte as the password's payload and requires that none
// of them lets the credential through.
func TestURLUserinfo_NoDelimiterInAPasswordCanDefeatIt(t *testing.T) {
	for b := 0; b < 128; b++ {
		c := byte(b)
		if c == '@' { // an '@' inside the password moves the separator, not a leak
			continue
		}
		pw := "aa" + string(c) + "bb"
		raw := "http://user:" + pw + "@host.example:8484/p"
		got := URLUserinfo(raw)
		if strings.Contains(got, pw) {
			t.Fatalf("byte %#02x in the password survived: URLUserinfo(%q) = %q", c, raw, got)
		}
		if strings.Contains(got, "user:") {
			t.Fatalf("byte %#02x left the username behind: %q", c, got)
		}
	}
}

// TestURLUserinfo_NeverReturnsAnAuthorityAt is the invariant in its most
// general form: whatever comes out, no '@' may remain in an authority
// position. It is the single assertion that a future rewrite cannot pass while
// reintroducing this class.
func TestURLUserinfo_NeverReturnsAnAuthorityAt(t *testing.T) {
	for _, raw := range []string{
		"http://user:pw?part@host",
		"http://user:pw/part@host",
		"http://user:pw#part@host",
		"http://u:pw%zz@host:8484/x",
		"http:// u:pw@host/x",
		"u:pw@host:8484",
		"//u:pw@host/x",
		"http://a@b@c@host/x",
	} {
		got := URLUserinfo(raw)
		start := authorityStart(got)
		if start < 0 {
			continue
		}
		authority := got[start:]
		if i := strings.IndexAny(authority, "/?#"); i >= 0 {
			authority = authority[:i]
		}
		if strings.ContainsRune(authority, '@') {
			t.Fatalf("URLUserinfo(%q) = %q — authority %q still carries an '@'", raw, got, authority)
		}
	}
}
