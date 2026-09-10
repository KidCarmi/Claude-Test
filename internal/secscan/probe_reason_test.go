package secscan

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestProbeFailureReason_NeverRendersTheURL is the SECURITY contract: whatever
// the error carries, the returned class must not contain the origin, the
// username or the password. The parse error is the dangerous one — its text
// embeds the raw URL with the password in cleartext.
func TestProbeFailureReason_NeverRendersTheURL(t *testing.T) {
	const secret = "pw%zzsecret"
	raw := "http://svcuser:" + secret + "@scan-svc.internal:8484/health"

	_, parseErr := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, http.NoBody)
	if parseErr == nil {
		t.Fatal("precondition: the URL was expected to be unparseable")
	}
	if !strings.Contains(parseErr.Error(), secret) {
		t.Fatalf("precondition: the parse error was expected to embed the password: %v", parseErr)
	}

	for _, err := range []error{
		parseErr,
		&url.Error{Op: "Get", URL: raw, Err: errors.New("dial tcp: connection refused")},
		fmt.Errorf("wrapped: %w", parseErr),
	} {
		got := ProbeFailureReason(err)
		for _, forbidden := range []string{secret, "svcuser", "scan-svc.internal"} {
			if strings.Contains(got, forbidden) {
				t.Fatalf("ProbeFailureReason(%v) = %q — leaked %q", err, got, forbidden)
			}
		}
	}
}

// TestProbeFailureReason_Classes pins the bounded vocabulary. A new class is a
// deliberate act; an unrecognised error must fall to "unavailable", never to
// interpolated text.
func TestProbeFailureReason_Classes(t *testing.T) {
	badURL, parseErr := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://u:p%zz@h/x", http.NoBody)
	_ = badURL

	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"not configured", ErrNotConfigured, ProbeReasonNotConfigured},
		{"wrapped not configured", fmt.Errorf("probe: %w", ErrNotConfigured), ProbeReasonNotConfigured},
		{"parse", parseErr, ProbeReasonInvalidURL},
		{"http status", &HTTPStatusError{Code: 503}, "http_503"},
		{"wrapped http status", fmt.Errorf("probe: %w", &HTTPStatusError{Code: 401}), "http_401"},
		{"deadline", context.DeadlineExceeded, ProbeReasonTimeout},
		{"dial", &url.Error{Op: "Get", URL: "http://h/x", Err: &net.OpError{Op: "dial", Err: errors.New("refused")}}, ProbeReasonConnectFailed},
		{"dns", &net.DNSError{Err: "no such host", Name: "h"}, ProbeReasonConnectFailed},
		{"tls verify", &tls.CertificateVerificationError{}, ProbeReasonTLSFailed},
		{"json syntax", &json.SyntaxError{}, ProbeReasonBadResponse},
		{"unknown", errors.New("something else entirely"), ProbeReasonUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProbeFailureReason(tc.err); got != tc.want {
				t.Fatalf("ProbeFailureReason = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestProbeFailureReason_ClassIsBounded pins that every class is a short,
// fixed token — nothing a far end or an operator string can grow.
func TestProbeFailureReason_ClassIsBounded(t *testing.T) {
	for _, err := range []error{
		ErrNotConfigured,
		&HTTPStatusError{Code: 599},
		context.DeadlineExceeded,
		errors.New(strings.Repeat("A", 4096)),
	} {
		got := ProbeFailureReason(err)
		if len(got) > 32 {
			t.Fatalf("reason class %q is not bounded (%d bytes)", got, len(got))
		}
		if strings.ContainsAny(got, " \"'\r\n:/@") {
			t.Fatalf("reason class %q carries structure it should not", got)
		}
	}
}

// TestHealthAndStatus_ReportTheSentinelWhenDisabled pins that the disabled
// probe path is classifiable without message matching.
func TestHealthAndStatus_ReportTheSentinelWhenDisabled(t *testing.T) {
	rs := &RemoteScanner{}
	if err := rs.Health(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Health on a disabled scanner = %v, want ErrNotConfigured", err)
	}
	if _, err := rs.Status(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Status on a disabled scanner = %v, want ErrNotConfigured", err)
	}
}
