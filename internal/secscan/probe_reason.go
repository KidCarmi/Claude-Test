package secscan

// probe_reason.go — BOUNDED reason classes for the remote scan-service
// liveness/status probes.
//
// The admin read surfaces (`GET /api/security-scan/svc`, `GET
// /api/security-scan/status`) are VIEWER-role and used to splice the raw
// probe error into their JSON. That error is not safe to render:
//
//   - http.NewRequestWithContext on an unparseable base URL returns
//     *url.Error{Op:"parse"}, whose text embeds the URL VERBATIM — including a
//     cleartext password (net/http's password masking applies to transport
//     errors, not to this one).
//   - a transport *url.Error masks the password but still carries the
//     USERNAME and the full origin.
//
// Same doctrine as the upstream-pool probe classifier and the CHAOS-53 remote
// fail-open alert: the surface carries a bounded class, the full cause goes to
// the log. Adding a class is a deliberate act — never interpolate a message.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Bounded probe reason classes.
const (
	ProbeReasonNotConfigured = "not_configured"
	ProbeReasonInvalidURL    = "invalid_url"
	ProbeReasonTimeout       = "timeout"
	ProbeReasonConnectFailed = "connect_failed"
	ProbeReasonTLSFailed     = "tls_failed"
	ProbeReasonBadResponse   = "bad_response"
	ProbeReasonUnavailable   = "unavailable"
)

// HTTPStatusError reports a probe answered with a non-200 status. The code is
// a small integer the far end cannot use to smuggle text, so it is safe to
// render and is worth keeping for diagnosis.
type HTTPStatusError struct{ Code int }

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("health check returned HTTP %d", e.Code)
}

// ErrNotConfigured is the sentinel for a probe attempted while remote mode is
// off, so the classifier never has to match on message text.
var ErrNotConfigured = errors.New("remote scanner not configured")

// ProbeFailureReason maps a Health/Status error to a bounded class safe to
// render on a viewer surface. It never returns caller- or far-end-controlled
// text. A nil error is "" (the caller reports success).
func ProbeFailureReason(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrNotConfigured) {
		return ProbeReasonNotConfigured
	}

	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		return "http_" + strconv.Itoa(httpErr.Code)
	}

	// The parse branch is tested BEFORE any other *url.Error handling: a parse
	// failure is itself a *url.Error, and it is the one whose text embeds the
	// raw URL — password included.
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Op == "parse" {
		return ProbeReasonInvalidURL
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return ProbeReasonTimeout
	case isTLSError(err):
		return ProbeReasonTLSFailed
	case isDialError(err):
		return ProbeReasonConnectFailed
	case isDecodeError(err):
		return ProbeReasonBadResponse
	}
	return ProbeReasonUnavailable
}

// isTimeout reports a net.Error timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isDialError reports a failure to establish or use the connection (refused,
// unreachable, DNS). Matched structurally: the messages are platform-specific.
func isDialError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

// isTLSError reports a handshake/verification failure. Verification has a
// typed error; the rest of the handshake failures do not, so a narrow
// TLS-specific substring is used — it is matched only to CLASSIFY, never
// rendered, so it cannot carry the URL onto a response.
func isTLSError(err error) bool {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "tls:") || strings.Contains(msg, "x509:")
}

// isDecodeError reports a well-formed transport exchange whose BODY could not
// be understood (the /status JSON).
func isDecodeError(err error) bool {
	var syn *json.SyntaxError
	if errors.As(err, &syn) {
		return true
	}
	var typ *json.UnmarshalTypeError
	if errors.As(err, &typ) {
		return true
	}
	return errors.Is(err, io.ErrUnexpectedEOF)
}
