package main

import (
	"bufio"
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// SEC-SOCKS5-LOG-1 — the SOCKS5 destination is ATTACKER BYTES, and every log
// site that names it must sanitise it.
//
// The SOCKS5 request's DOMAINNAME field (RFC 1928 §4, ATYP 0x03) is a
// length-prefixed byte string read straight off the socket:
//
//	domain := make([]byte, lenBuf[0])
//	io.ReadFull(r, domain)
//	host = string(domain)
//
// Nothing validates those bytes. They may carry NUL, LF, CR, TAB, DEL, or an
// ANSI escape sequence. This is the ONE protocol Culvert serves where that is
// true: the HTTP and CONNECT paths inherit net/http's own request-line and
// header validation, which rejects control characters (proved below by
// TestHTTPHostHeader_RejectsMostControlCharacters, which also records the one
// byte it does NOT reject).
//
// The strict host-canonicalisation gate is NOT a second line of defence here,
// and that is the trap this file exists to close. normalizeHostStrict rejects
// only non-ASCII and malformed ACE labels; a pure-ASCII host carrying a
// newline passes it unchanged (TestNormalizeHostStrict_IsNotALogSanitiser).
// So a host reaching the blocklist / SSRF / dial / success log sites can still
// contain a line terminator.
//
// The process log is Culvert's forensic record — it is what `internal/logsink`
// drains to the rotating file and what the syslog SIEM forwarder carries — so
// an unsanitised destination lets an unauthenticated client FORGE log lines:
// fabricate a "SOCKS5 OK" for a destination it never reached, or bury a real
// block under injected noise. CWE-117 / OWASP A09:2021.
//
// The repo convention is one line (CLAUDE.md, "User input in logs"): wrap with
// sanitizeLog(s) and use the %q verb. Two sites in handleSOCKS5 already did
// exactly that (INVALID_HOST, SHUTTING_DOWN) while four did not — which is why
// this is an oversight to close rather than a posture to debate.
// ─────────────────────────────────────────────────────────────────────────────

// syncBuf is a mutex-guarded log sink: handleSOCKS5 writes from its own
// goroutine while the test reads.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// captureLoggerForTest redirects the process logger into a buffer for the test.
//
// Registration ORDER is load-bearing: t.Cleanup is LIFO, so this must be called
// BEFORE startSOCKS5Listener. That listener's cleanup drains every in-flight
// handler; registering it later means it runs FIRST, so no handler can still be
// writing when the logger global is restored (a real -race failure otherwise).
func captureLoggerForTest(t *testing.T) *syncBuf {
	t.Helper()
	prev := logger
	sink := &syncBuf{}
	logger = log.New(sink, "", 0)
	t.Cleanup(func() { logger = prev })
	return sink
}

// socks5ConnectRaw performs the no-auth greeting and issues a CONNECT for a
// DOMAINNAME carrying arbitrary bytes. It deliberately does NOT go through the
// typed helpers, because the whole point is to put bytes on the wire that no
// well-formed client would send.
func socks5ConnectRaw(t *testing.T, addr, host string, port uint16) {
	t.Helper()
	if len(host) > 255 {
		t.Fatalf("DOMAINNAME is a 1-byte length prefix; host of %d bytes cannot be sent", len(host))
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil { // greeting, no-auth
		t.Fatalf("greeting write: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("greeting read: %v", err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))} // #nosec G115 -- length checked above
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("request write: %v", err)
	}
	// Best-effort: read whatever reply comes back so the handler has run to the
	// point of logging before we inspect the buffer.
	reply := make([]byte, 10)
	_, _ = io.ReadFull(conn, reply)
}

// waitForLogContaining polls the captured log until marker appears, so the test
// never races the handler goroutine.
func waitForLogContaining(t *testing.T, sink *syncBuf, marker string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := sink.String(); strings.Contains(got, marker) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no log line containing %q within 5s; captured:\n%q", marker, sink.String())
	return ""
}

// controlBytePayloads are the destination shapes an attacker can actually put
// on the wire. Each is embedded MID-HOST: blocklist ingestion trims surrounding
// whitespace, so a payload that only decorated the ends would prove nothing.
var controlBytePayloads = []struct {
	name string
	host string
}{
	// The headline case: a line terminator forges a complete, plausible log line.
	{"newline_forges_a_line", "evil-a.example\nsocks5 ok 10.0.0.9 -> bank.example.com:443"},
	{"crlf_forges_a_line", "evil-b.example\r\nsocks5 ok 10.0.0.9 -> bank.example.com:443"},
	// CR alone rewrites the visible line on a terminal without adding one.
	{"bare_cr_overwrites", "evil-c.example\rsocks5 ok 10.0.0.9 -> bank.example.com:443"},
	// TAB corrupts field-delimited ingestion without forging a line.
	{"tab_breaks_field_split", "evil-d.example\tsocks5\tok"},
	// ANSI escapes rewrite an operator's terminal.
	{"ansi_escape", "evil-e.example\x1b[2K\x1b[31mcompromised"},
	// NUL truncates C-string consumers downstream of the log.
	{"nul_truncates", "evil-f.example\x00hidden-suffix"},
	// DEL is a control byte above the C0 block; sanitizeLog covers it too.
	{"del_byte", "evil-g.example\x7fhidden"},
}

// TestSOCKS5_DestinationLogsCannotForgeLogLines is the DEFECT GATE. It drives
// the real handleSOCKS5 with a hostile DOMAINNAME and requires that nothing the
// client chose reaches the process log as a raw control byte.
//
// The blocklist branch is used because it is the one destination log site a
// test can reach with NO dependency on DNS, the network, or a dial: bl is a
// test-owned store, so the verdict is deterministic on any runner.
func TestSOCKS5_DestinationLogsCannotForgeLogLines(t *testing.T) {
	for _, tc := range controlBytePayloads {
		t.Run(tc.name, func(t *testing.T) {
			setupProxyTest(t)
			sink := captureLoggerForTest(t) // BEFORE the listener: see captureLoggerForTest
			bl.Add(tc.host)
			if !bl.IsBlocked(tc.host) {
				t.Fatalf("precondition: %q must be blocked for this test to reach the BLOCKED log site", tc.host)
			}

			ln := startSOCKS5Listener(t)
			socks5ConnectRaw(t, ln.Addr().String(), tc.host, 443)

			got := waitForLogContaining(t, sink, "SOCKS5 BLOCKED")
			assertNoRawControlBytes(t, got)
			assertNoForgedLine(t, got)
		})
	}
}

// assertNoRawControlBytes requires that the captured log carry no control byte
// other than the '\n' the logger itself appends to terminate each record.
func assertNoRawControlBytes(t *testing.T, captured string) {
	t.Helper()
	for _, line := range strings.Split(captured, "\n") {
		for i := 0; i < len(line); i++ {
			if c := line[i]; c < 0x20 || c == 0x7f {
				t.Errorf("raw control byte %#x survived into the process log at offset %d of line %q\n"+
					"a client-chosen destination must be sanitised before it is logged (CWE-117): "+
					"wrap it with sanitizeLog and print it with %%q", c, i, line)
				return
			}
		}
	}
}

// assertNoForgedLine requires that every line of the captured log be one the
// proxy actually emitted — i.e. the attacker's payload never became a record of
// its own. Only one genuine line is expected here (the BLOCKED verdict).
func assertNoForgedLine(t *testing.T, captured string) {
	t.Helper()
	lines := 0
	for _, line := range strings.Split(captured, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines++
		if !strings.HasPrefix(line, "SOCKS5 ") {
			t.Errorf("forged log record %q: the client's DOMAINNAME produced a line the proxy never emitted", line)
		}
	}
	if lines != 1 {
		t.Errorf("expected exactly 1 emitted log record, got %d; captured:\n%q", lines, captured)
	}
}

// TestSOCKS5_DestinationLogsStillNameTheHost is the CONTROL. The cheapest way
// to pass the gate above is to stop logging the destination at all, which would
// be far worse than the defect: the operator would lose the only record of what
// a client asked for. An ordinary host must still be identifiable in the log.
func TestSOCKS5_DestinationLogsStillNameTheHost(t *testing.T) {
	setupProxyTest(t)
	sink := captureLoggerForTest(t)
	const host = "blocked.example.com"
	bl.Add(host)

	ln := startSOCKS5Listener(t)
	socks5ConnectRaw(t, ln.Addr().String(), host, 443)

	got := waitForLogContaining(t, sink, "SOCKS5 BLOCKED")
	if !strings.Contains(got, host) {
		t.Errorf("the BLOCKED log line must still name the destination; got %q", got)
	}
}

// TestSOCKS5_EveryDestinationLogSiteSanitises is the STRUCTURAL WALL, and it is
// deliberately not a behavioural test: only two of the six destination log
// sites in handleSOCKS5 are reachable without DNS or a live dial, so a
// behavioural suite can never cover the other four. This gate reads the source
// instead and holds for every site, reachable or not.
//
// The rule: inside handleSOCKS5, every argument a log call interpolates must be
// either clientIP (a net.SplitHostPort product of the kernel-supplied peer
// address — never client-chosen bytes) or a value routed through sanitizeLog.
func TestSOCKS5_EveryDestinationLogSiteSanitises(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "socks5.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse socks5.go: %v", err)
	}

	var fn *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		if d, ok := n.(*ast.FuncDecl); ok && d.Name.Name == "handleSOCKS5" {
			fn = d
			return false
		}
		return true
	})
	if fn == nil {
		t.Fatal("handleSOCKS5 not found in socks5.go — this wall must be re-aimed, not deleted")
	}

	// clientIP is the ONLY bare identifier this wall admits. Widening this set
	// is how the defect comes back: add a name here only with the argument for
	// why those bytes cannot be client-chosen.
	safeBare := map[string]bool{"clientIP": true}

	checked := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "logger" {
			return true
		}
		if sel.Sel.Name != "Printf" && sel.Sel.Name != "Println" {
			return true
		}
		checked++
		for i, arg := range call.Args {
			if i == 0 {
				continue // the format string is a source-literal
			}
			if id, ok := arg.(*ast.Ident); ok && safeBare[id.Name] {
				continue
			}
			var b bytes.Buffer
			if err := printer.Fprint(&b, fset, arg); err != nil {
				t.Fatalf("render argument: %v", err)
			}
			expr := b.String()
			if !strings.Contains(expr, "sanitizeLog") {
				t.Errorf("handleSOCKS5 (%s): log argument %s is neither clientIP nor sanitised.\n"+
					"The SOCKS5 DOMAINNAME is raw attacker bytes; wrap it with sanitizeLog and use %%q (CWE-117).",
					fset.Position(call.Pos()), expr)
			}
		}
		return true
	})

	// A selector typo that matched nothing would let this wall pass forever.
	if checked < 4 {
		t.Fatalf("the wall inspected only %d log calls in handleSOCKS5; it is no longer finding them", checked)
	}
}

// TestNormalizeHostStrict_IsNotALogSanitiser records the ROOT CAUSE as an
// executable fact, so a future reader cannot conclude that the strict
// canonicalisation gate in front of these log sites already neutralises the
// bytes. It does not: it rejects non-ASCII and malformed ACE labels, and is
// deliberately silent about control characters.
//
// This is NOT a request to change normalizeHostStrict. Making it reject control
// bytes would change which destinations the proxy serves — a policy decision
// with its own blast radius — while the defect here is only that a log site
// failed to sanitise what it prints.
func TestNormalizeHostStrict_IsNotALogSanitiser(t *testing.T) {
	for _, host := range []string{
		"evil.example\nforged",
		"evil.example\rforged",
		"evil.example\tforged",
		"evil.example\x1b[31mforged",
		"evil.example\x7fforged",
	} {
		norm, ok := normalizeHostStrict(host)
		if !ok {
			t.Fatalf("normalizeHostStrict(%q) rejected the host; this test's premise (and the log sites' exposure) has changed — re-derive the fix before relaxing anything", host)
		}
		if !strings.ContainsAny(norm, "\n\r\t\x1b\x7f") {
			t.Errorf("normalizeHostStrict(%q) = %q stripped the control byte; it is not supposed to, and the log sites must not rely on it", host, norm)
		}
	}
}

// TestHTTPHostHeader_RejectsMostControlCharacters pins WHY this finding is
// SOCKS5-specific — and, just as importantly, the one place it is not.
//
// net/http rejects a Host header or CONNECT authority carrying LF, CR, ESC or
// DEL, so the HTTP paths cannot forge a log line. It ACCEPTS a horizontal TAB
// (a legal HTTP field-value byte), which is why the shared scan-block log sites
// are sanitised too: they cannot forge a record, but they can corrupt
// field-delimited ingestion, and sanitizeLog is free.
func TestHTTPHostHeader_RejectsMostControlCharacters(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantAccept bool
	}{
		{"lf_rejected", "GET / HTTP/1.1\r\nHost: ev\nil.com\r\n\r\n", false},
		{"esc_rejected", "GET / HTTP/1.1\r\nHost: ev\x1bil.com\r\n\r\n", false},
		{"del_rejected", "GET / HTTP/1.1\r\nHost: ev\x7fil.com\r\n\r\n", false},
		{"connect_esc_rejected", "CONNECT ev\x1bil.com:443 HTTP/1.1\r\nHost: ev\x1bil.com:443\r\n\r\n", false},
		{"tab_accepted", "GET / HTTP/1.1\r\nHost: ev\til.com\r\n\r\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := readRequestForTest(tc.raw)
			if tc.wantAccept {
				if err != nil {
					t.Fatalf("expected net/http to accept %q, got %v", tc.raw, err)
				}
				if !strings.ContainsAny(req, "\t") {
					t.Fatalf("expected the TAB to survive into r.Host, got %q", req)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected net/http to REJECT %q, but it produced r.Host=%q — the HTTP paths would then share the SOCKS5 exposure", tc.raw, req)
			}
		})
	}
}

// TestScanBlockLogSitesAreSanitised covers the shared block-response helpers,
// which are reached from BOTH the plain-HTTP path and inside SSL-inspected
// tunnels. Their host argument is net/http-validated (so no line forgery), but
// a TAB does get through, and the sibling sites in proxy_tunnel.go already
// sanitise the same value.
func TestScanBlockLogSitesAreSanitised(t *testing.T) {
	const hostile = "scan\ttarget\x1b[31m.example.com"

	t.Run("scanBlockConn", func(t *testing.T) {
		sink := captureLoggerForTest(t)
		scanBlockConn(nopBlockResponder{}, hostile, "eicar", "clamav")
		assertNoRawControlBytes(t, sink.String())
	})

	t.Run("dpiBlock", func(t *testing.T) {
		sink := captureLoggerForTest(t)
		dpiBlock(nopBlockResponder{}, hostile, "pattern-name")
		assertNoRawControlBytes(t, sink.String())
	})
}

// TestDNSResolveFailureLogIsSanitised covers the CHAOS-64 resolver log site.
// Its `host` argument is already sanitised; its `err` argument was not, and a
// *net.DNSError carries the queried name verbatim — so the same bytes came back
// through the second argument. The site's own comment identifies the name as
// attacker-chosen, which is what makes this a gap rather than a judgement call.
func TestDNSResolveFailureLogIsSanitised(t *testing.T) {
	const hostile = "dns\ttarget\x1b[31m.example.com"

	prevLookup := lookupHostFn
	t.Cleanup(func() { lookupHostFn = prevLookup })
	lookupHostFn = func(_ context.Context, host string) ([]string, error) {
		// Shaped like the real thing: net.DNSError embeds the queried name.
		// Deliberately NOT IsNotFound — an NXDOMAIN is counted but never logged
		// (it is a healthy resolver), so it could not reach the log site at all.
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
	}

	resetDNSResolveHealthForTest()
	t.Cleanup(resetDNSResolveHealthForTest)

	sink := captureLoggerForTest(t)
	_ = lookupPublicHostIP(hostile)

	got := sink.String()
	if !strings.Contains(got, "DNS resolution failed") {
		t.Fatalf("expected the resolver failure line to be emitted; captured %q", got)
	}
	assertNoRawControlBytes(t, got)
}

// nopBlockResponder swallows the block body; these tests assert on the log, not
// on the wire bytes (which are locked by the PR0 characterization tests).
type nopBlockResponder struct{}

func (nopBlockResponder) blockBeforeResponse(string, string) {}

// readRequestForTest parses raw as an HTTP request and returns r.Host, so the
// control-character verdict above comes from net/http itself rather than from a
// claim in a comment.
func readRequestForTest(raw string) (string, error) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return "", err
	}
	return req.Host, nil
}
