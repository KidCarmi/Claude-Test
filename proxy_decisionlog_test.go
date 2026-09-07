package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Regression suite for the per-request policy-decision log lines in
// applyPolicyDecision (proxy.go).
//
// Those lines are the largest Culvert-owned allocation site on the request
// path, and they were made cheaper by (a) hoisting the rule-name sanitiser that
// each line called TWICE on the same value and (b) rendering the integer
// priority with strconv.Itoa instead of fmt.Sprintf("%d", ...).
//
// Both are COST changes: every byte these lines emit must be unchanged. That is
// what this file pins — the format-level equivalence below, and the end-to-end
// byte-exact expectations in TestDecisionLog_ByteExactOutput.

// TestDecisionLogPriority_ItoaMatchesSprintf pins the exact substitution made
// at the four decision-log call sites: the rendered priority field must be
// byte-identical to the fmt.Sprintf form it replaced, for every int — including
// negatives (a hand-edited or imported rule is not range-checked here) and the
// 64-bit extremes, where a naive digit-buffer implementation would overflow.
//
// It also pins the claim that justifies dropping the sanitiser's effect: a
// decimal integer rendering can never contain a byte sanitizeLog would rewrite,
// so the inline strings.ReplaceAll retained for CodeQL is a provable no-op.
func TestDecisionLogPriority_ItoaMatchesSprintf(t *testing.T) {
	cases := []int{
		0, 1, 9, 10, 42, 99, 100, 101, 999, 1000, 65535, 1 << 20,
		-1, -42, -100, -999999,
		math.MaxInt32, math.MinInt32,
		math.MaxInt64, math.MinInt64,
	}
	for _, n := range cases {
		old := strings.ReplaceAll(fmt.Sprintf("%d", n), "\n", "")
		got := strings.ReplaceAll(strconv.Itoa(n), "\n", "")
		if old != got {
			t.Errorf("priority %d: Itoa form %q != Sprintf form %q", n, got, old)
		}
		// The sanitiser must be a no-op on this value: nothing a decimal
		// integer can produce is a control character.
		if raw := strconv.Itoa(n); raw != got {
			t.Errorf("priority %d: ReplaceAll changed %q to %q — the no-op claim is false", n, raw, got)
		}
		if containsControl(got) {
			t.Errorf("priority %d: rendered form %q carries a control byte", n, got)
		}
	}
}

// TestDecisionLog_HoistedRuleNameIsStillSanitised proves the hoisted
// safeRuleName carries the SAME sanitisation the two inline sanitizeLog calls
// used to apply — a rule name carrying CRLF and an ANSI escape must not reach
// the log verbatim (CWE-117 / CWE-150). This is the security half of the
// change: hoisting must not have moved the sanitiser off the value's path.
func TestDecisionLog_HoistedRuleNameIsStillSanitised(t *testing.T) {
	const evil = "ev\nil\r\tname\x1b[31m\x7f"
	line := captureDecisionLog(t, &PolicyRule{
		Name:     evil,
		Priority: 7,
		Action:   ActionAllow,
	}, ActionAllow, http.MethodGet)

	if strings.ContainsAny(line, "\r\x1b\x7f") {
		t.Fatalf("unsanitised control byte reached the log line: %q", line)
	}
	// The name appears under both %q and %s in the same line; BOTH must carry
	// the sanitised form, which is what the single hoisted value now feeds.
	want := sanitizeLog(evil)
	if strings.Count(line, want) < 2 {
		t.Fatalf("sanitised name %q expected twice in %q", want, line)
	}
	if strings.Contains(line, evil) {
		t.Fatalf("raw name leaked into %q", line)
	}
}

// TestDecisionLog_ByteExactOutput pins the full rendered line for the two
// highest-volume branches against a literal expectation, so any future change
// to the operands or the format is a test failure rather than a silent change
// to an operator-facing (and SIEM-parsed) log contract.
func TestDecisionLog_ByteExactOutput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action PolicyAction
		rule   *PolicyRule
		want   string
	}{
		{
			name:   "allow",
			action: ActionAllow,
			rule:   &PolicyRule{Name: "corp-saas", Priority: 42, Action: ActionAllow},
			want: `POLICY_ALLOW rule="corp-saas" pri=42 192.0.2.9 GET "files.example.com" ` +
				`[fqdn=*.example.com] {req_id=req-1 identity=alice rule=corp-saas action=allow}`,
		},
		{
			// Priority >= 100 leaves strconv.Itoa's small-int fast path, so the
			// wide-value rendering is pinned too.
			name:   "block-wide-priority",
			action: ActionBlockPage,
			rule:   &PolicyRule{Name: "deny-gambling", Priority: 4096, Action: ActionBlockPage},
			want: `POLICY_BLOCK rule="deny-gambling" pri=4096 192.0.2.9 -> "files.example.com" ` +
				`[fqdn=*.example.com] {req_id=req-1 identity=alice rule=deny-gambling action=block}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := captureDecisionLog(t, tc.rule, tc.action, http.MethodGet)
			if got != tc.want {
				t.Errorf("decision log line mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// captureDecisionLog runs applyPolicyDecision with the process logger swapped
// for a buffer and returns the single POLICY_* line it emitted.
func captureDecisionLog(t *testing.T, rule *PolicyRule, action PolicyAction, method string) string {
	t.Helper()

	var buf bytes.Buffer
	prev := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = prev })

	match := &PolicyMatch{
		Rule:              rule,
		Action:            action,
		MatchedConditions: "fqdn=*.example.com",
	}
	r := httptest.NewRequestWithContext(context.Background(), method, "http://files.example.com/a/b", http.NoBody)
	r.Host = "files.example.com"
	w := httptest.NewRecorder()

	applyPolicyDecision(w, r, "192.0.2.9", "files.example.com", "req-1", "alice", AuthLogFields{}, match)

	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "POLICY_") || strings.HasPrefix(line, "FILE_BLOCKED") {
			return line
		}
	}
	t.Fatalf("no decision log line emitted; captured: %q", buf.String())
	return ""
}
