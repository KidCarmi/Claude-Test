// Package rewrite owns per-host HTTP header rewrite rules: the rule DTO, the
// ordered active rule set, and the request/response header mutators. It is a
// self-contained leaf (stdlib only, no Culvert coupling) extracted from the flat
// package main per ADR-0002.
package rewrite

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// Rule defines header mutations applied to requests and/or responses
// whose destination host matches the given pattern.
//
// Example (config.yaml):
//
//	rewrite:
//	  - host: "*.internal.corp"
//	    req_set:
//	      X-Forwarded-By: "Culvert"
//	    resp_remove:
//	      - Server
//	  - host: ""           # empty = match all hosts
//	    resp_set:
//	      Strict-Transport-Security: "max-age=31536000"
type Rule struct {
	// ID is assigned automatically when the rule is added at runtime.
	ID int `json:"id"`

	// Host is an exact hostname or wildcard pattern (*.example.com).
	// Empty string matches every request.
	Host string `yaml:"host" json:"host"`

	// Request header operations — applied before forwarding to upstream.
	ReqSet    map[string]string `yaml:"req_set"    json:"req_set,omitempty"`    // set / overwrite
	ReqAdd    map[string]string `yaml:"req_add"    json:"req_add,omitempty"`    // append
	ReqRemove []string          `yaml:"req_remove" json:"req_remove,omitempty"` // delete

	// Response header operations — applied before returning to client.
	RespSet    map[string]string `yaml:"resp_set"    json:"resp_set,omitempty"`
	RespAdd    map[string]string `yaml:"resp_add"    json:"resp_add,omitempty"`
	RespRemove []string          `yaml:"resp_remove" json:"resp_remove,omitempty"`
}

// matchesHost reports whether the rule applies to host.
//
// It is the semantic ORACLE for the compiled matcher the request path actually
// runs: it compiles this one rule's pattern and asks it, so the two cannot
// diverge and the existing pattern/host table tests keep validating the live
// matcher rather than a retired copy.
func (r *Rule) matchesHost(host string) bool {
	return compileHostPattern(r.Host).match(strings.ToLower(host))
}

// ─── Compiled matcher ─────────────────────────────────────────────────────────

// hostMatcher is a rule's host pattern with everything that depends only on the
// PATTERN already decided: which branch applies, and the lowercased forms the
// branch compares against.
//
// The pattern is immutable between writes, so lowercasing it — and re-deciding
// which of the three branches it takes — on every request, for every rule, was
// pure repeated work. Deciding it once at publish time leaves the request path
// with string comparisons and nothing else.
type hostMatcher struct {
	matchAll bool   // pattern "" — matches every host
	suffix   string // "*.example.com" → ".example.com"
	apex     string // "*.example.com" → "example.com"
	exact    string // bare pattern, lowercased
}

// compileHostPattern precomputes the matcher for one rule's Host pattern.
func compileHostPattern(pattern string) hostMatcher {
	if pattern == "" {
		return hostMatcher{matchAll: true}
	}
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "*.") {
		return hostMatcher{suffix: pattern[1:], apex: pattern[2:]}
	}
	return hostMatcher{exact: pattern}
}

// match reports whether an ALREADY-LOWERCASED host matches. Callers lowercase
// the host once per request rather than once per rule.
func (m hostMatcher) match(lowerHost string) bool {
	switch {
	case m.matchAll:
		return true
	case m.suffix != "":
		return strings.HasSuffix(lowerHost, m.suffix) || lowerHost == m.apex
	default:
		return lowerHost == m.exact
	}
}

// compiledRule pairs a precompiled host matcher with the header operations to
// apply on a hit. The ops are held by POINTER into the view's own private rule
// slice: the request path only ranges over them, and the slice is never mutated
// after publication, so no copy is needed per request. Ranging the rules by
// value instead copied the whole 104-byte Rule per rule, per request.
type compiledRule struct {
	host hostMatcher
	ops  *Rule
}

// ruleView is the immutable snapshot the request path reads. A published view
// is never mutated; every mutator builds a REPLACEMENT and swaps the pointer.
type ruleView struct {
	rules []compiledRule
}

// Rewriter holds the ordered list of active rewrite rules and applies them.
//
// ── Why the request path reads a view instead of taking the lock ──────────────
//
// ApplyRequest and ApplyResponse both run on the plain-HTTP forward path
// (proxy_http.go: prepareHTTPForward before the round trip, handleHTTP after
// it), so a proxied HTTP request paid TWO acquisitions of this one RWMutex.
// sync.RWMutex.RLock is an atomic read-modify-write on a single shared word, so
// that is not a constant cost but a throughput CEILING: every request in the
// process wrote the same cache line, and the contention grew with core count.
//
// It landed hardest in the DEFAULT posture, where NO rewrite rules are
// configured and the lock guarded an empty slice. Measured on a 4-core Xeon
// (rewrite_bench_test.go, BenchmarkApplyRequest_NoRulesParallel, n=6 medians):
//
//	cores │ before      │ after
//	──────┼─────────────┼──────────
//	  1   │  15.9 ns/op │  1.7 ns/op
//	  2   │  94.6 ns/op │  0.9 ns/op
//	  4   │ 113.7 ns/op │  0.5 ns/op
//
// i.e. before, four cores delivered 0.56x the throughput of ONE core — adding
// cores SUBTRACTED throughput, for a feature that is switched off. This is the
// same finding, and the same remedy, as internal/threatfeed's lookup path and
// package main's IP filter: read an immutable view through an atomic.Pointer.
//
// ── The contract, and why it is a SECURITY contract ───────────────────────────
//
// A published view's rules are NEVER mutated in place. Every mutator of rules
// or nextID must call publishLocked() before releasing mu.
//
// Adding a mutator without that call is a silent SECURITY failure, not a
// performance one: rewrite rules set and strip headers (the package doc's own
// example installs Strict-Transport-Security and removes Server), so a rule
// added through an unpublishing mutator would be accepted, listed, persisted
// and audited while never actually being applied to a single request. It is
// pinned per mutator by TestRuleView_EveryMutatorRepublishes; the
// no-in-place-mutation half is enforced by the race detector via
// TestRuleView_ConcurrentReadersAndWriters.
//
// mu and the fields it guards stay the AUTHORITATIVE write-side state, so
// SetRules/List/Add/RemoveByID/Snapshot keep their exact prior semantics —
// including List's pre-existing shallow copy, whose maps alias the stored
// rules. Only the read path changed.
type Rewriter struct {
	mu     sync.RWMutex
	rules  []Rule
	nextID int

	// view is the lock-free read path's snapshot of rules. Nil until the first
	// publish; ApplyRequest/ApplyResponse treat nil and empty identically.
	view atomic.Pointer[ruleView]
}

// NewRewriter returns a Rewriter with ID assignment starting at 1.
func NewRewriter() *Rewriter {
	return &Rewriter{nextID: 1}
}

// publishLocked rebuilds the immutable view from rules. Callers must hold mu
// for writing; the view is swapped before the lock is released so a reader can
// never observe a mutation that has not been published.
func (rw *Rewriter) publishLocked() {
	if len(rw.rules) == 0 {
		// Publish an explicit empty view rather than leaving a stale one: a
		// mutator that empties the rule set must stop applying immediately.
		rw.view.Store(&ruleView{})
		return
	}
	// The view owns its own copy of the rules, so a later mutation of rw.rules
	// cannot reach a view already handed to an in-flight request.
	owned := make([]Rule, len(rw.rules))
	copy(owned, rw.rules)
	compiled := make([]compiledRule, len(owned))
	for i := range owned {
		compiled[i] = compiledRule{host: compileHostPattern(owned[i].Host), ops: &owned[i]}
	}
	rw.view.Store(&ruleView{rules: compiled})
}

// SetRules replaces the full rule set (used during startup from config).
func (rw *Rewriter) SetRules(rules []Rule) {
	rw.mu.Lock()
	rw.rules = make([]Rule, len(rules))
	for i, r := range rules {
		r.ID = rw.nextID
		rw.nextID++
		rw.rules[i] = r
	}
	rw.publishLocked()
	rw.mu.Unlock()
}

// List returns a snapshot of the current rules.
func (rw *Rewriter) List() []Rule {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	out := make([]Rule, len(rw.rules))
	copy(out, rw.rules)
	return out
}

// Add appends a rule and returns it with the assigned ID.
func (rw *Rewriter) Add(rule Rule) Rule {
	rw.mu.Lock()
	rule.ID = rw.nextID
	rw.nextID++
	rw.rules = append(rw.rules, rule)
	rw.publishLocked()
	rw.mu.Unlock()
	return rule
}

// RemoveByID deletes the rule with the given ID. Returns false if not found.
func (rw *Rewriter) RemoveByID(id int) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	for i, r := range rw.rules {
		if r.ID == id {
			rw.rules = append(rw.rules[:i], rw.rules[i+1:]...)
			rw.publishLocked()
			return true
		}
	}
	return false
}

// activeRules returns this call's view of the rule set and the host lowercased
// ONCE, or ok=false when no rule is configured — the default posture, which is
// then one atomic pointer load and nothing else.
//
// Lowercasing here rather than inside the matcher is the second half of the
// per-rule repeated work: strings.ToLower scans every byte, and ALLOCATES a
// copy when the client spelled the Host header with capitals (which is legal
// and does happen). Per rule that was one allocation each — 20 allocs / 320 B
// per request on a 20-rule policy. Per call it is at most one.
func (rw *Rewriter) activeRules(host string) (rules []compiledRule, lowerHost string, ok bool) {
	v := rw.view.Load()
	if v == nil || len(v.rules) == 0 {
		return nil, "", false
	}
	return v.rules, strings.ToLower(host), true
}

// ApplyRequest mutates h in-place for every matching rule.
func (rw *Rewriter) ApplyRequest(host string, h http.Header) {
	rules, lowerHost, ok := rw.activeRules(host)
	if !ok {
		return
	}
	for i := range rules {
		if !rules[i].host.match(lowerHost) {
			continue
		}
		rule := rules[i].ops
		for k, v := range rule.ReqSet {
			h.Set(k, v)
		}
		for k, v := range rule.ReqAdd {
			h.Add(k, v)
		}
		for _, k := range rule.ReqRemove {
			h.Del(k)
		}
	}
}

// ApplyResponse mutates resp.Header in-place for every matching rule.
func (rw *Rewriter) ApplyResponse(host string, resp *http.Response) {
	if resp == nil {
		return
	}
	rules, lowerHost, ok := rw.activeRules(host)
	if !ok {
		return
	}
	for i := range rules {
		if !rules[i].host.match(lowerHost) {
			continue
		}
		rule := rules[i].ops
		for k, v := range rule.RespSet {
			resp.Header.Set(k, v)
		}
		for k, v := range rule.RespAdd {
			resp.Header.Add(k, v)
		}
		for _, k := range rule.RespRemove {
			resp.Header.Del(k)
		}
	}
}

// Snapshot captures the current rules and ID counter and returns a closure that
// restores them, under the mutex on both ends. Production code never calls this;
// it exists so package main's startup-slice test isolation helper can save and
// restore the package-global rewriter without reaching across the package
// boundary into the unexported fields (ADR-0002 extraction).
func (rw *Rewriter) Snapshot() func() {
	rw.mu.RLock()
	savedRules := append([]Rule(nil), rw.rules...)
	savedNext := rw.nextID
	rw.mu.RUnlock()
	return func() {
		rw.mu.Lock()
		rw.rules = savedRules
		rw.nextID = savedNext
		rw.publishLocked()
		rw.mu.Unlock()
	}
}
