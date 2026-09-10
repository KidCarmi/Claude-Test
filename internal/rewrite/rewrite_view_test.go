package rewrite

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// ─── The republish contract ───────────────────────────────────────────────────
//
// ApplyRequest/ApplyResponse read an immutable view through an atomic.Pointer
// instead of taking rw.mu, so every mutator MUST call publishLocked() before
// releasing the lock. A mutator that forgets is a silent security failure — a
// rule that sets or strips a header would be accepted, listed, persisted and
// audited while never applying to a single request — so the contract is pinned
// per mutator rather than spot-checked.

// mutator names the exported methods that change the rule set. Every one of
// them must leave the view consistent with List().
var viewMutators = []string{"SetRules", "Add", "RemoveByID", "RemoveByStableID", "Snapshot"}

// TestRuleView_MutatorInventoryIsComplete fails when a mutator is added to the
// type without being brought under the republish test below. Reflection is the
// point: a new method appears here automatically, so the contract cannot be
// bypassed by simply not thinking about it.
func TestRuleView_MutatorInventoryIsComplete(t *testing.T) {
	// Methods that only READ, and therefore need no publish.
	readOnly := map[string]bool{
		"List":          true,
		"ApplyRequest":  true,
		"ApplyResponse": true,
		// StateSnapshot is the v2 coherent read (rules + revision under one
		// RLock). It takes no write lock and changes nothing, so it needs no
		// publish.
		"StateSnapshot": true,
	}
	known := make(map[string]bool, len(viewMutators))
	for _, m := range viewMutators {
		known[m] = true
	}
	rt := reflect.TypeOf(&Rewriter{})
	for i := range rt.NumMethod() {
		name := rt.Method(i).Name
		if readOnly[name] || known[name] {
			continue
		}
		t.Errorf("exported method %q is not classified: if it mutates the rule set it must call "+
			"publishLocked() and be added to viewMutators; if it only reads, add it to readOnly", name)
	}
}

// viewMatchesRules reports whether the lock-free view agrees with the
// authoritative, mu-guarded rule list — the invariant every mutator must
// restore before releasing the lock.
func viewMatchesRules(rw *Rewriter) error {
	want := rw.List()
	v := rw.view.Load()
	var got []Rule
	if v != nil {
		for i := range v.rules {
			got = append(got, *v.rules[i].ops)
		}
	}
	if len(got) != len(want) {
		return fmt.Errorf("view holds %d rules, List() reports %d — a mutator did not republish",
			len(got), len(want))
	}
	for i := range want {
		// StableID is compared too: it is the DURABLE identity the v2 management
		// surface addresses rules by, so a view still carrying a superseded one
		// is the same class of drift as a stale host pattern.
		if got[i].ID != want[i].ID || got[i].Host != want[i].Host || got[i].StableID != want[i].StableID {
			return fmt.Errorf("view rule %d = {id:%d stable:%q host:%q}, want {id:%d stable:%q host:%q} — "+
				"a mutator did not republish", i,
				got[i].ID, got[i].StableID, got[i].Host,
				want[i].ID, want[i].StableID, want[i].Host)
		}
	}
	return nil
}

func TestRuleView_EveryMutatorRepublishes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(rw *Rewriter)
	}{
		{"SetRules", func(rw *Rewriter) {
			rw.SetRules([]Rule{{Host: "a.example.com"}, {Host: "*.b.example.com"}})
		}},
		{"SetRules_toEmpty", func(rw *Rewriter) {
			rw.SetRules([]Rule{{Host: "a.example.com"}})
			rw.SetRules(nil)
		}},
		{"Add", func(rw *Rewriter) {
			rw.Add(Rule{Host: "c.example.com"})
		}},
		{"RemoveByID", func(rw *Rewriter) {
			added := rw.Add(Rule{Host: "d.example.com"})
			rw.Add(Rule{Host: "e.example.com"})
			if !rw.RemoveByID(added.ID) {
				t.Fatal("RemoveByID reported not-found for a rule it had just added")
			}
		}},
		{"RemoveByID_toEmpty", func(rw *Rewriter) {
			added := rw.Add(Rule{Host: "f.example.com"})
			if !rw.RemoveByID(added.ID) {
				t.Fatal("RemoveByID reported not-found for a rule it had just added")
			}
		}},
		{"RemoveByStableID", func(rw *Rewriter) {
			added := rw.Add(Rule{Host: "j.example.com"})
			rw.Add(Rule{Host: "k.example.com"})
			if !rw.RemoveByStableID(added.StableID) {
				t.Fatal("RemoveByStableID reported not-found for a rule it had just added")
			}
		}},
		{"RemoveByStableID_toEmpty", func(rw *Rewriter) {
			added := rw.Add(Rule{Host: "l.example.com"})
			if !rw.RemoveByStableID(added.StableID) {
				t.Fatal("RemoveByStableID reported not-found for a rule it had just added")
			}
		}},
		{"Snapshot_restore", func(rw *Rewriter) {
			rw.SetRules([]Rule{{Host: "g.example.com"}})
			restore := rw.Snapshot()
			rw.SetRules([]Rule{{Host: "h.example.com"}, {Host: "i.example.com"}})
			restore()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := NewRewriter()
			tc.mutate(rw)
			if err := viewMatchesRules(rw); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
		})
	}
}

// TestRuleView_MutationIsVisibleImmediately is the behavioural half: the
// invariant above compares structures, this one proves a rule added through
// each mutator actually reaches a request's headers. A view that was published
// but compiled wrong would pass the structural test and fail this one.
func TestRuleView_MutationIsVisibleImmediately(t *testing.T) {
	const hdr = "Strict-Transport-Security"
	const val = "max-age=31536000"

	applied := func(rw *Rewriter) bool {
		h := make(http.Header)
		rw.ApplyRequest("www.example.com", h)
		return h.Get(hdr) == val
	}

	t.Run("Add", func(t *testing.T) {
		rw := NewRewriter()
		if applied(rw) {
			t.Fatal("empty rewriter applied a header")
		}
		rw.Add(Rule{Host: "", ReqSet: map[string]string{hdr: val}})
		if !applied(rw) {
			t.Fatal("rule added via Add never reached the request headers")
		}
	})

	t.Run("SetRules", func(t *testing.T) {
		rw := NewRewriter()
		rw.SetRules([]Rule{{Host: "", ReqSet: map[string]string{hdr: val}}})
		if !applied(rw) {
			t.Fatal("rule installed via SetRules never reached the request headers")
		}
	})

	t.Run("RemoveByID_stopsApplying", func(t *testing.T) {
		rw := NewRewriter()
		added := rw.Add(Rule{Host: "", ReqSet: map[string]string{hdr: val}})
		if !applied(rw) {
			t.Fatal("rule never applied before removal")
		}
		rw.RemoveByID(added.ID)
		if applied(rw) {
			t.Fatal("removed rule kept applying — the view was not republished")
		}
	})

	// The v2 management surface deletes by StableID, so this path carries the
	// same contract as RemoveByID and is exercised the same way.
	t.Run("RemoveByStableID_stopsApplying", func(t *testing.T) {
		rw := NewRewriter()
		added := rw.Add(Rule{Host: "", ReqSet: map[string]string{hdr: val}})
		if !applied(rw) {
			t.Fatal("rule never applied before removal")
		}
		if !rw.RemoveByStableID(added.StableID) {
			t.Fatal("RemoveByStableID reported not-found for a rule it had just added")
		}
		if applied(rw) {
			t.Fatal("removed rule kept applying — the view was not republished")
		}
	})

	t.Run("SetRules_emptyStopsApplying", func(t *testing.T) {
		rw := NewRewriter()
		rw.Add(Rule{Host: "", ReqSet: map[string]string{hdr: val}})
		rw.SetRules(nil)
		if applied(rw) {
			t.Fatal("rule kept applying after the rule set was emptied")
		}
	})
}

// TestRuleView_ConcurrentReadersAndWriters is the no-in-place-mutation half of
// the contract, enforced by the race detector: a published view must never be
// written to, so concurrent Apply calls and mutations must be race-free.
func TestRuleView_ConcurrentReadersAndWriters(t *testing.T) {
	rw := NewRewriter()
	rw.SetRules([]Rule{
		{Host: "*.example.com", ReqSet: map[string]string{"X-A": "1"}},
		{Host: "other.example.org", RespRemove: []string{"Server"}},
	})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := make(http.Header)
			resp := &http.Response{Header: make(http.Header)}
			for {
				select {
				case <-stop:
					return
				default:
				}
				rw.ApplyRequest("www.example.com", h)
				rw.ApplyResponse("www.example.com", resp)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 500 {
			added := rw.Add(Rule{Host: "churn.example.net", ReqSet: map[string]string{"X-B": "2"}})
			rw.RemoveByID(added.ID)
			if i%50 == 0 {
				rw.SetRules([]Rule{{Host: "*.example.com", ReqSet: map[string]string{"X-A": "1"}}})
			}
			rw.List()
		}
		close(stop)
	}()

	wg.Wait()
}

// TestRuleView_IsNotMutatedByLaterWrites pins that a view handed to an
// in-flight request keeps applying the rules it was published with, even after
// the rule set is replaced underneath it.
func TestRuleView_IsNotMutatedByLaterWrites(t *testing.T) {
	rw := NewRewriter()
	rw.SetRules([]Rule{{Host: "", ReqSet: map[string]string{"X-Old": "1"}}})

	// Take the view the way a request in flight holds it.
	inFlight := rw.view.Load()

	rw.SetRules([]Rule{{Host: "", ReqSet: map[string]string{"X-New": "1"}}})

	if n := len(inFlight.rules); n != 1 {
		t.Fatalf("in-flight view rule count changed to %d", n)
	}
	if _, ok := inFlight.rules[0].ops.ReqSet["X-Old"]; !ok {
		t.Fatal("a later SetRules mutated a view already published to a reader")
	}
}

// ─── Differential: the compiled matcher vs the pre-optimization body ──────────

// legacyMatchesHost is the verbatim pre-optimization (*Rule).matchesHost. It is
// the oracle: the compiled matcher is a COST change, so it must decide every
// (pattern, host) pair identically.
func legacyMatchesHost(rulePattern, host string) bool {
	if rulePattern == "" {
		return true
	}
	host = strings.ToLower(host)
	pattern := strings.ToLower(rulePattern)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	return host == pattern
}

func TestCompiledMatcher_MatchesLegacyBehaviour(t *testing.T) {
	patterns := []string{
		"", "*", "*.", "*.example.com", "*.EXAMPLE.com", "example.com", "EXAMPLE.COM",
		"www.example.com", ".example.com", "*.a.b.c.example.com", "a", "*.a",
		"xn--bcher-kva.example.com", "*.xn--bcher-kva.example.com",
		"192.168.1.1", "[2001:db8::1]", "*.co.uk", "*..example.com",
	}
	hosts := []string{
		"", "example.com", "www.example.com", "WWW.EXAMPLE.COM", "Www.Example.Com",
		"deep.sub.example.com", "notexample.com", ".example.com", "example.com.",
		"a", "a.a", "xn--bcher-kva.example.com", "192.168.1.1", "[2001:db8::1]",
		"co.uk", "www.co.uk", "*", "*.example.com", "..example.com",
	}
	for _, p := range patterns {
		m := compileHostPattern(p)
		for _, h := range hosts {
			want := legacyMatchesHost(p, h)
			got := m.match(strings.ToLower(h))
			if got != want {
				t.Errorf("pattern=%q host=%q: compiled=%v legacy=%v", p, h, got, want)
			}
			// (*Rule).matchesHost must agree too — it is the same matcher.
			if viaRule := (&Rule{Host: p}).matchesHost(h); viaRule != want {
				t.Errorf("pattern=%q host=%q: (*Rule).matchesHost=%v legacy=%v", p, h, viaRule, want)
			}
		}
	}
}

func FuzzCompiledMatcher(f *testing.F) {
	f.Add("*.example.com", "www.example.com")
	f.Add("", "anything")
	f.Add("EXAMPLE.COM", "example.com")
	f.Add("*.", ".")
	f.Add("*", "*")
	f.Fuzz(func(t *testing.T, pattern, host string) {
		want := legacyMatchesHost(pattern, host)
		got := compileHostPattern(pattern).match(strings.ToLower(host))
		if got != want {
			t.Fatalf("pattern=%q host=%q: compiled=%v legacy=%v", pattern, host, got, want)
		}
	})
}
