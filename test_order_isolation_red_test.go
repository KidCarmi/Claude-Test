package main

// test_order_isolation_red_test.go — PR-C7 RED proofs for two order
// dependencies the seeded determinism run (-shuffle=1788866999688368609,
// -count=2) exposed once PR-C2 cleared the latch that used to fail first.
//
// Each test rebuilds, deterministically and in-process, the state a
// predecessor leaves behind in that order and then runs the victim test
// unchanged, so the dependency is pinned without the shuffle.

import (
	"testing"
)

// A predecessor left rules in the global rewriter. After the corrupt
// admin_settings.json is quarantined, the seed-identity finalizer writes a
// fresh minimal ledger at the settings path — by design — so the victim's
// "file absent after quarantine" assertion only holds with an EMPTY
// rewriter, which it must establish itself.
func TestOrder_CorruptSettingsQuarantineWithSeededRewriter(t *testing.T) {
	saved := rewriter.List()
	t.Cleanup(func() { publishRewriteRules(saved) })
	publishRewriteRules([]RewriteRule{{Host: "seed.example", ReqSet: map[string]string{"X-Seed": "1"}}})

	TestLoadAdminSettings_CorruptFileQuarantinedNotOverwritten(t)
}

// A predecessor left an access rule in the global policy store. The reorder
// contract (2E-C) refuses a list that does not cover the whole access set
// with 409, so the victim's two-rule list is a state conflict unless it
// starts from a store it owns.
func TestOrder_PolicyReorderWithForeignAccessRule(t *testing.T) {
	extra := policyStore.Add(PolicyRule{Priority: 7790, Name: "reorder-foreign", Action: "allow"})
	t.Cleanup(func() { policyStore.Delete(extra.Priority) })

	TestAPIPolicyReorder_Post_Success(t)
}
