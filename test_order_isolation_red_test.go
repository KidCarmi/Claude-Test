package main

// test_order_isolation_red_test.go — PR-C7 RED proofs for two order
// dependencies the seeded determinism run (-shuffle=1788866999688368609,
// -count=2) exposed once PR-C2 cleared the latch that used to fail first.
//
// Each test rebuilds, deterministically and in-process, the state a
// predecessor leaves behind in that order and then runs the victim test
// unchanged, so the dependency is pinned without the shuffle.

import (
	"runtime"
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

// PR-C7b (the same seeded run, once PR-C7's two were isolated): a
// predecessor's best-effort admin-settings save (adminSettingsSave spawns a
// goroutine every admin mutation makes) was still in flight when the legacy
// LDAP sentinel test pinned and rewrote its fixture file, so the stale save
// landed on the fixture with the flag already reset and the load read
// `legacy_ldap_retired: false`. The fixture helper must drain pending saves
// BEFORE it hands the settings path to the test: with one held open here, a
// helper that drains cannot return until it is released.
func TestOrder_LegacyLDAPFixtureDrainsPendingSaves(t *testing.T) {
	release := make(chan struct{})
	adminSettingsSaveWG.Add(1)
	go func() {
		defer adminSettingsSaveWG.Done()
		<-release
	}()
	released := false
	unblock := func() {
		if !released {
			released = true
			close(release)
		}
	}
	t.Cleanup(unblock)

	done := make(chan struct{})
	go func() {
		defer close(done)
		withLegacyLDAPAuthorityReset(t)
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	select {
	case <-done:
		t.Fatal("the LDAP fixture helper returned while a best-effort save was still pending; that save can land on the fixture file")
	default:
	}
	unblock()
	<-done
}

// PR-C7b: the R3 premise arms the process-global rejected-document latch.
// upEnv resets it at ENTRY (PR-C2), which protects the next UPSTREAM test
// only; a non-upstream successor's save carried the rejected sections
// forward verbatim and its load logged `duplicate_authority` (the LDAP
// sentinel test above). The latch must not outlive the test that armed it.
func TestOrder_RejectedDocumentLatchDoesNotOutliveItsTest(t *testing.T) {
	t.Run("r3", TestUpstreamV2C_R3_RejectedDocumentFreezesMutationsAndKeyMinting)
	if _, _, ok := upstreamRetainedSections(); ok {
		t.Fatal("the rejected-document latch armed by R3 is still set after R3 finished")
	}
	if st := getUpstreamState(); st.Degraded != nil {
		t.Fatalf("the managed degradation surface armed by R3 is still set after R3 finished: %+v", st.Degraded)
	}
}
