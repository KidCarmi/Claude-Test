package main

// upstream_v2_env_isolation_red_test.go — PR-C2 (Batch 2 PR correction
// round): the CI determinism gate (-shuffle -count=2, seed
// 1788866999688368609) failed TestUpstreamV2D_R40_* and
// TestUpstreamV2D_Import_YAMLOwned* with 409 document_rejected: the
// process-global "stored document rejected at load" latch armed by
// TestUpstreamV2C_R3_RejectedDocumentFreezesMutationsAndKeyMinting outlived
// that test's environment, so whichever upstream test the shuffle placed
// next inherited a refusal it never caused. RED on the PR head; green once
// upEnv resets the latch (and the degraded surface) with the rest of the
// upstream process state.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestUpstreamV2_RejectedLatchDoesNotOutliveItsEnvironment(t *testing.T) {
	// First environment: the R3 premise — a stored document that fails
	// validation at load arms the process-global rejection latch.
	upEnv(t)
	path := filepath.Join(dataDir, "admin_settings.json")
	if err := os.WriteFile(path, []byte(upCorrRejectedDocument()), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadAdminSettings(path)
	if !upstreamRejectedActive() {
		t.Fatal("premise: loading a duplicate-authority document must arm the rejection latch")
	}
	if deg, _ := upGet(t)["degraded"].(map[string]any); deg == nil {
		t.Fatal("premise: the rejected document must be visible as degraded")
	}

	// Second environment: what the NEXT test in a shuffled order receives.
	upEnv(t)
	if upstreamRejectedActive() {
		t.Fatal("a fresh upstream environment must not inherit the previous environment's rejection latch")
	}
	if deg, _ := upGet(t)["degraded"].(map[string]any); deg != nil {
		t.Fatalf("a fresh upstream environment must not inherit the previous environment's degraded surface: %v", deg)
	}
	rec := upReq(t, "POST", "/api/upstream/entries",
		fmt.Sprintf(`{"scheme":"http","host":"parent-iso.test","port":3128,"revision":%d}`, upDocRevision(t)))
	if rec.Code != 201 {
		t.Fatalf("a create in a fresh environment must land, got %d %s", rec.Code, rec.Body.String())
	}
}
