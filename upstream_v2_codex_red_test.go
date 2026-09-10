package main

// upstream_v2_codex_red_test.go — PR-C5 (Batch 2 PR correction round): the
// three findings the repository's automated reviewer raised on PR #1340.
//
// P1 — an entry in the durable requiresReplacement state (a credentialed
// parent restored from a sanitized backup or declared by an import) holds
// NO material (Credential == nil) but carries the marker that only the T2
// replace / T3 clear ceremony may resolve (2F-D CR1/CR2, upstreamEntryProtected).
// The credential-free v1 adapter and the per-entry DELETE keyed their
// refusals on material only, so both could silently discard the marker.
//
// P2 — `culvert --prepare-downgrade --confirm <word>` runs from the one-shot
// dispatcher BEFORE observability is initialised, so its audit record landed
// in the in-memory ring of a process that exits immediately: with
// `-audit-log` configured, nothing durable survived.
//
// Every test here is RED on the tree immediately before the correction.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

// cxSeedRequiresReplacement lands one managed entry in the durable
// requiresReplacement state through the supported import path (an incoming
// entry that DECLARES a credential is created with the marker, never with
// material) and proves the premise.
func cxSeedRequiresReplacement(t *testing.T, id, host string) map[string]any {
	t.Helper()
	rec := pdImport(t, pdV2Payload(pdEntry(id, host, upstream.CredentialConfigured)), "")
	if rec.Code != 200 {
		t.Fatalf("premise import: %d %s", rec.Code, rec.Body.String())
	}
	e := upEntry(t, id)
	if e == nil || e["credentialState"] != upstream.CredentialRequiresReplacement {
		t.Fatalf("premise: the imported declared credential must land in requiresReplacement, got %v", e)
	}
	return e
}

func TestUpstreamV2_V1ReplaceProtectsRequiresReplacementMarker(t *testing.T) {
	upEnv(t)
	const id = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
	cxSeedRequiresReplacement(t, id, "parent-rr-v1.test")

	// A credential-free bulk replacement that OMITS the entry would discard
	// the marker without the exact-id Tier-3 clear: refused, nothing changed.
	rec := upV1Post(t, `[]`)
	if rec.Code != 409 {
		t.Fatalf("v1 replace omitting a requires-replacement entry must be refused 409, got %d %s", rec.Code, rec.Body.String())
	}
	body := upJSON(t, rec)
	if body["code"] != "credentialed_entries_present" {
		t.Fatalf("refusal code must be credentialed_entries_present, got %v", body["code"])
	}
	cur, _ := body["current"].(map[string]any)
	ids, _ := cur["credentialed"].([]any)
	found := false
	for _, v := range ids {
		if v == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("the refusal metadata must name the protected entry %s, got %v", id, cur)
	}
	if e := upEntry(t, id); e == nil || e["credentialState"] != upstream.CredentialRequiresReplacement {
		t.Fatalf("the entry and its marker must be untouched by the refused replace, got %v", e)
	}
}

func TestUpstreamV2_DeleteProtectsRequiresReplacementMarker(t *testing.T) {
	upEnv(t)
	const id = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	e := cxSeedRequiresReplacement(t, id, "parent-rr-del.test")
	rev, _ := e["revision"].(float64)

	rec := upReq(t, "DELETE", fmt.Sprintf("/api/upstream/entries/%s?revision=%d", id, int64(rev)), "")
	if rec.Code != 409 {
		t.Fatalf("deleting a requires-replacement entry without the T3 clear must be refused 409, got %d %s", rec.Code, rec.Body.String())
	}
	body := upJSON(t, rec)
	if body["code"] != "credential_present" {
		t.Fatalf("refusal code must be credential_present, got %v", body["code"])
	}
	cur, _ := body["current"].(map[string]any)
	if cur["credentialState"] != upstream.CredentialRequiresReplacement || cur["id"] != id {
		t.Fatalf("the refusal must carry the entry's identity and its requiresReplacement state, got %v", cur)
	}
	if e := upEntry(t, id); e == nil || e["credentialState"] != upstream.CredentialRequiresReplacement {
		t.Fatalf("the entry and its marker must survive the refused delete, got %v", e)
	}
}

// TestPrepareDowngrade_OneShotPersistsAuditWhenAuditLogConfigured drives the
// REAL one-shot dispatcher (main → handleOneShotCommands) in a re-executed
// copy of this test binary — the composition is what the defect lives in —
// with `-audit-log` configured and the data root pointed at this test's
// environment through CULVERT_DATA_DIR (PR-C1). The counts-only audit record
// must be on disk after the process exits, and must never carry a password.
func TestPrepareDowngrade_OneShotPersistsAuditWhenAuditLogConfigured(t *testing.T) {
	upEnv(t)
	pdSeed(t)
	adminSettingsSaveWG.Wait()
	dir := dataDir
	word := downgradeConfirmWord(dir, adminSettingsSchemaPredecessor)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	//nolint:gosec // G204: re-executes THIS test binary with a fixed test selector.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPrepareDowngradeOneShotHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		oneShotHelperEnv+"=1",
		dataDirEnv+"="+dir,
		// The confirmation word is the one positional argument, so every
		// flag precedes it (flag parsing stops at the first non-flag).
		oneShotHelperArgsEnv+"="+strings.Join([]string{
			"--audit-log", auditPath, "--prepare-downgrade",
			"--target-schema", fmt.Sprint(adminSettingsSchemaPredecessor),
			"--confirm", word,
		}, oneShotHelperArgSep),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("one-shot prepare-downgrade exited with %v:\n%s", err, out)
	}
	if !strings.Contains(string(out), "Prepared: admin_settings.json rewritten for the predecessor") {
		t.Fatalf("the one-shot must report the commit, output:\n%s", out)
	}
	data, rerr := os.ReadFile(auditPath)
	if rerr != nil {
		t.Fatalf("the configured audit log must hold the prepare-downgrade record after the process exited: %v\noutput:\n%s", rerr, out)
	}
	if !strings.Contains(string(data), "upstream.prepare_downgrade") {
		t.Fatalf("audit log must carry the upstream.prepare_downgrade record, got:\n%s", data)
	}
	if strings.Contains(string(data), pdCanaryPW) {
		t.Fatal("the audit record must be counts-only — it carries the parent-proxy password")
	}
}

const (
	oneShotHelperEnv     = "CULVERT_TEST_ONESHOT_HELPER"
	oneShotHelperArgsEnv = "CULVERT_TEST_ONESHOT_ARGS"
	oneShotHelperArgSep  = "\x1f"
)

// TestPrepareDowngradeOneShotHelper is the re-executed child of the test
// above: it becomes the appliance's own entrypoint with the requested
// arguments. Outside that child it is a no-op (not a skip: nothing is
// asserted in the parent process by design).
func TestPrepareDowngradeOneShotHelper(t *testing.T) {
	if os.Getenv(oneShotHelperEnv) != "1" {
		return
	}
	os.Args = append([]string{"culvert"}, strings.Split(os.Getenv(oneShotHelperArgsEnv), oneShotHelperArgSep)...)
	main()
	t.Fatal("main returned without exiting")
}
