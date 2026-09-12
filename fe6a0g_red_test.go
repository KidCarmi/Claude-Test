package main

// fe6a0g_red_test.go — FE-6A.0 correction round 6 (external review of
// `e5d66a59`): deterministic RED rows for the three remaining source-level
// gaps of the durable audit acknowledgement. Committed on exactly
// `e5d66a59` BEFORE any product change; the only non-test addition is the
// behaviour-neutral before-sync seam (fileutil.SetSyncHookForTest — nil
// unless a test installs it) that GR2 uses to fault a directory fsync and
// GR3 uses to schedule an ordinary rotation between "found" and "sync".
//
//   GR1  (internal/audit/boundary_red_test.go) partial write → zero-byte
//        failed repair → retry must never acknowledge a glued record
//   GR2  a rotating append whose DIRECTORY fsync fails: the readable record
//        must stay audit-pending until file AND directory durability are
//        proven — the retry must not acknowledge after a file-only sync
//   GR3  between "found at pathname X" and "synchronise X" an ordinary
//        audit.Add rotates the sink: the file the recovery synchronises
//        must be the generation that actually holds the entry, never the
//        pathname re-opened after the rotation
//   The FR rows (sync failure, power loss, rotation, marker failure,
//   exactly-once) are retained unchanged.

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// fe6agRotatingSink wires a 1 MB fileutil.RotatingFile on the real audit
// path, pre-filled so the next ~600-byte audit line crosses the cap.
func fe6agRotatingSink(t *testing.T, auditPath string) *fileutil.RotatingFile {
	t.Helper()
	rf, err := fileutil.NewRotatingFile(auditPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rf.Close() })
	line := []byte(`{"ts":1,"action":"pad","detail":"` + strings.Repeat("x", 100) + `"}` + "\n")
	for fe6afFileSize(t, auditPath) < (1<<20)-200 {
		if _, err := rf.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(audit.SetPersistForTest(rf))
	return rf
}

// ─── GR2 — directory fsync fails after a rotating append ────────────────────

func TestFE6A0G_GR2_DirectorySyncFailureKeepsTheRecordPendingUntilProven(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	opsPath := fe6adOpsPath(regPath)
	fe6agRotatingSink(t, auditPath)
	t.Cleanup(audit.ResetWriteErrorsForTest())
	var mu sync.Mutex
	dirFault := true
	dirSyncs := 0
	t.Cleanup(fileutil.SetSyncHookForTest(func(kind, path string) error {
		mu.Lock()
		defer mu.Unlock()
		if kind == "dir" && dirFault {
			return errors.New("fsync(dir): input/output error (injected)")
		}
		return nil
	}))
	t.Cleanup(fileutil.SetSyncObserverForTest(func(kind, path string) {
		if kind == "dir" {
			mu.Lock()
			dirSyncs++
			mu.Unlock()
		}
	}))
	const opID = "a2a2a2a2-4444-4444-8444-000000000062"
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("DirFault", nil), "operationId="+opID)
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("precondition: the record is readable once across current+archive, got %d", n)
	}
	if st, audited := fe6adLedgerState(t, opsPath, opID); st != idpOpCommitted || audited {
		t.Fatalf("precondition: a failed directory fsync must not be acknowledged at the write; ledger file says %s audited=%v", st, audited)
	}
	// RETRY while the directory still cannot be synchronised: the readable
	// record is not proof — file AND directory durability are required.
	_, lm := fe6adLookup(t, opID)
	if st, audited := fe6adLedgerState(t, opsPath, opID); audited || lm["audited"] == true {
		t.Fatalf("GR2: the retry acknowledged the record after a file-only synchronisation while the directory fsync still fails (ledger file %s audited=%v, lookup %v)", st, audited, lm)
	}
	// The directory recovers: the retry must synchronise it before marking.
	mu.Lock()
	dirFault = false
	before := dirSyncs
	mu.Unlock()
	_, lm = fe6adLookup(t, opID)
	mu.Lock()
	after := dirSyncs
	mu.Unlock()
	if lm["audited"] != true || after <= before {
		t.Fatalf("GR2: recovery must prove directory durability (dir syncs %d → %d) before marking; got %v", before, after, lm)
	}
	fe6afAssertFinal(t, auditPath, id, opID)
}

// ─── GR3 — ordinary rotation between "found" and "sync" ─────────────────────

func TestFE6A0G_GR3_RecoverySynchronisesTheGenerationThatHoldsTheEntry(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	opsPath := fe6adOpsPath(regPath)
	rf := fe6agRotatingSink(t, auditPath)
	const opID = "a3a3a3a3-4444-4444-8444-000000000063"
	// The create's audit line rotates the pre-filled sink and lands at the
	// head of a fresh CURRENT generation; that generation is then padded
	// back to the cap so the very next ordinary Add rotates it.
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Race", nil), "operationId="+opID)
	if code != http.StatusOK || m["auditState"] != nil {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	if _, k := fe6aeJSONLCountsIn(t, auditPath, opID); k != 1 {
		t.Fatalf("precondition: the entry must sit in the current generation, got %d", k)
	}
	pad := []byte(`{"ts":1,"action":"pad","detail":"` + strings.Repeat("x", 100) + `"}` + "\n")
	for fe6afFileSize(t, auditPath) < (1<<20)-200 {
		if _, err := rf.Write(pad); err != nil {
			t.Fatal(err)
		}
	}
	// CRASH between the durable append and the marker (ER1 shape); the
	// restart's reconciliation is the recovery under test.
	fe6adRewriteOps(t, opsPath, func(rec map[string]any) { rec["audited"] = false })
	var mu sync.Mutex
	var synced []string
	rotated := false
	t.Cleanup(fileutil.SetSyncObserverForTest(func(kind, path string) {
		mu.Lock()
		synced = append(synced, kind+":"+path)
		mu.Unlock()
	}))
	// Schedule point: the recovery has FOUND the entry at a pathname and is
	// about to synchronise. An ordinary audit.Add now forces a rotation of
	// that pathname (the entry moves to the archive; the pathname re-opens
	// as an empty new generation).
	t.Cleanup(fileutil.SetSyncHookForTest(func(kind, path string) error {
		mu.Lock()
		first := !rotated
		rotated = true
		mu.Unlock()
		if first {
			audit.Add(audit.Entry{TS: 2, Action: "rotate.now", Detail: strings.Repeat("y", 1200)})
		}
		return nil
	}))
	fe6aeRestart(t, regPath)
	mu.Lock()
	seen := append([]string(nil), synced...)
	didRotate := rotated
	mu.Unlock()
	if !didRotate {
		t.Fatal("precondition: the rotation was never scheduled between found and sync")
	}
	// Every FILE the recovery reported synchronised must hold the keyed
	// entry — otherwise the acknowledgement rests on the wrong generation.
	fileSyncs := 0
	for _, s := range seen {
		if !strings.HasPrefix(s, "file:") {
			continue
		}
		fileSyncs++
		p := strings.TrimPrefix(s, "file:")
		if _, k := fe6aeJSONLCountsIn(t, p, opID); k != 1 {
			t.Fatalf("GR3: the recovery synchronised %s, which holds %d keyed entries — audited:true rests on a generation that does not contain the audit (synced: %v)", filepath.Base(p), k, seen)
		}
	}
	if fileSyncs == 0 {
		t.Fatalf("GR3: no file synchronisation was reported before the acknowledgement (synced: %v)", seen)
	}
	fe6afAssertFinal(t, auditPath, id, opID)
}
