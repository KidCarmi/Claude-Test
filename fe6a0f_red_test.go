package main

// fe6a0f_red_test.go — FE-6A.0 correction round 5 (external review of
// `ac19a25b`): deterministic RED rows for the remaining blocker — the audit
// append is acknowledged "durably present" on a successful io.Writer.Write,
// before the bytes reach stable storage (no fsync of the JSONL file, no
// directory synchronisation on rotation), while the operation ledger's
// `audited:true` marker IS atomically durable. Committed on exactly
// `ac19a25b` BEFORE any product change; the only non-test addition is a
// no-op observability seam (fileutil.SetSyncObserverForTest — nothing calls
// it at that SHA, which is exactly what FR3 demonstrates).
//
//   FR1  the full JSONL write succeeds and the synchronisation fails: the
//        operation must stay committed / audited:false / auditState:pending
//        (RED: audited:true is persisted on the unsynchronised write)
//   FR2  power loss removes the unsynchronised bytes before the restart:
//        reconciliation must write exactly one durable operation-keyed
//        entry and only then mark (RED: the marker survives, the entry is
//        gone, nothing repairs it)
//   FR3  the append crosses a rotation boundary: the new current file AND
//        the directory must be synchronised before durable:true (RED: no
//        synchronisation happens at all)
//   FR4  CONTROL (passes on `ac19a25b`): a durable append followed by a
//        MarkAudited failure — lookups and two restarts never duplicate
//   FR5  (folded into every row) the final durable JSONL set holds exactly
//        one (action, operationId) entry and the ledger says audited:true
//
// The sync-controllable sink writes to the REAL audit JSONL (the same path
// audit.Init opened) so every count below reads the file a restart would
// read. No sleeps.

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// fe6afSyncWriter appends to the real audit file and lets the test decide
// whether the synchronisation to stable storage succeeds.
type fe6afSyncWriter struct {
	mu       sync.Mutex
	f        *os.File
	failSync bool
	syncs    int
}

func (w *fe6afSyncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Write(p)
}

// WriteSync is the durable append primitive: the bytes are appended and
// then synchronised; a synchronisation failure is reported even though the
// bytes may already sit in the page cache.
func (w *fe6afSyncWriter) WriteSync(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.f.Write(p)
	if err != nil {
		return n, err
	}
	w.syncs++
	if w.failSync {
		return n, errors.New("fsync: input/output error (injected)")
	}
	return n, w.f.Sync()
}

func fe6afOpenSyncWriter(t *testing.T, path string) *fe6afSyncWriter {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return &fe6afSyncWriter{f: f}
}

func fe6afFileSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func fe6afAssertFinal(t *testing.T, auditPath, id, opID string) {
	t.Helper()
	byObject, byOp := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID)
	if byObject != 1 || byOp != 1 {
		t.Fatalf("FR5: durable JSONL set holds %d entries for the profile / %d keyed to the operation, want exactly 1/1", byObject, byOp)
	}
	if _, lm := fe6adLookup(t, opID); lm["state"] != idpOpCommitted || lm["audited"] != true || lm["auditState"] != nil {
		t.Fatalf("FR5: ledger must say committed + audited:true; got %v", lm)
	}
}

// ─── FR1 — write ok, sync fails ─────────────────────────────────────────────

func TestFE6A0F_FR1_SyncFailureAfterAFullWriteIsNotDurable(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	sw := fe6afOpenSyncWriter(t, auditPath)
	sw.failSync = true
	t.Cleanup(audit.SetPersistForTest(sw))
	t.Cleanup(audit.ResetWriteErrorsForTest())
	const opID = "f1f1f1f1-3333-4333-8333-000000000041"
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("NoSync", nil), "operationId="+opID)
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("precondition: the bytes reached the file (page cache) exactly once; got %d", n)
	}
	_, lm := fe6adLookup(t, opID)
	if lm["audited"] != false || lm["auditState"] != "pending" || lm["state"] != idpOpCommitted {
		t.Fatalf("FR1: a write whose synchronisation failed was acknowledged durable — ledger says %v", lm)
	}
	if m["auditState"] != "pending" {
		t.Fatalf("FR1: the create response must say the audit is still owed; got %v", m)
	}
	// The device recovers: the retry must SYNCHRONISE the containing file
	// (finding the readable entry is not enough) and only then mark.
	sw.failSync = false
	if _, lm = fe6adLookup(t, opID); lm["audited"] != true {
		t.Fatalf("after recovery = %v", lm)
	}
	fe6afAssertFinal(t, auditPath, id, opID)
}

// ─── FR2 — power loss drops the unsynchronised bytes ────────────────────────

func TestFE6A0F_FR2_PowerLossAfterUnsyncedWriteIsRepairedExactlyOnce(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	sw := fe6afOpenSyncWriter(t, auditPath)
	sw.failSync = true
	restoreWriter := audit.SetPersistForTest(sw)
	t.Cleanup(audit.ResetWriteErrorsForTest())
	before := fe6afFileSize(t, auditPath)
	const opID = "f2f2f2f2-3333-4333-8333-000000000042"
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("PowerLoss", nil), "operationId="+opID)
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	// POWER LOSS: the bytes never reached stable storage — the file is
	// exactly as it was before the write. The ledger (atomic write) survived.
	restoreWriter()
	if err := os.Truncate(auditPath, before); err != nil {
		t.Fatal(err)
	}
	fe6aeRestart(t, regPath)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("FR2: after power loss + restart the durable record holds %d success entries for the operation, want exactly 1 — a marker claimed an audit that did not survive", n)
	}
	fe6aeRestart(t, regPath)
	fe6afAssertFinal(t, auditPath, id, opID)
}

// ─── FR3 — rotation boundary ────────────────────────────────────────────────

func TestFE6A0F_FR3_RotationSynchronisesFileAndDirectoryBeforeDurable(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	// A 1 MB rotating sink already holding ~1 MB: the operation's append
	// crosses the rotation boundary.
	pad := strings.Repeat("x", 100) // ~140-byte lines: the fill itself never rotates
	rf, err := fileutil.NewRotatingFile(auditPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rf.Close() })
	for fe6afFileSize(t, auditPath) < (1<<20)-200 { // the ~600-byte audit line then crosses the cap
		if _, err := rf.Write([]byte(`{"ts":1,"action":"pad","detail":"` + pad + `"}` + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(audit.SetPersistForTest(rf))
	var mu sync.Mutex
	syncs := map[string]int{}
	t.Cleanup(fileutil.SetSyncObserverForTest(func(kind, path string) {
		mu.Lock()
		syncs[kind+":"+path]++
		mu.Unlock()
	}))
	const opID = "f3f3f3f3-3333-4333-8333-000000000043"
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Rotate", nil), "operationId="+opID)
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	if _, err := os.Stat(auditPath + ".1"); err != nil {
		t.Fatalf("precondition: the append must have rotated (%v)", err)
	}
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("precondition: one entry across current+archive, got %d", n)
	}
	mu.Lock()
	fileSyncs, dirSyncs := syncs["file:"+auditPath], syncs["dir:"+filepath.Dir(auditPath)]
	mu.Unlock()
	if m["auditState"] == "pending" {
		t.Fatalf("a healthy rotating sink must complete the audit; got %v", m)
	}
	if fileSyncs == 0 || dirSyncs == 0 {
		t.Fatalf("FR3: durable:true was acknowledged across a rotation with file syncs=%d dir syncs=%d — the new current file and its directory were not synchronised before the acknowledgement", fileSyncs, dirSyncs)
	}
	fe6afAssertFinal(t, auditPath, id, opID)
}

// ─── FR4 — CONTROL: durable append, marker fails ────────────────────────────

func TestFE6A0F_FR4_Control_DurableAppendThenMarkerFailureNeverDuplicates(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	opsPath := fe6adOpsPath(regPath)
	const opID = "f4f4f4f4-3333-4333-8333-000000000044"
	var committedBytes []byte
	sawRegistry, armed := false, false
	fileutil.SetWriteSuccessObserver(func(path string) {
		switch {
		case armed:
		case filepath.Base(path) == filepath.Base(regPath):
			sawRegistry = true
		case sawRegistry && filepath.Base(path) == idpOperationsFile:
			armed = true
			committedBytes, _ = os.ReadFile(opsPath)
			_ = os.Remove(opsPath)
			_ = os.MkdirAll(filepath.Join(opsPath, "blocker"), 0o700)
		}
	})
	t.Cleanup(func() { fileutil.SetWriteSuccessObserver(noteStorageWriteSuccess) })
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Control", nil), "operationId="+opID)
	fileutil.SetWriteSuccessObserver(noteStorageWriteSuccess)
	if !armed || code != http.StatusOK {
		t.Fatalf("precondition: armed=%v create=%d %v", armed, code, m)
	}
	id, _ := m["id"].(string)
	if err := os.RemoveAll(opsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opsPath, committedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		fe6adLookup(t, opID)
	}
	fe6aeRestart(t, regPath)
	fe6aeRestart(t, regPath)
	fe6afAssertFinal(t, auditPath, id, opID)
}
