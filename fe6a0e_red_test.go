package main

// fe6a0e_red_test.go — FE-6A.0 correction round 4 (external review of
// `0b2046de`): deterministic RED rows for the remaining blocker — the
// success-audit completion of an operation-identified IdP write is neither
// exactly-once nor durably proven. Committed on exactly `0b2046de` BEFORE
// any product change.
//
//   ER1  crash after the durable audit append but before MarkAudited: the
//        restart reconciliation appends the SAME success audit again
//        (JSONL holds two entries for one operation)
//   ER2  audit append persistence failure: `audited:true` is persisted while
//        the durable JSONL never received the entry (a false completion
//        claim); recovery must instead write exactly one durable entry
//   ER3  MarkAudited persistence failure after a successful audit append:
//        repeated lookups and two restarts duplicate the audit instead of
//        retrying only the missing marker
//   ER4  (folded into ER1–ER3) a replay of the operationId after each
//        boundary performs zero product mutation and audits nothing more
//   ER5  the persistent JSONL evidence carries no structured operation
//        identity: nothing in the durable record keys the entry to the
//        operation, so exactly-once cannot even be checked
//
// Seams: audit.ResetForTest + audit.Init on a temp JSONL (the real durable
// sink), audit.SetPersistForTest (append-failure fault), the fileutil
// write-success observer (MarkAudited fault, armed on the ledger write that
// follows the registry commit), a fresh IdPRegistry load (restart). No
// sleeps.

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// fe6aeAuditFile wires the REAL durable audit sink (a temp JSONL file) for
// the test and returns its path.
func fe6aeAuditFile(t *testing.T) string {
	t.Helper()
	restore := audit.ResetForTest()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := audit.Init(path); err != nil {
		t.Fatalf("audit.Init: %v", err)
	}
	t.Cleanup(func() {
		_ = audit.Close()
		audit.ClearPersistForTest()
		restore()
	})
	return path
}

type fe6aeFailWriter struct{ err error }

func (f fe6aeFailWriter) Write([]byte) (int, error) { return 0, f.err }

// fe6aeJSONLCounts scans the durable audit record (current file + rotated
// archive) and counts the success entries for one profile: by (action,
// object) and by the STRUCTURED operation identity.
func fe6aeJSONLCounts(t *testing.T, path, action, object, opID string) (byObject, byOperation int) {
	t.Helper()
	for _, p := range []string{path, path + ".1"} {
		f, err := os.Open(p) // #nosec G304 -- test temp path
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			if m["action"] == action && m["object"] == object {
				byObject++
			}
			if m["operationId"] == opID {
				byOperation++
			}
		}
		_ = f.Close()
	}
	return byObject, byOperation
}

func fe6aeRestart(t *testing.T, regPath string) *IdPRegistry {
	t.Helper()
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(regPath); err != nil {
		t.Fatal(err)
	}
	idpRegistry = fresh
	return fresh
}

func fe6aeAssertReplayNoMutation(t *testing.T, auditPath, id, opID string, body map[string]any, wantByObject int) {
	t.Helper()
	before := len(idpRegistry.All())
	code, m := fe6acCreateFenced(t, body, "operationId="+opID)
	if code != http.StatusOK || m["replayed"] != true || m["id"] != id {
		t.Fatalf("replay = %d %v", code, m)
	}
	if n := len(idpRegistry.All()); n != before {
		t.Fatalf("replay mutated the registry (%d → %d)", before, n)
	}
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != wantByObject {
		t.Fatalf("replay changed the durable audit count: %d, want %d", n, wantByObject)
	}
}

// ─── ER1 — crash after the durable append, before the marker ───────────────

func TestFE6A0E_ER1_CrashBeforeMarkAuditedNeverDuplicatesTheDurableAudit(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	opsPath := fe6adOpsPath(regPath)
	const opID = "e1e1e1e1-1111-4111-8111-000000000021"
	body := ldapProfileBodyForPut("Crash", nil)
	code, m := fe6acCreateFenced(t, body, "operationId="+opID)
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("precondition: one durable success entry after the create, got %d", n)
	}
	// CRASH between the durable audit append and the durable marker: the
	// on-disk ledger still says audited:false. The very next thing that
	// happens is the restart, so no in-process state is stale.
	fe6adRewriteOps(t, opsPath, func(rec map[string]any) { rec["audited"] = false })
	fe6aeRestart(t, regPath)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("ER1: the durable record holds %d success entries for one operation after the restart — reconciliation re-appended an audit that was already durable", n)
	}
	if _, n := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("ER1: exactly one entry must be keyed to the operation; got %d", n)
	}
	code, lm := fe6adLookup(t, opID)
	if code != http.StatusOK || lm["audited"] != true {
		t.Fatalf("ER1: after recovery the marker must be durable; got %d %v", code, lm)
	}
	fe6aeRestart(t, regPath)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("ER1: a second restart re-audited (%d)", n)
	}
	fe6aeAssertReplayNoMutation(t, auditPath, id, opID, body, 1)
}

// ─── ER2 — the append itself is not durable ─────────────────────────────────

func TestFE6A0E_ER2_AuditAppendFailureNeverClaimsAudited(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	const opID = "e2e2e2e2-1111-4111-8111-000000000022"
	restoreWriter := audit.SetPersistForTest(fe6aeFailWriter{err: errors.New("disk full (injected)")})
	restoreErrs := audit.ResetWriteErrorsForTest()
	t.Cleanup(restoreErrs)
	body := ldapProfileBodyForPut("NoDisk", nil)
	code, m := fe6acCreateFenced(t, body, "operationId="+opID)
	restoreWriter()
	if code != http.StatusOK {
		t.Fatalf("create = %d %v (the registry commit is durable; the audit is the pending step)", code, m)
	}
	id, _ := m["id"].(string)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 0 {
		t.Fatalf("precondition: the injected failure did not stop the durable append (%d)", n)
	}
	lcode, lm := fe6adLookup(t, opID)
	if lcode != http.StatusOK {
		t.Fatalf("lookup = %d %v", lcode, lm)
	}
	if lm["audited"] == true {
		t.Fatal("ER2: audited:true was persisted while the durable audit record never received the entry — a false completion claim")
	}
	// The sink recovers: recovery must write EXACTLY one durable entry and
	// only then mark the operation audited.
	fe6aeRestart(t, regPath)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("ER2: recovery wrote %d durable entries, want exactly 1", n)
	}
	if lcode, lm = fe6adLookup(t, opID); lm["audited"] != true {
		t.Fatalf("ER2: after the durable append the marker must be set; got %d %v", lcode, lm)
	}
	fe6aeRestart(t, regPath)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("ER2: a later restart re-audited (%d)", n)
	}
	fe6aeAssertReplayNoMutation(t, auditPath, id, opID, body, 1)
}

// ─── ER3 — the marker persist fails after a successful append ───────────────

func TestFE6A0E_ER3_MarkAuditedFailureRetriesOnlyTheMarker(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	opsPath := fe6adOpsPath(regPath)
	const opID = "e3e3e3e3-1111-4111-8111-000000000023"
	// The ledger write that FOLLOWS the registry commit is the terminal
	// (committed) record; the audit append comes next, then the marker.
	// Make the marker's write impossible while keeping the committed
	// record's bytes, so the process continues from the exact crash state.
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
	body := ldapProfileBodyForPut("Marker", nil)
	code, m := fe6acCreateFenced(t, body, "operationId="+opID)
	fileutil.SetWriteSuccessObserver(noteStorageWriteSuccess)
	if !armed || len(committedBytes) == 0 {
		t.Fatal("precondition: the marker fault was never armed")
	}
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("precondition: the audit append itself succeeded once, got %d", n)
	}
	// The volume recovers with the committed-but-unmarked record in place.
	if err := os.RemoveAll(opsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opsPath, committedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, lm := fe6adLookup(t, opID); lm["state"] != idpOpCommitted {
			t.Fatalf("lookup #%d = %v", i, lm)
		}
	}
	fe6aeRestart(t, regPath)
	fe6aeRestart(t, regPath)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("ER3: %d durable success entries for one operation after two lookups and two restarts — the audit was re-appended instead of only the marker being retried", n)
	}
	if _, lm := fe6adLookup(t, opID); lm["audited"] != true {
		t.Fatalf("ER3: the marker was never persisted after the durable append; got %v", lm)
	}
	fe6aeAssertReplayNoMutation(t, auditPath, id, opID, body, 1)
}

// ─── ER5 — the durable evidence must be keyed to the operation ──────────────

func TestFE6A0E_ER5_DurableAuditIsOperationKeyed(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	const opID = "e5e5e5e5-1111-4111-8111-000000000025"
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Keyed", nil), "operationId="+opID)
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	byObject, byOp := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID)
	if byObject != 1 {
		t.Fatalf("precondition: one durable success entry, got %d", byObject)
	}
	if byOp != 1 {
		t.Fatalf("ER5: the durable JSONL carries %d entries keyed to operation %s — exactly one structured operation identity is required (text inside `detail` is not a key)", byOp, opID)
	}
	w := httptest.NewRecorder()
	apiAudit(w, adminCtx(httptest.NewRequest(http.MethodGet, "/api/audit?source=file&limit=100", http.NoBody)))
	var page struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range page.Entries {
		if e["operationId"] == opID {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("ER5: the audit read model exposes %d entries keyed to the operation, want 1", n)
	}
}
