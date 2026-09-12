package main

// fe6a0e_green_test.go — FE-6A.0 correction round 4: GREEN proofs for the
// operation-keyed, exactly-once, durably-proven success-audit completion
// boundary, beyond the RED rows in fe6a0e_red_test.go.
//
//   EG1  append failure at create: 200 with `auditState: pending`, the
//        lookup reports `audited:false` + `auditState: pending`, the ring
//        holds nothing for the operation (the volatile fan-out never runs
//        ahead of the durable record), and the C2c audit-completion
//        observability is satisfied by the boundary (no audit_missing).
//   EG2  settle-before-write completes an owed audit exactly once through
//        the same boundary (a later writer on the profile), and an
//        unwritable audit sink at that moment leaves the operation
//        committed-but-audit-pending without blocking the writer.
//   EG3  memory sink (no audit log configured): `auditSink: memory` on the
//        read model, audited once, replay/restart never duplicate.
//   EG4  the audit read model exposes the structured key on the entry.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
)

func TestFE6A0E_Green_AppendFailureIsReportedPendingAndNeverRunsAhead(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	const opID = "e1e1e1e1-2222-4222-8222-000000000031"
	restoreWriter := audit.SetPersistForTest(fe6aeFailWriter{err: errors.New("enospc (injected)")})
	t.Cleanup(audit.ResetWriteErrorsForTest())
	missingBefore := c2AuditMissingTotal.Load()
	// Through the full middleware chain so C2c observes the request.
	mux := d0WireMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, adminCtx(jsonReq(http.MethodPost, fencedIdPCreatePath("operationId="+opID), ldapProfileBodyForPut("Pending", nil))))
	if w.Code != http.StatusOK {
		t.Fatalf("create = %d: %s", w.Code, w.Body.String())
	}
	m := fe6aJSON(t, w)
	id, _ := m["id"].(string)
	if m["auditState"] != "pending" {
		t.Fatalf("the response must say the audit is still owed; got %v", m)
	}
	if got := c2AuditMissingTotal.Load(); got != missingBefore {
		t.Fatalf("C2c counted the boundary-owned audit as missing (%d → %d)", missingBefore, got)
	}
	for _, e := range auditGet() {
		if e.OperationID == opID {
			t.Fatal("the ring received an entry the durable record does not hold")
		}
	}
	_, lm := fe6adLookup(t, opID)
	if lm["audited"] != false || lm["auditState"] != "pending" || lm["state"] != idpOpCommitted {
		t.Fatalf("lookup = %v", lm)
	}
	restoreWriter()
	// Recovery via the lookup: exactly one durable entry, then the marker.
	_, lm = fe6adLookup(t, opID)
	if lm["audited"] != true || lm["auditState"] != nil {
		t.Fatalf("after recovery = %v", lm)
	}
	if n, k := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 || k != 1 {
		t.Fatalf("durable entries = %d keyed = %d, want 1/1", n, k)
	}
	fe6aeRestart(t, regPath)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 {
		t.Fatalf("restart re-audited (%d)", n)
	}
}

func TestFE6A0E_Green_SettleBeforeWriteCompletesTheAuditOnceOrLeavesItPending(t *testing.T) {
	reg, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	withConfigVersionsDir(t)
	auditPath := fe6aeAuditFile(t)
	opsPath := fe6adOpsPath(regPath)
	const opID = "e2e2e2e2-2222-4222-8222-000000000032"
	// A lost terminal record (DR1a shape) leaves a durable pending intent
	// and NO audit; the next writer on the profile settles it.
	id := fe6adCreateWithLostTerminalRecord(t, reg, regPath, opsPath, opID, "Settle")
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 0 {
		t.Fatalf("precondition: no audit yet, got %d", n)
	}
	// (a) The audit sink is unwritable while the writer settles: the write
	// itself is allowed (the verdict IS durable), the audit stays owed.
	restoreWriter := audit.SetPersistForTest(fe6aeFailWriter{err: errors.New("enospc (injected)")})
	t.Cleanup(audit.ResetWriteErrorsForTest())
	rev := fe6aIdPRevision(t, id)
	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), ldapProfileBodyForPut("Settled", nil)), id)
	if w.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", w.Code, w.Body.String())
	}
	_, lm := fe6adLookup(t, opID) // the lookup retries against the failing sink: still pending
	if lm["state"] != idpOpCommitted || lm["audited"] != false || lm["auditState"] != "pending" {
		t.Fatalf("settled verdict must be durable while the audit stays owed; got %v", lm)
	}
	restoreWriter()
	// (b) The sink recovers: a DELETE (another writer) is not needed — the
	// lookup completes the owed audit once; a further writer re-appends
	// nothing.
	_, lm = fe6adLookup(t, opID)
	if lm["audited"] != true {
		t.Fatalf("after recovery = %v", lm)
	}
	w = httptest.NewRecorder()
	apiIdPItem(w, fencedDeleteReq(fencedIdPPath(id)), id)
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", w.Code, w.Body.String())
	}
	fe6aeRestart(t, regPath)
	if n, k := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 1 || k != 1 {
		t.Fatalf("durable entries = %d keyed = %d, want 1/1", n, k)
	}
}

func TestFE6A0E_Green_MemorySinkAuditsOnceAndReportsItsPosture(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	t.Cleanup(audit.ResetForTest()) // no durable sink: the ring is the record
	const opID = "e3e3e3e3-2222-4222-8222-000000000033"
	body := ldapProfileBodyForPut("Memory", nil)
	code, m := fe6acCreateFenced(t, body, "operationId="+opID)
	if code != http.StatusOK || m["auditState"] != nil {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	w := httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	if ops, _ := fe6aJSON(t, w)["operations"].(map[string]any); ops["auditSink"] != "memory" {
		t.Fatalf("read model must name the sink; got %v", ops)
	}
	count := func() int {
		n := 0
		for _, e := range auditGet() {
			if e.OperationID == opID {
				n++
			}
		}
		return n
	}
	if count() != 1 {
		t.Fatalf("ring entries = %d, want 1", count())
	}
	_, lm := fe6adLookup(t, opID)
	if lm["audited"] != true {
		t.Fatalf("lookup = %v", lm)
	}
	if code, rm := fe6acCreateFenced(t, body, "operationId="+opID); code != http.StatusOK || rm["replayed"] != true || rm["id"] != id {
		t.Fatalf("replay = %d %v", code, rm)
	}
	if count() != 1 || len(idpRegistry.All()) != 1 {
		t.Fatalf("replay re-audited or re-created (%d, %d)", count(), len(idpRegistry.All()))
	}
	// A restart wipes the ring (the recorded posture of a memory sink); the
	// durable marker means reconciliation appends nothing on top.
	fe6aeRestart(t, regPath)
	if _, lm = fe6adLookup(t, opID); lm["audited"] != true {
		t.Fatalf("after restart = %v", lm)
	}
}

func TestFE6A0E_Green_FileSinkPostureAndKeyedReadModel(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	_ = fe6aeAuditFile(t)
	const opID = "e4e4e4e4-2222-4222-8222-000000000034"
	if code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Keyed", nil), "operationId="+opID); code != http.StatusOK || m["auditState"] != nil {
		t.Fatalf("create = %d %v", code, m)
	}
	w := httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	if ops, _ := fe6aJSON(t, w)["operations"].(map[string]any); ops["auditSink"] != "file" {
		t.Fatalf("read model must name the sink; got %v", ops)
	}
	for _, src := range []string{"", "file"} {
		w = httptest.NewRecorder()
		apiAudit(w, adminCtx(httptest.NewRequest(http.MethodGet, "/api/audit?limit=100&source="+src, http.NoBody)))
		if !containsKeyedEntry(fe6aJSON(t, w), opID) {
			t.Fatalf("source=%q: the audit read model must expose the operation key", src)
		}
	}
}

func containsKeyedEntry(page map[string]any, opID string) bool {
	entries, _ := page["entries"].([]any)
	for _, e := range entries {
		if m, _ := e.(map[string]any); m["operationId"] == opID {
			return true
		}
	}
	return false
}
