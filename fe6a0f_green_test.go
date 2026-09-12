package main

// fe6a0f_green_test.go — FE-6A.0 correction round 5: GREEN proofs beyond the
// FR rows — a sink that cannot synchronise is refused (never trusted), a
// synchronisation failure is charged to the storage-health plane, and the
// memory-sink posture is unchanged and never described as disk-durable.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// fe6afPlainWriter is an io.Writer WITHOUT WriteSync: it can accept bytes
// but can never prove they reached stable storage.
type fe6afPlainWriter struct{ sw *fe6afSyncWriter }

func (w fe6afPlainWriter) Write(p []byte) (int, error) { return w.sw.Write(p) }

func TestFE6A0F_Green_UnsyncableSinkIsPendingNeverTrusted(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	opsPath := fe6adOpsPath(regPath)
	sw := fe6afOpenSyncWriter(t, auditPath)
	restoreWriter := audit.SetPersistForTest(fe6afPlainWriter{sw: sw})
	t.Cleanup(audit.ResetWriteErrorsForTest())
	const opID = "f6f6f6f6-3333-4333-8333-000000000046"
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Plain", nil), "operationId="+opID)
	if code != http.StatusOK || m["auditState"] != "pending" {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	if n, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id, opID); n != 0 {
		t.Fatalf("an unsyncable sink must receive nothing (%d)", n)
	}
	for _, e := range auditGet() {
		if e.OperationID == opID {
			t.Fatal("the ring must not run ahead of a durable record that cannot exist")
		}
	}
	if st, audited := fe6adLedgerState(t, opsPath, opID); st != idpOpCommitted || audited {
		t.Fatalf("ledger file = %s audited=%v", st, audited)
	}
	// The real synchronising sink is back (the audit.Init RotatingFile).
	restoreWriter()
	if _, lm := fe6adLookup(t, opID); lm["audited"] != true {
		t.Fatalf("after recovery = %v", lm)
	}
	fe6afAssertFinal(t, auditPath, id, opID)
}

func TestFE6A0F_Green_SyncFailureIsChargedToStorageHealth(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	auditPath := fe6aeAuditFile(t)
	sw := fe6afOpenSyncWriter(t, auditPath)
	sw.failSync = true
	t.Cleanup(audit.SetPersistForTest(sw))
	t.Cleanup(audit.ResetWriteErrorsForTest())
	before := audit.WriteErrors()
	const opID = "f7f7f7f7-3333-4333-8333-000000000047"
	if code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Charged", nil), "operationId="+opID); code != http.StatusOK || m["auditState"] != "pending" {
		t.Fatalf("create = %d %v", code, m)
	}
	if got := audit.WriteErrors(); got != before+1 {
		t.Fatalf("a synchronisation failure must be counted as a durable-write loss; WriteErrors %d → %d", before, got)
	}
}

func TestFE6A0F_Green_MemorySinkPostureUnchanged(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	t.Cleanup(audit.ResetForTest())
	const opID = "f8f8f8f8-3333-4333-8333-000000000048"
	if code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Mem", nil), "operationId="+opID); code != http.StatusOK || m["auditState"] != nil {
		t.Fatalf("create = %d %v", code, m)
	}
	w := httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	if ops, _ := fe6aJSON(t, w)["operations"].(map[string]any); ops["auditSink"] != "memory" {
		t.Fatalf("posture = %v", ops)
	}
	if _, lm := fe6adLookup(t, opID); lm["audited"] != true {
		t.Fatalf("memory sink: the ring is the record; got %v", lm)
	}
}
