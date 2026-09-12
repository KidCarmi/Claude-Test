package main

// fe6a0d_green_test.go — FE-6A.0 correction round 3: GREEN proofs for the
// durable-ledger authority (B1), the fail-closed ledger (B2) and the bounded
// compile seam (B3), beyond the RED rows in fe6a0d_red_test.go.
//
//   DG1  a lost terminal persist is settled by the LOOKUP once the ledger is
//        writable again: committed from provenance, audited exactly once,
//        the verdict durable before it is reported.
//   DG2  a later UPDATE of a profile with an outstanding intent settles it
//        BEFORE the write (committed, audited once) and preserves provenance;
//        a caller-supplied operationId on the body never overrides it.
//   DG3  an UNSETTLEABLE intent (ledger not writable) refuses the update
//        503 operation_unsettled with ZERO mutation (memory, file, revision).
//   DG4  the CP→DP ReplaceAll settles an outstanding intent on a profile it
//        removes, and DEFERS (error, nothing applied) when it cannot.
//   DG5  a degraded ledger: lookup and identified create are 503
//        operation_ledger_degraded; a change/removal of an existing profile
//        is refused; a pure add of a new profile still lands.
//   DG6  capacity: with every slot unresolved the handler answers 503
//        operation_ledger_full and creates nothing; the read model counts.
//   DG7  a replay of an audited commit never re-audits; a restart never
//        re-audits; a durable-first Finish leaves memory pending on failure.
//
// No sleeps; every restart is a fresh IdPRegistry load of the same files.

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// fe6adCreateWithLostTerminalRecord performs an operation-identified create
// whose registry commit lands but whose terminal ledger write fails (the
// DR1a fault), then makes the ledger writable again with the durable
// PENDING intent back in place — the exact state a crash leaves behind.
// Returns the created profile id.
func fe6adCreateWithLostTerminalRecord(t *testing.T, reg *IdPRegistry, regPath, opsPath, opID, name string) string {
	t.Helper()
	var pendingBytes []byte
	fired := false
	fileutil.SetWriteSuccessObserver(func(path string) {
		if fired || filepath.Base(path) != filepath.Base(regPath) {
			return
		}
		fired = true
		pendingBytes, _ = os.ReadFile(opsPath)
		_ = os.Remove(opsPath)
		_ = os.MkdirAll(filepath.Join(opsPath, "blocker"), 0o700)
	})
	t.Cleanup(func() { fileutil.SetWriteSuccessObserver(noteStorageWriteSuccess) })
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut(name, nil), "operationId="+opID)
	fileutil.SetWriteSuccessObserver(noteStorageWriteSuccess)
	if !fired || len(pendingBytes) == 0 {
		t.Fatal("precondition: the registry commit never fired the write observer with a durable pending intent")
	}
	if code != http.StatusInternalServerError || m["code"] != refusalOutcomeUnknown {
		t.Fatalf("precondition: want 500 outcome_unknown, got %d %v", code, m)
	}
	if cur, _ := m["current"].(map[string]any); cur["detail"] != "operation_record_not_durable" || cur["operationId"] != opID {
		t.Fatalf("the non-terminal answer must name the split and the operationId; got %v", m)
	}
	all := reg.All()
	if len(all) != 1 || all[0].OperationID != opID {
		t.Fatalf("the committed profile must carry the operation's provenance; got %+v", all)
	}
	if err := os.RemoveAll(opsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opsPath, pendingBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return all[0].ID
}

func fe6adLookup(t *testing.T, opID string) (status int, body map[string]any) {
	t.Helper()
	mux := d0WireMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, getReq("/api/idp/operations/"+opID))
	return w.Code, fe6aJSON(t, w)
}

func fe6adLedgerState(t *testing.T, opsPath, opID string) (state string, audited bool) {
	t.Helper()
	s := newIdPOperationStore(filepath.Join(filepath.Dir(opsPath), "idp_profiles.json"))
	if d := s.Degraded(); d != nil {
		t.Fatalf("ledger file degraded: %+v", d)
	}
	op, err := s.Get(opID)
	if err != nil || op == nil {
		t.Fatalf("ledger file has no record for %s (%v)", opID, err)
	}
	return op.State, op.Audited
}

// ─── DG1 — the lookup settles a lost terminal record from provenance ────────

func TestFE6A0D_Green_LookupSettlesALostTerminalRecordDurablyAndAuditsOnce(t *testing.T) {
	reg, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	opsPath := fe6adOpsPath(regPath)
	t.Cleanup(audit.SwapRingForTest())
	const opID = "e1e1e1e1-0000-4000-8000-000000000011"
	id := fe6adCreateWithLostTerminalRecord(t, reg, regPath, opsPath, opID, "Lookup")
	if n := fe6adCountAudit("idp.create", id); n != 0 {
		t.Fatalf("no success may be audited before the terminal record is durable; got %d", n)
	}
	if st, _ := fe6adLedgerState(t, opsPath, opID); st != idpOpPending {
		t.Fatalf("the durable truth must still be pending; got %s", st)
	}
	code, m := fe6adLookup(t, opID)
	if code != http.StatusOK || m["state"] != idpOpCommitted || m["code"] != "lookup_committed" || m["audited"] != true {
		t.Fatalf("lookup must settle from provenance and report the DURABLE verdict; got %d %v", code, m)
	}
	if st, audited := fe6adLedgerState(t, opsPath, opID); st != idpOpCommitted || !audited {
		t.Fatalf("the verdict reported must be the one on disk; got %s audited=%v", st, audited)
	}
	if n := fe6adCountAudit("idp.create", id); n != 1 {
		t.Fatalf("settlement completes the success audit exactly once; got %d", n)
	}
	// A second lookup and a restart change nothing and audit nothing.
	if code, m = fe6adLookup(t, opID); code != http.StatusOK || m["state"] != idpOpCommitted {
		t.Fatalf("second lookup = %d %v", code, m)
	}
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(regPath); err != nil {
		t.Fatal(err)
	}
	idpRegistry = fresh
	if n := fe6adCountAudit("idp.create", id); n != 1 {
		t.Fatalf("restart must not re-audit; got %d", n)
	}
	// The replay of the same operationId is answered from the durable record.
	code, rm := fe6acCreateFenced(t, ldapProfileBodyForPut("Lookup", nil), "operationId="+opID)
	if code != http.StatusOK || rm["replayed"] != true || rm["id"] != id {
		t.Fatalf("replay = %d %v", code, rm)
	}
	if n := fe6adCountAudit("idp.create", id); n != 1 || len(fresh.All()) != 1 {
		t.Fatalf("replay must not re-audit or re-create (audits=%d profiles=%d)", n, len(fresh.All()))
	}
}

// ─── DG2 — a later writer settles first, provenance survives the replace ────

func TestFE6A0D_Green_UpdateSettlesTheOutstandingIntentBeforeWritingAndKeepsProvenance(t *testing.T) {
	reg, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	withConfigVersionsDir(t)
	opsPath := fe6adOpsPath(regPath)
	t.Cleanup(audit.SwapRingForTest())
	const opID = "e2e2e2e2-0000-4000-8000-000000000012"
	id := fe6adCreateWithLostTerminalRecord(t, reg, regPath, opsPath, opID, "Before")
	rev := fe6aIdPRevision(t, id)
	body := ldapProfileBodyForPut("After", nil)
	body["operationId"] = "ffffffff-0000-4000-8000-00000000ffff" // caller-supplied: ignored
	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), body), id)
	if w.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", w.Code, w.Body.String())
	}
	if st, audited := fe6adLedgerState(t, opsPath, opID); st != idpOpCommitted || !audited {
		t.Fatalf("the intent must be settled DURABLY before the write; got %s audited=%v", st, audited)
	}
	if code, m := fe6adLookup(t, opID); code != http.StatusOK || m["code"] != "settled_before_write_committed" {
		t.Fatalf("lookup = %d %v", code, m)
	}
	if n := fe6adCountAudit("idp.create", id); n != 1 {
		t.Fatalf("exactly one success audit; got %d", n)
	}
	p := reg.Get(id)
	if p == nil || p.Name != "After" || p.OperationID != opID || idpEntryRevision(p) != rev+1 {
		t.Fatalf("the replace must land with the ORIGINAL provenance preserved; got %+v", p)
	}
	w = httptest.NewRecorder()
	apiIdPItem(w, getReq("/api/idp/"+id), id)
	if m := fe6aJSON(t, w); m["operationId"] != opID {
		t.Fatalf("the read model must expose the provenance; got %v", m)
	}
	// Restart: the settled verdict is what the file says.
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(regPath); err != nil {
		t.Fatal(err)
	}
	idpRegistry = fresh
	if code, m := fe6adLookup(t, opID); code != http.StatusOK || m["state"] != idpOpCommitted {
		t.Fatalf("after restart = %d %v", code, m)
	}
	if n := fe6adCountAudit("idp.create", id); n != 1 {
		t.Fatalf("restart re-audited (%d)", n)
	}
}

// ─── DG3 — unsettleable ⇒ 503 with zero mutation ────────────────────────────

func TestFE6A0D_Green_UnsettleableIntentRefusesTheWriteWithoutMutation(t *testing.T) {
	reg, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	withConfigVersionsDir(t)
	opsPath := fe6adOpsPath(regPath)
	t.Cleanup(audit.SwapRingForTest())
	const opID = "e3e3e3e3-0000-4000-8000-000000000013"
	id := fe6adCreateWithLostTerminalRecord(t, reg, regPath, opsPath, opID, "Stuck")
	// The ledger becomes unwritable AGAIN (still readable: the pending intent
	// is the durable truth), so the settlement cannot be made durable.
	pending, err := os.ReadFile(opsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(opsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(opsPath, "blocker"), 0o700); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(regPath)
	rev := fe6aIdPRevision(t, id)
	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), ldapProfileBodyForPut("Renamed", nil)), id)
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, refusalOperationUnsettled)
	w = httptest.NewRecorder()
	apiIdPItem(w, fencedDeleteReq(fencedIdPPath(id)), id)
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, refusalOperationUnsettled)
	after, _ := os.ReadFile(regPath)
	if !bytes.Equal(before, after) {
		t.Fatal("a refused write must leave the registry file byte-identical")
	}
	if p := reg.Get(id); p == nil || p.Name != "Stuck" || idpEntryRevision(p) != rev {
		t.Fatalf("a refused write must leave memory untouched; got %+v", p)
	}
	if n := fe6adCountAudit("idp.create", id); n != 0 {
		t.Fatalf("nothing was settled, nothing may be audited; got %d", n)
	}
	// The pending record is still the durable truth once the volume recovers.
	if err := os.RemoveAll(opsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opsPath, pending, 0o600); err != nil {
		t.Fatal(err)
	}
	if st, _ := fe6adLedgerState(t, opsPath, opID); st != idpOpPending {
		t.Fatalf("durable truth = %s, want pending", st)
	}
	// An UNRELATED add is never blocked by another profile's intent.
	if code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Unrelated", nil)); code != http.StatusOK {
		t.Fatalf("unrelated create = %d %v", code, m)
	}
}

// ─── DG4 — CP→DP ReplaceAll settles or defers ───────────────────────────────

func TestFE6A0D_Green_ReplaceAllSettlesOrDefersAnOutstandingIntent(t *testing.T) {
	reg, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	opsPath := fe6adOpsPath(regPath)
	t.Cleanup(audit.SwapRingForTest())
	const opID = "e4e4e4e4-0000-4000-8000-000000000014"
	id := fe6adCreateWithLostTerminalRecord(t, reg, regPath, opsPath, opID, "Synced")
	// (a) Cannot settle: the ledger is unwritable ⇒ the snapshot is DEFERRED,
	// nothing applied, the profile stays.
	pending, _ := os.ReadFile(opsPath)
	_ = os.Remove(opsPath)
	if err := os.MkdirAll(filepath.Join(opsPath, "blocker"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := reg.ReplaceAll([]*IdPProfile{}); !errors.Is(err, errIdPOperationUnsettled) {
		t.Fatalf("ReplaceAll must defer with errIdPOperationUnsettled; got %v", err)
	}
	if reg.Get(id) == nil {
		t.Fatal("a deferred snapshot must apply nothing")
	}
	// (b) Can settle: the removal settles the intent first (committed from
	// provenance, audited once), then applies.
	if err := os.RemoveAll(opsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opsPath, pending, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reg.ReplaceAll([]*IdPProfile{}); err != nil {
		t.Fatalf("ReplaceAll = %v", err)
	}
	if reg.Get(id) != nil {
		t.Fatal("the snapshot must have applied")
	}
	if st, audited := fe6adLedgerState(t, opsPath, opID); st != idpOpCommitted || !audited {
		t.Fatalf("intent = %s audited=%v, want committed+audited", st, audited)
	}
	if n := fe6adCountAudit("idp.create", id); n != 1 {
		t.Fatalf("exactly one success audit; got %d", n)
	}
	// (c) Provenance travels CP→DP: a snapshot carrying the profile keeps it.
	p := &IdPProfile{ID: "dp-prov", Name: "DP", Type: IdPTypeSAML, Revision: 3, OperationID: opID,
		SAML: &SAMLProfileConfig{MetadataXML: "<EntityDescriptor/>"}}
	if err := reg.ReplaceAll([]*IdPProfile{p}); err != nil {
		t.Fatal(err)
	}
	if got := reg.Get("dp-prov"); got == nil || got.OperationID != opID || got.Revision != 3 {
		t.Fatalf("provenance must survive the wire; got %+v", got)
	}
}

// ─── DG5 — degraded ledger posture at the handlers ──────────────────────────

func TestFE6A0D_Green_DegradedLedgerRefusesIdentifiedWritesLookupsAndChangesButNotAdds(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	withConfigVersionsDir(t)
	opsPath := fe6adOpsPath(regPath)
	const opID = "e5e5e5e5-0000-4000-8000-000000000015"
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Existing", nil), "operationId="+opID)
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	if err := os.WriteFile(opsPath, []byte("{not a ledger"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(regPath); err != nil {
		t.Fatal(err)
	}
	idpRegistry = fresh
	w := httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	ops, _ := fe6aJSON(t, w)["operations"].(map[string]any)
	if ops["degraded"] != true || ops["degradedReason"] != "corrupt" {
		t.Fatalf("read model = %v", ops)
	}
	mux := d0WireMux(t)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, getReq("/api/idp/operations/"+opID))
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, refusalOperationLedgerDegraded)
	if code, m = fe6acCreateFenced(t, ldapProfileBodyForPut("Identified", nil), "operationId="+testOperationID()); code != http.StatusServiceUnavailable || m["code"] != refusalOperationLedgerDegraded {
		t.Fatalf("identified create = %d %v", code, m)
	}
	rev := fe6aIdPRevision(t, id)
	w = httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), ldapProfileBodyForPut("Changed", nil)), id)
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, refusalOperationLedgerDegraded)
	w = httptest.NewRecorder()
	apiIdPItem(w, fencedDeleteReq(fencedIdPPath(id)), id)
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, refusalOperationLedgerDegraded)
	if p := fresh.Get(id); p == nil || p.Name != "Existing" {
		t.Fatalf("refusals must not mutate; got %+v", p)
	}
	// A pure add touches nothing an intent could target.
	if code, m = fe6acCreateFenced(t, ldapProfileBodyForPut("Added", nil)); code != http.StatusOK {
		t.Fatalf("unidentified add = %d %v", code, m)
	}
	if b, err := os.ReadFile(opsPath); err != nil || string(b) != "{not a ledger" {
		t.Fatalf("the damaged ledger must be left exactly in place as evidence (%v %q)", err, b)
	}
}

// ─── DG6 — capacity refusal at the handler ──────────────────────────────────

func TestFE6A0D_Green_UnresolvedCapacityRefusesANewOperationTruthfully(t *testing.T) {
	reg, _ := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	ops := reg.operations()
	for i := 0; i < idpOperationsMax; i++ {
		id := testOperationID()
		if _, created, err := ops.Begin(idpOperation{OperationID: id, Action: "idp.create", Actor: "a", ProfileID: "p-" + id[:8], SpecDigest: "d", RegistryRevision: "r"}); err != nil || !created {
			t.Fatalf("Begin #%d: %v", i, err)
		}
	}
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Full", nil), "operationId="+testOperationID())
	if code != http.StatusServiceUnavailable || m["code"] != refusalOperationLedgerFull {
		t.Fatalf("want 503 operation_ledger_full, got %d %v", code, m)
	}
	if n := len(reg.All()); n != 0 {
		t.Fatalf("a refused operation must create nothing (%d)", n)
	}
	w := httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	rm, _ := fe6aJSON(t, w)["operations"].(map[string]any)
	if rm["unresolved"] != float64(idpOperationsMax) || rm["capacity"] != float64(idpOperationsMax) || rm["degraded"] != false {
		t.Fatalf("read model = %v", rm)
	}
	// Settling one (aborted: no such profile) frees exactly one slot.
	pending := ops.Unresolved()
	if err := reg.settleOperation(ops, pending[0], nil, "test"); err != nil {
		t.Fatal(err)
	}
	if code, m = fe6acCreateFenced(t, ldapProfileBodyForPut("Full", nil), "operationId="+testOperationID()); code != http.StatusOK {
		t.Fatalf("after one settlement = %d %v", code, m)
	}
}

// ─── DG7 — durable-first Finish ─────────────────────────────────────────────

func TestFE6A0D_Green_FinishLeavesMemoryPendingWhenTheRecordIsNotDurable(t *testing.T) {
	dir := t.TempDir()
	s := newIdPOperationStore(filepath.Join(dir, "idp_profiles.json"))
	const opID = "e7e7e7e7-0000-4000-8000-000000000017"
	if _, created, err := s.Begin(idpOperation{OperationID: opID, Action: "idp.create", Actor: "a", ProfileID: "p", SpecDigest: "d", RegistryRevision: "r"}); err != nil || !created {
		t.Fatal(err)
	}
	opsPath := filepath.Join(dir, idpOperationsFile)
	if err := os.Remove(opsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(opsPath, "blocker"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := s.Finish(opID, idpOpCommitted, "", "rev", map[string]any{"id": "p"}, "detail", nil)
	if !errors.Is(err, errIdPOperationPersist) {
		t.Fatalf("Finish must report the persist failure; got %v", err)
	}
	if op, gerr := s.Get(opID); gerr != nil || op == nil || op.State != idpOpPending || op.Result != nil {
		t.Fatalf("memory must not claim a terminal state the disk does not hold; got %+v", op)
	}
	if err := s.MarkAudited(opID); !errors.Is(err, errIdPOperationPersist) {
		t.Fatalf("MarkAudited must report the persist failure; got %v", err)
	}
	if op, _ := s.Get(opID); op.Audited {
		t.Fatal("audited must not flip in memory without a durable record")
	}
}
