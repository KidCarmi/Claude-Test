package main

// fe6a0d_red_test.go — FE-6A.0 correction round 3 (external review of
// `08c972c3`): deterministic RED rows for the three source-level contract
// breaks, committed on exactly `08c972c3` BEFORE any product change.
//
//   DR1  the operation ledger is not durably authoritative:
//        a. a terminal-record persist failure after the registry commit still
//           answers 2xx and GET reports `committed` from memory     (B1)
//        b. a durable `pending` intent whose profile is later deleted is
//           reconciled from PRESENCE, so restart reports `aborted` for an
//           operation that committed; no writer settles it first      (B1)
//        c. a crash after the durable terminal record but before the success
//           audit loses the audit forever — reconciliation emits nothing (B1)
//   DR2  the at-most-once ledger fails open:
//        a. the ring truncates the OLDEST record regardless of state, so a
//           pending intent is evicted and its operationId is accepted again (B2)
//        b. a corrupt / unreadable ledger silently becomes an empty
//           authoritative ledger (evidence moved aside, id accepted as new) (B2)
//   DR3  raw provider errors cross the log boundary on the other compile paths:
//        a. IdPRegistry.Load logs the raw compile error                  (B3)
//        b. ReplaceAll wraps the raw compile error and the snapshot apply
//           path logs it                                                 (B3)
//
// Seams: fileutil.SetWriteSuccessObserver (fires after the registry commit
// and before the terminal-record persist — the exact boundary of DR1a),
// the ssrfSafeDialContext dial seam (canaries), direct edits of the durable
// ledger file (crash simulation), a swapped audit ring, a fresh IdPRegistry
// load (restart). No sleeps.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/fileutil"
)

func fe6adOpsPath(regPath string) string {
	return filepath.Join(filepath.Dir(regPath), idpOperationsFile)
}

// fe6adRewriteOps applies edit to every record of the durable ledger file.
func fe6adRewriteOps(t *testing.T, opsPath string, edit func(rec map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(opsPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	var recs []map[string]any
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatalf("decode ledger: %v", err)
	}
	for _, rec := range recs {
		edit(rec)
	}
	out, _ := json.MarshalIndent(recs, "", "  ")
	if err := os.WriteFile(opsPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fe6adCountAudit(action, object string) int {
	n := 0
	entries := auditGet()
	for i := range entries {
		if entries[i].Action == action && entries[i].Object == object {
			n++
		}
	}
	return n
}

// fe6adCanaryDial makes every outbound dial fail with an error carrying the
// canary (the OIDC discovery / SAML metadata dependency path).
func fe6adCanaryDial(t *testing.T, canary string) {
	t.Helper()
	orig := ssrfSafeDialContext
	ssrfSafeDialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial tcp 203.0.113.30:443: " + canary + ": tls: handshake failure")
	}
	t.Cleanup(func() { ssrfSafeDialContext = orig })
}

func fe6adEnabledOIDC(id string) *IdPProfile {
	return &IdPProfile{ID: id, Name: "Boot OIDC", Type: IdPTypeOIDC, Enabled: true, Revision: 1,
		OIDC: &OIDCProfileConfig{Issuer: "https://203.0.113.30", ClientID: "c"}}
}

// ─── DR1a — terminal-record persistence failure after the registry commit ──

func TestFE6A0D_DR1a_TerminalPersistFailureIsNeverATerminalAnswer(t *testing.T) {
	reg, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	opsPath := fe6adOpsPath(regPath)
	// After the registry commit lands (idp_profiles.json written), make the
	// ledger's next atomic write impossible: the ledger path becomes a
	// non-empty directory, so the terminal record cannot be persisted.
	fired := false
	fileutil.SetWriteSuccessObserver(func(path string) {
		if fired || filepath.Base(path) != filepath.Base(regPath) {
			return
		}
		fired = true
		_ = os.Remove(opsPath)
		_ = os.MkdirAll(filepath.Join(opsPath, "blocker"), 0o700)
	})
	t.Cleanup(func() { fileutil.SetWriteSuccessObserver(noteStorageWriteSuccess) })

	const opID = "a1a1a1a1-0000-4000-8000-000000000001"
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Terminal", nil), "operationId="+opID)
	if !fired {
		t.Fatal("precondition: the registry commit never fired the write observer")
	}
	if code >= 200 && code < 300 {
		t.Fatalf("DR1a: a terminal record that could not be persisted was answered %d %v — the client now holds a terminal verdict the durable ledger does not", code, m)
	}
	if code != http.StatusInternalServerError || m["code"] != "outcome_unknown" {
		t.Fatalf("DR1a: want the non-terminal 500 outcome_unknown, got %d %v", code, m)
	}
	if n := len(reg.All()); n != 1 {
		t.Fatalf("the registry commit itself must stand (%d profiles)", n)
	}
	mux := d0WireMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, getReq("/api/idp/operations/"+opID))
	if w.Code == http.StatusOK {
		if st := fe6aJSON(t, w)["state"]; st == idpOpCommitted || st == idpOpAborted {
			t.Fatalf("DR1a: GET claims the durable terminal state %v that was never persisted", st)
		}
	}
}

// ─── DR1b — provenance, not presence: restart must prove the commit ─────────

func TestFE6A0D_DR1b_CommittedIntentSurvivesALaterDeleteAcrossRestart(t *testing.T) {
	reg, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	withConfigVersionsDir(t)
	opsPath := fe6adOpsPath(regPath)
	t.Cleanup(audit.SwapRingForTest())
	const opID = "b1b1b1b1-0000-4000-8000-000000000002"
	// CRASH SIMULATION at the ledger write itself: after the registry commit
	// lands (idp_profiles.json written), the ledger's next atomic write is
	// impossible, so the terminal record (and the audit that follows it)
	// never becomes durable. The durable PENDING intent — exactly what a
	// real crash leaves behind — is captured first and put back once the
	// "volume" recovers, so the process continues against a file that says
	// `pending` while the registry file carries the committed profile.
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
	code, first := fe6acCreateFenced(t, ldapProfileBodyForPut("Provenance", nil), "operationId="+opID)
	fileutil.SetWriteSuccessObserver(noteStorageWriteSuccess)
	if !fired || len(pendingBytes) == 0 {
		t.Fatal("precondition: the registry commit never fired the write observer with a durable pending intent on disk")
	}
	if code != http.StatusOK && code != http.StatusInternalServerError {
		t.Fatalf("create = %d %v", code, first)
	}
	all := reg.All()
	if len(all) != 1 {
		t.Fatalf("the registry commit itself must stand (%d profiles)", len(all))
	}
	id := all[0].ID
	// The volume recovers: the ledger is writable again and still says pending.
	if err := os.RemoveAll(opsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opsPath, pendingBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	// An administrator deletes the profile before anything reconciled it.
	w := httptest.NewRecorder()
	apiIdPItem(w, fencedDeleteReq(fencedIdPPath(id)), id)
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Fatalf("delete = %d: %s", w.Code, w.Body.String())
	}
	// RESTART.
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(regPath); err != nil {
		t.Fatal(err)
	}
	idpRegistry = fresh
	mux := d0WireMux(t)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, getReq("/api/idp/operations/"+opID))
	if w.Code != http.StatusOK {
		t.Fatalf("lookup = %d: %s", w.Code, w.Body.String())
	}
	if st := fe6aJSON(t, w)["state"]; st != idpOpCommitted {
		t.Fatalf("DR1b: an operation whose registry commit landed is reported %v after a later delete + restart — the verdict was derived from presence, not provenance", st)
	}
	if n := fe6adCountAudit("idp.create", id); n != 1 {
		t.Fatalf("DR1b: the success audit must be completed exactly once by settlement/reconciliation; got %d", n)
	}
}

// ─── DR1c — crash after the durable terminal record, before the audit ───────

func TestFE6A0D_DR1c_ReconciliationCompletesTheSuccessAuditExactlyOnce(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	opsPath := fe6adOpsPath(regPath)
	const opID = "c1c1c1c1-0000-4000-8000-000000000003"
	code, first := fe6acCreateFenced(t, ldapProfileBodyForPut("Audited", nil), "operationId="+opID)
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, first)
	}
	id, _ := first["id"].(string)
	// CRASH SIMULATION: terminal record durable, audit never emitted.
	t.Cleanup(audit.SwapRingForTest())
	fe6adRewriteOps(t, opsPath, func(rec map[string]any) { rec["audited"] = false })
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(regPath); err != nil {
		t.Fatal(err)
	}
	if n := fe6adCountAudit("idp.create", id); n != 1 {
		t.Fatalf("DR1c: boot reconciliation must emit the missing success audit exactly once; got %d", n)
	}
	// Idempotent: a second load (or a replay) never emits a second audit.
	again := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := again.Load(regPath); err != nil {
		t.Fatal(err)
	}
	idpRegistry = again
	if code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Audited", nil), "operationId="+opID); code != http.StatusOK || m["replayed"] != true {
		t.Fatalf("replay = %d %v", code, m)
	}
	if n := fe6adCountAudit("idp.create", id); n != 1 {
		t.Fatalf("DR1c: a second load / a replay duplicated the audit (%d)", n)
	}
}

// ─── DR2a — unresolved records are never evicted; capacity refuses ──────────

func TestFE6A0D_DR2a_PendingIntentsAreNeverEvictedAtCapacity(t *testing.T) {
	reg, _ := fe6aSwapRegistry(t, "")
	ops := reg.operations()
	ids := make([]string, 0, idpOperationsMax)
	for i := 0; i < idpOperationsMax; i++ {
		id := testOperationID()
		ids = append(ids, id)
		if _, created, err := ops.Begin(idpOperation{OperationID: id, Action: "idp.create", Actor: "a", ProfileID: "p-" + id[:8], SpecDigest: "d", RegistryRevision: "r"}); err != nil || !created {
			t.Fatalf("Begin #%d: created=%v err=%v", i, created, err)
		}
	}
	extra := testOperationID()
	_, created, err := ops.Begin(idpOperation{OperationID: extra, Action: "idp.create", Actor: "a", ProfileID: "p-extra", SpecDigest: "d", RegistryRevision: "r"})
	if err == nil && created {
		t.Fatal("DR2a: a new operation was admitted while every slot holds an UNRESOLVED intent — something was evicted")
	}
	for _, id := range ids {
		if op, err := ops.Get(id); err != nil || op == nil || op.State != idpOpPending {
			t.Fatalf("DR2a: pending intent %s was evicted or reinterpreted (%+v, %v)", id, op, err)
		}
	}
	// The evicted id must not be accepted as NEW afterwards either.
	if _, created, _ := ops.Begin(idpOperation{OperationID: ids[0], Action: "idp.create", Actor: "a", ProfileID: "p-0", SpecDigest: "d", RegistryRevision: "r"}); created {
		t.Fatal("DR2a: the oldest pending operationId was accepted again as a new operation")
	}
}

// ─── DR2b — a corrupt or unreadable ledger fails closed with evidence ───────

func TestFE6A0D_DR2b_CorruptLedgerNeverBecomesAnEmptyAuthoritativeLedger(t *testing.T) {
	for _, tc := range []struct {
		name    string
		corrupt func(t *testing.T, opsPath string)
	}{
		{"corrupt", func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("{not a ledger"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unreadable", func(t *testing.T, p string) {
			_ = os.Remove(p)
			if err := os.MkdirAll(filepath.Join(p, "blocker"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, regPath := fe6aSwapRegistry(t, "")
			fe6aSwapConfigStore(t)
			opsPath := fe6adOpsPath(regPath)
			const opID = "d2d2d2d2-0000-4000-8000-000000000004"
			body := ldapProfileBodyForPut("Ledger", nil)
			if code, m := fe6acCreateFenced(t, body, "operationId="+opID); code != http.StatusOK {
				t.Fatalf("create = %d %v", code, m)
			}
			tc.corrupt(t, opsPath)
			// RESTART with the damaged ledger.
			fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
			if err := fresh.Load(regPath); err != nil {
				t.Fatal(err)
			}
			idpRegistry = fresh
			if _, err := os.Lstat(opsPath); err != nil {
				t.Fatalf("DR2b: the damaged ledger was moved aside or removed — the only at-most-once evidence is gone (%v)", err)
			}
			code, m := fe6acCreateFenced(t, body, "operationId="+opID)
			if code >= 200 && code < 300 && m["replayed"] != true {
				t.Fatalf("DR2b: a previously used operationId was accepted as NEW on an empty ledger (%d %v)", code, m)
			}
			if code != http.StatusServiceUnavailable {
				t.Fatalf("DR2b: want the fail-closed 503 while the ledger is degraded, got %d %v", code, m)
			}
			if n := len(fresh.All()); n != 1 {
				t.Fatalf("DR2b: a second profile was created (%d)", n)
			}
			mux := d0WireMux(t)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, getReq("/api/idp/operations/"+opID))
			if w.Code == http.StatusNotFound {
				t.Fatal("DR2b: the lookup answered 'no such operation' from an empty ledger — an unknowable answer presented as authoritative")
			}
			w = httptest.NewRecorder()
			apiIdPList(w, getReq("/api/idp"))
			rm := fe6aJSON(t, w)
			if ops, _ := rm["operations"].(map[string]any); ops["degraded"] != true {
				t.Fatalf("DR2b: the read model must report the degraded ledger posture; got %v", rm["operations"])
			}
		})
	}
}

// ─── DR3a — boot Load must not log the raw provider error ───────────────────

func TestFE6A0D_DR3a_BootLoadBoundsTheCompileError(t *testing.T) {
	const canary = "CANARY-boot-load-8c4d2e-idp.corp.example"
	fe6adCanaryDial(t, canary)
	dir := t.TempDir()
	regPath := filepath.Join(dir, "idp_profiles.json")
	b, _ := json.Marshal([]*IdPProfile{fe6adEnabledOIDC("boot-oidc")})
	if err := os.WriteFile(regPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	logs := captureLogger(t, func() {
		if err := fresh.Load(regPath); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})
	for _, needle := range []string{canary, "203.0.113.30", "handshake"} {
		if strings.Contains(logs, needle) {
			t.Fatalf("DR3a: boot Load leaked %q into the process log: %s", needle, logs)
		}
	}
	if fresh.Get("boot-oidc") == nil {
		t.Fatal("the profile must still load (degraded, not live)")
	}
	if _, live := fresh.LiveProvider("boot-oidc"); live {
		t.Fatal("a profile whose provider failed to compile must not be live")
	}
}

// ─── DR3b — ReplaceAll / snapshot apply must not surface the raw error ──────

func TestFE6A0D_DR3b_SnapshotApplyBoundsTheCompileError(t *testing.T) {
	const canary = "CANARY-snapshot-9f1e3b-idp.corp.example"
	fe6adCanaryDial(t, canary)
	withIdPSyncGlobals(t)
	var applyErr error
	logs := captureLogger(t, func() {
		applyErr = applyConfigSnapshot(ConfigSnapshot{Version: 1, IdPProfiles: []*IdPProfile{fe6adEnabledOIDC("synced-oidc")}})
	})
	if applyErr == nil {
		t.Fatal("precondition: a snapshot whose provider cannot be built must be rejected")
	}
	for _, needle := range []string{canary, "203.0.113.30", "handshake"} {
		if strings.Contains(logs, needle) {
			t.Fatalf("DR3b: the snapshot apply path leaked %q into the process log: %s", needle, logs)
		}
		if strings.Contains(applyErr.Error(), needle) {
			t.Fatalf("DR3b: the returned error carries %q: %v", needle, applyErr)
		}
	}
	var compile *idpCompileError
	if !errors.As(applyErr, &compile) {
		t.Fatalf("DR3b: ReplaceAll must classify the failure through the bounded seam (*idpCompileError); got %T: %v", applyErr, applyErr)
	}
}
