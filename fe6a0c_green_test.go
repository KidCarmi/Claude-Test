package main

// fe6a0c_green_test.go — FE-6A.0 correction round: GREEN proofs beyond the
// CR1–CR10 defect matrix (fe6a0c_red_test.go). Each row pins a property the
// external review required a proof for and that the RED matrix does not
// already carry: both interleaving directions of the shared reference gate
// (Blocker 5), restart recovery of a durable operation intent and the
// in-progress/replay-across-restart semantics (Blocker 9), the SAML and LDAP
// dependency canaries (Blocker 6), every non-durable-store refusal (Blocker
// 7), fleet facts on update/delete (Blocker 8), and the per-user scope of
// session invalidation (Blocker 2).

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fe6acEnabledSAML seeds an ENABLED interactive profile without a live
// provider (reference semantics only — exactly what
// validateSSOProviderRefsLive and objectReferences read).
func fe6acEnabledSAML(t *testing.T, reg *IdPRegistry, id string) {
	t.Helper()
	if err := reg.Upsert(&IdPProfile{ID: id, Name: "Corp SAML", Type: IdPTypeSAML, Enabled: false,
		SAML: &SAMLProfileConfig{MetadataXML: "<EntityDescriptor/>"}}); err != nil {
		t.Fatal(err)
	}
	reg.mu.Lock()
	for _, p := range reg.profiles {
		if p.ID == id {
			p.Enabled = true
		}
	}
	reg.mu.Unlock()
}

func fe6acSSORuleBody(name, ref string) map[string]any {
	body := authRuleBody(name, name+".test")
	body["auth"] = map[string]any{"outcome": "SSORequired", "owner": "secops", "reason": "portal requires SSO", "providerRefs": []string{ref}}
	return body
}

// ─── Blocker 5 — both interleaving directions ───────────────────────────────

// Writer first: the SSORequired create validated its providerRef and holds
// the SHARED gate inside its validate→commit window; the delete must wait on
// the EXCLUSIVE side, so when it scans it SEES the committed reference and is
// refused. Without the gate the delete would land inside the window and the
// writer would commit a dangling reference (both 200).
func TestFE6A0C_Green_Gate_WriterFirstDeleteSeesTheCommittedReference(t *testing.T) {
	draftTestSetup(t)
	fe6aSwapConfigStore(t)
	reg, _ := fe6aSwapRegistry(t, "")
	fe6acEnabledSAML(t, reg, "corp-saml")
	rev := fe6aIdPRevision(t, "corp-saml")

	parked, release := make(chan struct{}), make(chan struct{})
	prev := policyWriteStateDecisionHook
	var parkedOnce bool
	policyWriteStateDecisionHook = func(r *http.Request, s string) {
		if s == "resolved" && r.Header.Get(holdHeader) == "resolved" && !parkedOnce {
			parkedOnce = true
			close(parked)
			<-release
		}
	}
	t.Cleanup(func() { policyWriteStateDecisionHook = prev })

	writerDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		apiAuthPolicyCreate(w, heldReq("POST", "/api/authpolicy", fe6acSSORuleBody("sso-writer-first", "corp-saml"), "resolved"))
		writerDone <- w
	}()
	select {
	case <-parked:
	case <-time.After(30 * time.Second):
		t.Fatal("writer never reached its hold stage")
	}
	deleteDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/corp-saml?revision="+strconv.FormatInt(rev, 10), nil), "corp-saml")
		deleteDone <- w
	}()
	select {
	case w := <-deleteDone:
		t.Fatalf("delete completed (%d) while the SSORequired writer held the reference gate", w.Code)
	case <-time.After(time.Second):
	}
	close(release)
	ww := <-writerDone
	if ww.Code != http.StatusOK {
		t.Fatalf("writer = %d: %s", ww.Code, ww.Body.String())
	}
	var dw *httptest.ResponseRecorder
	select {
	case dw = <-deleteDone:
	case <-time.After(10 * time.Second):
		t.Fatal("delete never completed after the writer released the gate")
	}
	m := fe6aAssertRefusal(t, dw, http.StatusConflict, "referenced")
	if cur, _ := m["current"].(map[string]any); cur["references"] == nil {
		t.Fatalf("refusal must name the committed reference; got %v", m)
	}
	if reg.Get("corp-saml") == nil {
		t.Fatal("a referenced provider was deleted")
	}
	if n := len(policyStore.List()); n != 1 {
		t.Fatalf("the writer's rule must exist (%d rules)", n)
	}
}

// Delete first: the delete holds the EXCLUSIVE gate across scan + durable
// delete; the SSORequired create arriving inside that window waits on the
// SHARED side and then revalidates its providerRef against the post-delete
// registry — refused, nothing committed. Without the gate the writer would
// validate against the still-present provider and commit a dangling ref.
func TestFE6A0C_Green_Gate_DeleteFirstWriterRevalidatesAndRefuses(t *testing.T) {
	draftTestSetup(t)
	fe6aSwapConfigStore(t)
	reg, _ := fe6aSwapRegistry(t, "")
	fe6acEnabledSAML(t, reg, "corp-saml")
	rev := fe6aIdPRevision(t, "corp-saml")

	parked, release := make(chan struct{}), make(chan struct{})
	idpDeletePauseHook = func() { close(parked); <-release }
	t.Cleanup(func() { idpDeletePauseHook = nil })

	deleteDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/corp-saml?revision="+strconv.FormatInt(rev, 10), nil), "corp-saml")
		deleteDone <- w
	}()
	select {
	case <-parked:
	case <-time.After(30 * time.Second):
		t.Fatal("delete never reached the pause between scan and durable delete")
	}
	writerDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		apiAuthPolicyCreate(w, jsonReq("POST", "/api/authpolicy", fe6acSSORuleBody("sso-delete-first", "corp-saml")))
		writerDone <- w
	}()
	select {
	case w := <-writerDone:
		t.Fatalf("SSORequired writer completed (%d) while the delete held the exclusive gate", w.Code)
	case <-time.After(time.Second):
	}
	close(release)
	dw := <-deleteDone
	if dw.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", dw.Code, dw.Body.String())
	}
	var ww *httptest.ResponseRecorder
	select {
	case ww = <-writerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("writer never completed after the delete released the gate")
	}
	if ww.Code != http.StatusBadRequest {
		t.Fatalf("writer after the delete = %d, want 400 (providerRef no longer resolves): %s", ww.Code, ww.Body.String())
	}
	if reg.Get("corp-saml") != nil {
		t.Fatal("delete did not land")
	}
	if n := len(policyStore.List()); n != 0 {
		t.Fatalf("a dangling SSORequired rule was committed (%d rules)", n)
	}
}

// ─── Blocker 9 — durable intent: restart recovery, in-progress, replay ──────

func TestFE6A0C_Green_PendingIntentIsReconciledFromTheRegistryFileAtBoot(t *testing.T) {
	reg, path := fe6aSwapRegistry(t, "")
	if err := reg.Upsert(&IdPProfile{ID: "present-id", Name: "Present", Type: IdPTypeSAML,
		SAML: &SAMLProfileConfig{MetadataXML: "<EntityDescriptor/>"}}); err != nil {
		t.Fatal(err)
	}
	ops := reg.operations()
	const opPresent, opAbsent = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	for _, in := range []idpOperation{
		{OperationID: opPresent, Action: "idp.create", Actor: "admin", ProfileID: "present-id", SpecDigest: "d", RegistryRevision: "r"},
		{OperationID: opAbsent, Action: "idp.create", Actor: "admin", ProfileID: "absent-id", SpecDigest: "d", RegistryRevision: "r"},
	} {
		if _, created, err := ops.Begin(in); err != nil || !created {
			t.Fatalf("Begin(%s): created=%v err=%v", in.OperationID, created, err)
		}
	}
	// RESTART: a fresh process loads the registry file and its intent ring.
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(path); err != nil {
		t.Fatal(err)
	}
	idpRegistry = fresh
	mux := d0WireMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, getReq("/api/idp/operations/"+opPresent))
	if w.Code != http.StatusOK {
		t.Fatalf("lookup = %d: %s", w.Code, w.Body.String())
	}
	m := fe6aJSON(t, w)
	if m["state"] != "committed" || m["profileId"] != "present-id" || m["committedRevision"] != fresh.DocumentRevision() {
		t.Fatalf("an intent whose profile is in the registry file must reconcile to committed; got %v", m)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, getReq("/api/idp/operations/"+opAbsent))
	if st := fe6aJSON(t, w)["state"]; st != "aborted" {
		t.Fatalf("an intent whose profile never reached the file must reconcile to aborted; got %v", st)
	}
	if fe6aJSON(t, w)["code"] != "reconciled_absent" {
		t.Fatalf("aborted reconciliation must say why; got %v", fe6aJSON(t, w))
	}
	// Deterministic: a second load changes nothing.
	again := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := again.Load(path); err != nil {
		t.Fatal(err)
	}
	if op := again.operations().Get(opPresent); op == nil || op.State != idpOpCommitted {
		t.Fatalf("reconciled state must be durable; got %+v", op)
	}
}

func TestFE6A0C_Green_CommittedOperationReplaysAcrossRestart(t *testing.T) {
	_, path := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	const opID = "33333333-3333-4333-8333-333333333333"
	body := ldapProfileBodyForPut("Replayed", nil)
	code, first := fe6acCreateFenced(t, body, "operationId="+opID)
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, first)
	}
	// RESTART, then the client re-sends the same operation.
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(path); err != nil {
		t.Fatal(err)
	}
	idpRegistry = fresh
	before := fe6acAuditSnapshot()
	code, again := fe6acCreateFenced(t, body, "operationId="+opID)
	if code != http.StatusOK || again["replayed"] != true || again["id"] != first["id"] {
		t.Fatalf("replay after restart = %d %v, want the recorded result", code, again)
	}
	if n := len(fresh.All()); n != 1 {
		t.Fatalf("replay after restart created a profile (%d)", n)
	}
	fe6acAssertNoNewAudit(t, before, "idp.create")
}

func TestFE6A0C_Green_InProgressOperationRefusesRedispatch(t *testing.T) {
	reg, _ := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	const opID = "44444444-4444-4444-8444-444444444444"
	body := ldapProfileBodyForPut("Inflight", nil)
	var p IdPProfile
	fe6acDecodeInto(t, body, &p)
	normalizeIdPProfileWriteInput(&p)
	// A concurrent dispatch of the same id already recorded its intent.
	if _, created, err := reg.operations().Begin(idpOperation{OperationID: opID, Action: "idp.create", Actor: "x",
		ProfileID: "pre-minted", SpecDigest: idpSpecDigest(&p), RegistryRevision: reg.DocumentRevision()}); err != nil || !created {
		t.Fatalf("Begin: %v %v", created, err)
	}
	code, m := fe6acCreateFenced(t, body, "operationId="+opID)
	if code != http.StatusConflict || m["code"] != "operation_in_progress" {
		t.Fatalf("re-dispatch of a pending operation = %d %v, want 409 operation_in_progress", code, m)
	}
	if n := len(reg.All()); n != 0 {
		t.Fatalf("re-dispatch wrote a profile (%d)", n)
	}
	// A different id is an independent write and proceeds.
	code, m = fe6acCreateFenced(t, body, "operationId=55555555-5555-4555-8555-555555555555")
	if code != http.StatusOK {
		t.Fatalf("independent operation = %d %v", code, m)
	}
	// Malformed ids are refused before anything is consulted.
	code, m = fe6acCreateFenced(t, body, "operationId=not-a-uuid")
	if code != http.StatusBadRequest || m["code"] != "invalid_input" {
		t.Fatalf("malformed operationId = %d %v, want 400 invalid_input", code, m)
	}
}

// ─── Blocker 6 — SAML and LDAP dependency canaries ──────────────────────────

func TestFE6A0C_Green_SAMLMetadataFetchCanaryIsBounded(t *testing.T) {
	const canary = "CANARY-saml-5d2c17-idp-metadata.corp.example"
	reg, path := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	orig := ssrfSafeDialContext
	ssrfSafeDialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial tcp 203.0.113.20:443: " + canary + ": tls: handshake failure")
	}
	t.Cleanup(func() { ssrfSafeDialContext = orig })
	since := fe6aSince()
	probe := fe6aProbeIdP(t, reg, path)
	var w *httptest.ResponseRecorder
	logs := captureLogger(t, func() {
		w = httptest.NewRecorder()
		apiIdPList(w, jsonReq(http.MethodPost, fencedIdPCreatePath(), map[string]any{
			"name": "Broken SAML", "type": "saml", "enabled": true,
			"saml": map[string]any{"metadataUrl": "https://203.0.113.20/metadata"},
		}))
	})
	m := fe6aAssertRefusal(t, w, http.StatusBadGateway, "provider_compile_failed")
	if cur, _ := m["current"].(map[string]any); cur["reason"] != "saml_metadata" {
		t.Fatalf("bounded reason class expected; got %v", m)
	}
	for _, needle := range []string{canary, "203.0.113.20", "handshake", "tls:"} {
		if strings.Contains(w.Body.String(), needle) {
			t.Fatalf("response leaked %q: %s", needle, w.Body.String())
		}
	}
	if strings.Contains(logs, canary) || strings.Contains(logs, "203.0.113.20") {
		t.Fatalf("process log leaked the dependency detail: %s", logs)
	}
	fe6acAssertAuditClean(t, since, canary)
	probe.assertIdPUnchanged(t, reg, path, "idp.create")
}

func TestFE6A0C_Green_LDAPPreflightCanaryIsBounded(t *testing.T) {
	const host = "canary-ldap-9a1f3e.corp.example"
	reg, path := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	since := fe6aSince()
	probe := fe6aProbeIdP(t, reg, path)
	body := ldapProfileBodyForPut("Preflighted AD", map[string]any{"url": "ldaps://" + host + ":636", "bindPassword": "s"})
	body["enabled"] = true
	var w *httptest.ResponseRecorder
	logs := captureLogger(t, func() {
		w = httptest.NewRecorder()
		apiIdPList(w, jsonReq(http.MethodPost, fencedIdPCreatePath("preflight=connection"), body))
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("preflight against an unreachable directory = %d: %s", w.Code, w.Body.String())
	}
	m := fe6aJSON(t, w)
	rep, _ := m["test"].(map[string]any)
	steps, _ := rep["steps"].([]any)
	if len(steps) == 0 {
		t.Fatalf("preflight report must carry steps; got %v", m)
	}
	st, _ := steps[0].(map[string]any)
	if ok, _ := st["ok"].(bool); ok || st["error"] == "" {
		t.Fatalf("first step must be the failed reachability step with a bounded class; got %v", st)
	}
	for _, needle := range []string{host, "no such host", "dial tcp", "x509"} {
		if strings.Contains(w.Body.String(), needle) {
			t.Fatalf("preflight response leaked %q: %s", needle, w.Body.String())
		}
	}
	if strings.Contains(logs, host) {
		t.Fatalf("process log leaked the directory host: %s", logs)
	}
	fe6acAssertAuditClean(t, since, host)
	probe.assertIdPUnchanged(t, reg, path, "idp.create")
}

func fe6acAssertAuditClean(t *testing.T, since int64, needle string) {
	t.Helper()
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.TS >= since && strings.Contains(e.Detail+e.Before+e.After+e.Object, needle) {
			t.Fatalf("audit leaked %q: %+v", needle, e)
		}
	}
}

// ─── Blocker 7 — every administrative mutation on a non-durable store ───────

func TestFE6A0C_Green_NonDurableStoresRefuseEveryAdminMutation(t *testing.T) {
	orig := idpRegistry
	mem := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := mem.Upsert(&IdPProfile{ID: "mem-saml", Name: "Mem", Type: IdPTypeSAML, SAML: &SAMLProfileConfig{MetadataXML: "<EntityDescriptor/>"}}); err != nil {
		t.Fatal(err)
	}
	idpRegistry = mem
	t.Cleanup(func() { idpRegistry = orig })
	fe6aSwapConfigStore(t)
	withLegacyLDAPYAML(t, &LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
	since := fe6aSince()
	rev := fe6aIdPRevision(t, "mem-saml")
	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/mem-saml?revision="+strconv.FormatInt(rev, 10), map[string]any{"name": "Renamed", "type": "saml", "saml": map[string]any{"metadataXml": "<EntityDescriptor/>"}}), "mem-saml")
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, "persistence_not_configured")
	w = httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/mem-saml?revision="+strconv.FormatInt(rev, 10), nil), "mem-saml")
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, "persistence_not_configured")
	w = httptest.NewRecorder()
	apiIdPLegacyLDAPImport(w, jsonReq(http.MethodPost, "/api/idp/legacy-ldap/import", nil))
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, "persistence_not_configured")
	if p := mem.Get("mem-saml"); p == nil || p.Name != "Mem" || len(mem.All()) != 1 {
		t.Fatal("a refused mutation changed the in-memory registry")
	}
	fe6aAssertNoAudit(t, since, "idp.update", "idp.delete", "idp.import")

	origCfg := cfg
	c := newTestConfig() // no users file
	if err := c.SetAuth("root", "RootPass1"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetUIUser("bob", "BobPass123", RoleViewer); err != nil {
		t.Fatal(err)
	}
	cfg = c
	t.Cleanup(func() { cfg = origCfg })
	rrev := c.RosterRevision()
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(rrev, 10), map[string]any{"username": "bob", "role": "admin"}))
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, "persistence_not_configured")
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodDelete, "/api/auth/users?username=bob&revision="+strconv.FormatInt(rrev, 10), nil))
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, "persistence_not_configured")
	w = fe6acSelfChange(t, "bob", "BobPass123", "BobNew456", 0)
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, "persistence_not_configured")
	if role, ok := c.VerifyUIUser("bob", "BobPass123"); !ok || role != RoleViewer {
		t.Fatal("a refused mutation changed the in-memory roster")
	}
	fe6aAssertNoAudit(t, since, "auth.users.update", "auth.users.delete", "auth.password_change")
	w = httptest.NewRecorder()
	apiAuthUsers(w, getReq("/api/auth/users"))
	if w.Code != http.StatusOK {
		t.Fatalf("reads must keep working: %d", w.Code)
	}
}

// ─── Blocker 8 — fleet facts on update and delete ───────────────────────────

func TestFE6A0C_Green_UpdateAndDeleteCarryFleetFacts(t *testing.T) {
	reg, _ := fe6aSwapRegistry(t, "")
	store := fe6aSwapConfigStore(t)
	withConfigVersionsDir(t)
	if err := reg.Upsert(&IdPProfile{ID: "fleet-saml", Name: "Fleet", Type: IdPTypeSAML, SAML: &SAMLProfileConfig{MetadataXML: "<EntityDescriptor/>"}}); err != nil {
		t.Fatal(err)
	}
	if err := publishCurrentConfigSnapshot(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	if rc, _ := fe6aJSON(t, w)["cluster"].(map[string]any); rc["state"] != "published" {
		t.Fatalf("published registry must read as published; got %v", rc)
	}
	setRewriteIdentityDegraded("green-fleet")
	t.Cleanup(clearRewriteIdentityDegraded)
	since := fe6aSince()
	rev := fe6aIdPRevision(t, "fleet-saml")
	w = httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/fleet-saml?revision="+strconv.FormatInt(rev, 10), map[string]any{"name": "Fleet v2", "type": "saml", "saml": map[string]any{"metadataXml": "<EntityDescriptor/>"}}), "fleet-saml")
	if w.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", w.Code, w.Body.String())
	}
	um := fe6aJSON(t, w)
	if cl, _ := um["cluster"].(map[string]any); cl["publication"] != "rejected" || cl["reason"] != "identity_degraded" {
		t.Fatalf("update must report the bounded fleet rejection; got %v", um["cluster"])
	}
	if e := fe6aFindAudit(since, "idp.update"); e == nil || !strings.Contains(e.Detail, "fleet=rejected:identity_degraded") {
		t.Fatalf("update audit must carry the fleet outcome; got %+v", e)
	}
	if reg.Get("fleet-saml").Name != "Fleet v2" {
		t.Fatal("the local commit must stand although the fleet refused")
	}
	w = httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	rc, _ := fe6aJSON(t, w)["cluster"].(map[string]any)
	lr, _ := rc["lastRejection"].(map[string]any)
	if rc["state"] != "pending" || lr["reason"] != "identity_degraded" {
		t.Fatalf("read model must show pending with the last rejection; got %v", rc)
	}
	if store.Version() != 1 {
		t.Fatalf("a rejected publication must not advance the store (v%d)", store.Version())
	}
	rev = fe6aIdPRevision(t, "fleet-saml")
	w = httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/fleet-saml?revision="+strconv.FormatInt(rev, 10), nil), "fleet-saml")
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", w.Code, w.Body.String())
	}
	if e := fe6aFindAudit(since, "idp.delete"); e == nil || !strings.Contains(e.Detail, "fleet=rejected:identity_degraded") {
		t.Fatalf("delete audit must carry the fleet outcome; got %+v", e)
	}
	clearRewriteIdentityDegraded()
	if err := publishCurrentConfigSnapshot(); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	rc, _ = fe6aJSON(t, w)["cluster"].(map[string]any)
	if rc["state"] != "published" || rc["lastRejection"] != nil {
		t.Fatalf("recovery must clear the pending state; got %v", rc)
	}
}

// ─── Blocker 2 — invalidation is per user, and a Basic-auth self change ─────

func TestFE6A0C_Green_GenerationInvalidatesOnlyTheChangedUser(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	for _, u := range []struct{ n, p string }{{"alice", "AlicePass1"}, {"bob", "BobPass123"}} {
		if err := c.SetUIUser(u.n, u.p, RoleOperator); err != nil {
			t.Fatal(err)
		}
	}
	ch := fe6aFullChain(t)
	alice := ch.login(t, "alice", "AlicePass1")
	bob := ch.login(t, "bob", "BobPass123")
	aliceGen, bobGen := fe6acUserGeneration(t, "alice"), fe6acUserGeneration(t, "bob")
	rev := fe6aRosterRevision(t)
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{"username": "bob", "role": "viewer"}))
	if w.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", w.Code, w.Body.String())
	}
	if g, _ := fe6aJSON(t, w)["securityGeneration"].(float64); int64(g) <= bobGen {
		t.Fatal("update must report the advanced security generation")
	}
	if fe6acUserGeneration(t, "alice") != aliceGen || fe6acUserGeneration(t, "bob") <= bobGen {
		t.Fatal("only the changed user's generation may move")
	}
	if st := fe6acStatus(t, ch, alice); st["loggedIn"] != true {
		t.Fatalf("an unrelated user's session must survive; status=%v", st)
	}
	if st := fe6acStatus(t, ch, bob); st["loggedIn"] != false {
		t.Fatalf("the changed user's session must be invalid; status=%v", st)
	}
	if got := ch.get(t, bob, "/api/auth/users"); got != http.StatusUnauthorized {
		t.Fatalf("invalidated session on a gated route = %d, want 401", got)
	}
}

func TestFE6A0C_Green_BasicAuthSelfChangeReportsFactsWithoutACookie(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("bob", "BobPass123", RoleOperator); err != nil {
		t.Fatal(err)
	}
	gen, _ := c.UserSecurityGeneration("bob")
	r := jsonReq(http.MethodPost, "/api/auth/change-password?generation="+strconv.FormatInt(gen, 10), map[string]string{"current_password": "BobPass123", "new_password": "BobNew456"})
	r = withRoleCtx(r, RoleOperator)
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "bob"))
	w := httptest.NewRecorder()
	apiAuthChangePassword(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("change = %d: %s", w.Code, w.Body.String())
	}
	m := fe6aJSON(t, w)
	if m["sessionsRevoked"] != true || m["selfAffected"] != true {
		t.Fatalf("facts missing: %v", m)
	}
	if g, _ := m["securityGeneration"].(float64); int64(g) <= gen {
		t.Fatalf("generation must advance (%d → %v)", gen, m["securityGeneration"])
	}
	if strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), uiSessionCookieName+"=") {
		t.Fatal("a caller without a UI session cookie must not be issued one")
	}
	if _, ok := c.VerifyUIUser("bob", "BobNew456"); !ok {
		t.Fatal("new credential not accepted")
	}
}

// fe6acDecodeInto round-trips a JSON body map into a typed value.
func fe6acDecodeInto(t *testing.T, body map[string]any, dst any) {
	t.Helper()
	r := jsonReq(http.MethodPost, "/", body)
	if err := decodeJSON(r, dst); err != nil {
		t.Fatal(err)
	}
}

// ─── Legacy UI carries the corrected fences ─────────────────────────────────

func TestFE6A0C_Green_LegacyUISendsTheCorrectionFences(t *testing.T) {
	b, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, want := range []string{
		"const path = '/api/auth/users?revision=' + encodeURIComponent(_usersRevision);",
		"_lockoutsGeneration = d.generation || 0;",
		"'/api/auth/lockouts?generation=' + encodeURIComponent(_lockoutsGeneration)",
		"_idpDocumentRevision = (data && data.revision) || '';",
		"q.push('documentRevision=' + encodeURIComponent(_idpDocumentRevision));",
		"q.push('operationId=' + encodeURIComponent(newOperationId()));",
		"function newOperationId() {",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("legacy UI missing FE-6A.0 correction patch: %q", want)
		}
	}
}
