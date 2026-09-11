package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Phase C4 — Role-divergence detector tests ─────────────────────────────
//
// These tests pin the C4 contract:
//
//   • recordRoleDivergence increments the counter ONLY when:
//     (a) a c2EvaluatedRoleKey is in the request context, AND
//     (b) the C2-evaluated role's priority is strictly LESS than the
//         role demanded by the handler-level requireRole.
//
//   • requireRole's failure branch invokes recordRoleDivergence but
//     keeps its existing 403-writing semantics. C4 NEVER changes the
//     response decision — handler-level RBAC remains the real backstop.
//
//   • The full middleware chain (uiMetadataEnforcement → mux) injects
//     c2EvaluatedRoleKey from the per-method MinRole, so a request to a
//     dynamic dispatcher's PUT (metadata MethodAny=viewer; handler asks
//     requireRole(admin)) increments the counter when the actor is
//     viewer and does NOT increment when the actor is admin. (Since
//     FE-6A.0 /api/idp/ is per-method, so the chain proof rides a
//     synthetic dispatcher fixture.)
//
// Counter mutations are restored via t.Cleanup so other tests see the
// pre-test baseline regardless of shuffle ordering.

// withEvaluatedRole builds a test request that already carries a C2
// evaluated MinRole and an optional session uiRoleKey. Mirrors c2Req
// from ui_metadata_enforcement_test.go but stamps both keys at once.
func withEvaluatedRole(method, path string, evaluated, session UIRole) *http.Request {
	r := httptest.NewRequest(method, path, http.NoBody)
	r.RemoteAddr = "203.0.113.40:0" // TEST-NET-3, distinct from C2/C2c tests
	ctx := r.Context()
	if evaluated != "" {
		ctx = context.WithValue(ctx, c2EvaluatedRoleKey{}, evaluated)
	}
	if session != "" {
		ctx = context.WithValue(ctx, uiRoleKey{}, session)
	}
	return r.WithContext(ctx)
}

// snapshotDivergence captures the current counter and registers a
// Cleanup that restores it. Lets each test compute deltas without
// leaking state into the shuffled suite.
func snapshotDivergence(t *testing.T) int64 {
	t.Helper()
	before := c2RoleDivergenceTotal.Load()
	t.Cleanup(func() { c2RoleDivergenceTotal.Store(before) })
	return before
}

// ── recordRoleDivergence direct unit tests ────────────────────────────────

// TestC4_RecordRoleDivergence_C2LowerThanHandler is the canonical
// divergence case: C2 metadata said viewer was enough, the handler
// demands admin, and a viewer session is present. recordRoleDivergence
// increments the counter once.
func TestC4_RecordRoleDivergence_C2LowerThanHandler(t *testing.T) {
	before := snapshotDivergence(t)
	r := withEvaluatedRole(http.MethodPut, "/api/idp/test-divergence-1", RoleViewer, RoleViewer)
	recordRoleDivergence(r, RoleAdmin)
	if got := c2RoleDivergenceTotal.Load() - before; got != 1 {
		t.Errorf("counter delta = %d, want 1", got)
	}
}

// TestC4_RecordRoleDivergence_C2EqualsHandler — when C2 and the
// handler agree on the role bar, no divergence is recorded even
// though the handler may still be calling recordRoleDivergence on
// its failure path.
func TestC4_RecordRoleDivergence_C2EqualsHandler(t *testing.T) {
	before := snapshotDivergence(t)
	r := withEvaluatedRole(http.MethodGet, "/api/idp/test-divergence-2", RoleViewer, "")
	recordRoleDivergence(r, RoleViewer)
	if got := c2RoleDivergenceTotal.Load() - before; got != 0 {
		t.Errorf("counter delta = %d, want 0 (parity case)", got)
	}
}

// TestC4_RecordRoleDivergence_C2HigherThanHandler — C2 demanded admin
// but the handler asked for viewer (a permissive handler under a
// strict policy). This direction is NOT divergence per the C4
// definition: C2 is at-least-as-strict. No counter movement.
func TestC4_RecordRoleDivergence_C2HigherThanHandler(t *testing.T) {
	before := snapshotDivergence(t)
	r := withEvaluatedRole(http.MethodGet, "/api/idp/test-divergence-3", RoleAdmin, "")
	recordRoleDivergence(r, RoleViewer)
	if got := c2RoleDivergenceTotal.Load() - before; got != 0 {
		t.Errorf("counter delta = %d, want 0 (C2 stricter than handler)", got)
	}
}

// TestC4_RecordRoleDivergence_NoContext — when no c2EvaluatedRoleKey
// is in the context (route was public, missing meta, no policy, or
// the call bypassed the middleware), the hook is a no-op. Soft-fail;
// requireRole still produces its 403 normally.
func TestC4_RecordRoleDivergence_NoContext(t *testing.T) {
	before := snapshotDivergence(t)
	r := httptest.NewRequest(http.MethodPut, "/api/idp/test-divergence-4", http.NoBody)
	recordRoleDivergence(r, RoleAdmin)
	if got := c2RoleDivergenceTotal.Load() - before; got != 0 {
		t.Errorf("counter delta = %d, want 0 (no context key)", got)
	}
}

// TestC4_RecordRoleDivergence_NilRequest — defensive guard. Should
// never happen for HTTP handlers, but ensures the helper is safe to
// call from any code path.
func TestC4_RecordRoleDivergence_NilRequest(t *testing.T) {
	before := snapshotDivergence(t)
	recordRoleDivergence(nil, RoleAdmin)
	if got := c2RoleDivergenceTotal.Load() - before; got != 0 {
		t.Errorf("counter delta = %d, want 0 (nil request)", got)
	}
}

// ── requireRole failure-branch integration ────────────────────────────────

// TestC4_RequireRole_SuccessNoDivergence — when requireRole returns
// true (the session meets the bar), the divergence hook is NEVER
// reached, regardless of what c2EvaluatedRoleKey says.
func TestC4_RequireRole_SuccessNoDivergence(t *testing.T) {
	before := snapshotDivergence(t)
	r := withEvaluatedRole(http.MethodPut, "/api/idp/test-c4-success", RoleViewer, RoleAdmin)
	w := httptest.NewRecorder()
	if !requireRole(w, r, RoleAdmin) {
		t.Fatalf("requireRole returned false; admin session must satisfy admin bar")
	}
	if got := c2RoleDivergenceTotal.Load() - before; got != 0 {
		t.Errorf("counter delta = %d, want 0 (success path bypasses hook)", got)
	}
}

// TestC4_RequireRole_FailureWithLowerEvaluated — the canonical
// integration case at the requireRole boundary. Viewer session, C2
// evaluated viewer, handler demands admin. requireRole writes 403 AND
// recordRoleDivergence increments the counter.
//
// Critical: the 403 must come from requireRole's existing http.Error
// call, not from the C4 hook. The hook is observation-only.
func TestC4_RequireRole_FailureWithLowerEvaluated(t *testing.T) {
	before := snapshotDivergence(t)
	r := withEvaluatedRole(http.MethodPut, "/api/idp/test-c4-failure", RoleViewer, RoleViewer)
	w := httptest.NewRecorder()
	if requireRole(w, r, RoleAdmin) {
		t.Fatalf("requireRole returned true; viewer session must NOT satisfy admin bar")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if got := c2RoleDivergenceTotal.Load() - before; got != 1 {
		t.Errorf("counter delta = %d, want 1", got)
	}
	// Body comes from requireRole, not from C4. Confirms the response
	// is owned by the existing RBAC backstop.
	if !strings.Contains(w.Body.String(), "Forbidden") {
		t.Errorf("response body = %q, expected handler error text", w.Body.String())
	}
}

// TestC4_RequireRole_FailureWithoutEvaluated — viewer session, no
// c2EvaluatedRoleKey, handler demands admin. requireRole still 403's
// (defense-in-depth backstop preserved), but C4 does NOT record an
// event because there is no metadata signal to compare against.
func TestC4_RequireRole_FailureWithoutEvaluated(t *testing.T) {
	before := snapshotDivergence(t)
	r := withEvaluatedRole(http.MethodPut, "/api/idp/test-c4-no-key", "", RoleViewer)
	w := httptest.NewRecorder()
	if requireRole(w, r, RoleAdmin) {
		t.Fatalf("requireRole returned true; viewer must not pass admin")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if got := c2RoleDivergenceTotal.Load() - before; got != 0 {
		t.Errorf("counter delta = %d, want 0 (no evaluated role in context)", got)
	}
}

// ── Full-middleware integration over the real middleware ─────────────────

// withC4SyntheticDispatcher installs a TEMPORARY dynamic-dispatcher route —
// metadata MethodAny=viewer, handler asking requireRole(admin) on PUT and
// requireRole(viewer) on GET — the exact shape /api/idp/ had before FE-6A.0
// made its metadata per-method (the production divergence no longer exists,
// so the whole-chain proof rides a synthetic route registered on a fresh
// mux and appended to uiRoutes for the test's lifetime only).
func withC4SyntheticDispatcher(t *testing.T) http.Handler {
	t.Helper()
	prev := uiRoutes
	uiRoutes = append(append([]uiRouteMetadata(nil), prev...), uiRouteMetadata{
		Path: "/api/c4-synthetic/", Handler: "c4SyntheticDispatcher", Domain: "test", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer, Mutating: true, AuditExpected: false,
			Note: "C4 test fixture: dynamic dispatcher (GET=viewer / PUT=admin)"}},
	})
	resetC2Index()
	t.Cleanup(func() {
		uiRoutes = prev
		resetC2Index()
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/api/c4-synthetic/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			if !requireRole(w, r, RoleAdmin) {
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if !requireRole(w, r, RoleViewer) {
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return uiMetadataEnforcement(mux)
}

// TestC4_Middleware_ViewerOnDispatcherPut_RecordsDivergence is the
// end-to-end canonical case: viewer hits PUT on a dynamic dispatcher whose
// metadata declares MethodAny=viewer, so C2 admits the request; the
// handler-level requireRole(admin) then 403's. C4 records the divergence.
//
// This proves the WHOLE chain wires correctly: uiMetadataEnforcement
// injects c2EvaluatedRoleKey, the request flows to the handler, requireRole
// runs and fails, and recordRoleDivergence reads the context value the
// middleware put there.
func TestC4_Middleware_ViewerOnDispatcherPut_RecordsDivergence(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	before := snapshotDivergence(t)
	mw := withC4SyntheticDispatcher(t)

	r := c2Req(http.MethodPut, "/api/c4-synthetic/c4-integration-test", RoleViewer)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if got := c2RoleDivergenceTotal.Load() - before; got != 1 {
		t.Errorf("counter delta = %d, want 1", got)
	}
}

// TestC4_Middleware_AdminOnDispatcherPut_NoDivergence — same route with an
// admin session. The handler's requireRole(admin) succeeds, so no
// divergence is recorded.
func TestC4_Middleware_AdminOnDispatcherPut_NoDivergence(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	before := snapshotDivergence(t)
	mw := withC4SyntheticDispatcher(t)

	r := c2Req(http.MethodPut, "/api/c4-synthetic/c4-integration-admin", RoleAdmin)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if got := c2RoleDivergenceTotal.Load() - before; got != 0 {
		t.Errorf("counter delta = %d, want 0 (admin meets handler bar)", got)
	}
}

// TestC4_Middleware_ViewerOnDispatcherGet_NoDivergence — same route, GET
// instead of PUT. The handler's GET branch calls requireRole(viewer), which
// is the same role C2 evaluated. Parity case → no divergence.
func TestC4_Middleware_ViewerOnDispatcherGet_NoDivergence(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	before := snapshotDivergence(t)
	mw := withC4SyntheticDispatcher(t)

	r := c2Req(http.MethodGet, "/api/c4-synthetic/c4-integration-get", RoleViewer)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if got := c2RoleDivergenceTotal.Load() - before; got != 0 {
		t.Errorf("counter delta = %d, want 0 (parity: metadata=viewer, handler=viewer)", got)
	}
}

// TestC4_Middleware_IdPPutIsNowPerMethod pins the FE-6A.0 correction: the
// /api/idp/ metadata is per-method (PUT=admin), so C2 itself denies a
// viewer PUT at the middleware — the handler is never reached and NO
// divergence is recorded (metadata and handler agree).
func TestC4_Middleware_IdPPutIsNowPerMethod(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()
	before := snapshotDivergence(t)

	mux := d0WireMux(t)
	mw := uiMetadataEnforcement(mux)

	r := c2Req(http.MethodPut, "/api/idp/c4-integration-test", RoleViewer)
	r.Body = http.NoBody
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if got := c2RoleDivergenceTotal.Load() - before; got != 0 {
		t.Errorf("counter delta = %d, want 0 (C2 and the handler agree: PUT=admin)", got)
	}
}

// TestC4_NeverChangesResponse — proves C4 cannot block or allow on its
// own. We compare the response a divergence-triggering request would
// produce with and without the C4 hook recording having run. Since C4
// is observation-only, the response must be identical in both cases.
//
// The structural guarantee here is: requireRole's return value and
// status-code behavior depend only on the role/min-role check, not on
// whether the divergence hook fired. We exercise both paths and
// confirm the response is unchanged.
func TestC4_NeverChangesResponse(t *testing.T) {
	// Path A: divergence-triggering request (ev=viewer, handler=admin, session=viewer).
	rA := withEvaluatedRole(http.MethodPut, "/api/idp/c4-never-blocks-A", RoleViewer, RoleViewer)
	wA := httptest.NewRecorder()
	okA := requireRole(wA, rA, RoleAdmin)

	// Path B: no-divergence request (no evaluated role, otherwise identical).
	rB := withEvaluatedRole(http.MethodPut, "/api/idp/c4-never-blocks-B", "", RoleViewer)
	wB := httptest.NewRecorder()
	okB := requireRole(wB, rB, RoleAdmin)

	// Restore counter — divergence path bumped it.
	t.Cleanup(func() { c2RoleDivergenceTotal.Add(-1) })

	if okA != okB {
		t.Errorf("requireRole return values differ across C4 paths: A=%v B=%v", okA, okB)
	}
	if wA.Code != wB.Code {
		t.Errorf("status codes differ: divergence=%d no-divergence=%d", wA.Code, wB.Code)
	}
	if wA.Body.String() != wB.Body.String() {
		t.Errorf("response bodies differ: divergence=%q no-divergence=%q", wA.Body.String(), wB.Body.String())
	}
}
