package main

// upstream_mutation_content_type_red_test.go — 2F-F contract defect found by
// the real-binary Upstream React journeys (frontend/e2e/upstream-2ff.spec.ts,
// J2/J3/J5) and reproduced here deterministically on the frozen 2F-C/2F-D
// backend.
//
// The OpenAPI contract declares every 2xx answer of the v2 mutation
// endpoints (create 201, update 200, delete 200, credential replace/clear
// 200) as `application/json`, and the v2 client's boundary refuses any other
// media type by construction (FRONTEND-SECURITY-CONTRACT §7). The handler
// (`upstreamMutate`) called `w.WriteHeader(status)` BEFORE `jsonWrite` set
// the Content-Type, so the header snapshot went out without it and the
// server's sniffer labelled the JSON body `text/plain`. The legacy panel
// never checked the media type, which is why 2F-C/2F-D did not observe it.
//
// Reproduced against the response the WIRE carries (`rec.Result()`, whose
// header map is the WriteHeader-time snapshot — `rec.Header()` would show
// the late Set and mask the defect). GET, the manual probe and every
// refusal already carried the type.

import (
	"fmt"
	"mime"
	"net/http/httptest"
	"testing"
)

func upMutationContentType(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	ct := rec.Result().Header.Get("Content-Type") //nolint:bodyclose // recorder result, no network body
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ct
	}
	return mt
}

func TestUpstreamMutationAnswers_AreApplicationJSONOnTheWire(t *testing.T) {
	upEnv(t)

	// create (201)
	rec := upReq(t, "POST", "/api/upstream/entries",
		fmt.Sprintf(`{"scheme":"http","host":"ct.test","port":3128,"username":"svc","revision":%d}`, upDocRevision(t)))
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if mt := upMutationContentType(t, rec); mt != "application/json" {
		t.Errorf("create 201 must be application/json on the wire, got %q", mt)
	}
	entry, _ := upJSON(t, rec)["entry"].(map[string]any)
	id, _ := entry["id"].(string)
	if id == "" {
		t.Fatalf("create answer carries no entry: %s", rec.Body.String())
	}
	rev := func() int64 {
		r, _ := upEntry(t, id)["revision"].(float64)
		return int64(r)
	}

	// update (200)
	rec = upReq(t, "PUT", "/api/upstream/entries/"+id,
		fmt.Sprintf(`{"scheme":"http","host":"ct.test","port":3129,"username":"svc","revision":%d}`, rev()))
	if rec.Code != 200 {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if mt := upMutationContentType(t, rec); mt != "application/json" {
		t.Errorf("update 200 must be application/json on the wire, got %q", mt)
	}

	// credential replace (200, T2)
	rec = upReq(t, "POST", "/api/upstream/entries/"+id+"/credential",
		fmt.Sprintf(`{"action":"replace","password":"ct-pw","revision":%d}`, rev()))
	if rec.Code != 200 {
		t.Fatalf("replace: %d %s", rec.Code, rec.Body.String())
	}
	if mt := upMutationContentType(t, rec); mt != "application/json" {
		t.Errorf("credential replace 200 must be application/json on the wire, got %q", mt)
	}

	// credential clear (200, T3)
	rec = upReq(t, "POST", "/api/upstream/entries/"+id+"/credential",
		fmt.Sprintf(`{"action":"clear","confirm":%q,"revision":%d}`, id, rev()))
	if rec.Code != 200 {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	if mt := upMutationContentType(t, rec); mt != "application/json" {
		t.Errorf("credential clear 200 must be application/json on the wire, got %q", mt)
	}

	// delete (200)
	rec = upReq(t, "DELETE", fmt.Sprintf("/api/upstream/entries/%s?revision=%d", id, rev()), "")
	if rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if mt := upMutationContentType(t, rec); mt != "application/json" {
		t.Errorf("delete 200 must be application/json on the wire, got %q", mt)
	}

	// CONTROL: the refusal path already carried the type (a stale delete).
	rec = upReq(t, "DELETE", fmt.Sprintf("/api/upstream/entries/%s?revision=%d", id, 1), "")
	if rec.Code != 404 {
		t.Fatalf("control: expected 404 vanished, got %d %s", rec.Code, rec.Body.String())
	}
	if mt := upMutationContentType(t, rec); mt != "application/json" {
		t.Errorf("control: the refusal path must stay application/json, got %q", mt)
	}
}
