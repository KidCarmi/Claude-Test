package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

// PR-C15 RED matrix — the seventh Codex round on the Batch 2 PR head
// (6ec6e875), written against that tree BEFORE any correction.
//
//   R7-A  normalizeHost accepted hosts with EMPTY labels (`.example`,
//         `parent..example`): the IDNA mapping returns them unchanged, so
//         an invalid DNS name was persisted and published as an eligible
//         parent instead of the mutation receiving `invalid_entry`. The
//         single trailing FQDN dot stays supported.
//   R7-B  the read model did not expose whether a manual probe run is in
//         flight, so a client whose probe answer outran its deadline had
//         no appliance truth to resolve against and latched the completed
//         run as unproven.

func TestUpstreamR7_NormalizeRefusesEmptyLabels(t *testing.T) {
	rejected := []string{".example", "parent..example", "a..b.example", "example.com...", ".", "..", "..example"}
	for _, h := range rejected {
		if _, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: h, Port: 3128}); err == nil {
			t.Errorf("host %q: expected a refusal, got accepted", h)
		}
	}
	accepted := map[string]string{
		"example.com":           "example.com",
		"example.com..":         "example.com.",
		"parent-a.example.":     "parent-a.example",
		"127.1":                 "127.1",
		"[2001:db8::1]":         "[2001:db8::1]",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
	}
	for h, want := range accepted {
		sp, err := upstream.Normalize(upstream.Spec{Scheme: "http", Host: h, Port: 3128})
		if err != nil {
			t.Errorf("host %q: unexpected refusal: %v", h, err)
			continue
		}
		if sp.Host != want {
			t.Errorf("host %q: got %q, want %q", h, sp.Host, want)
		}
	}
}

func TestUpstreamR7_CreateRefusesEmptyLabel(t *testing.T) {
	upEnv(t)
	for _, h := range []string{".example", "parent..example"} {
		rec := upReq(t, "POST", "/api/upstream/entries", `{"scheme":"http","host":"`+h+`","port":3128,"revision":1}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("host %q: create answered %d, want 400: %s", h, rec.Code, rec.Body.String())
		}
		if got := upJSON(t, rec)["code"]; got != "invalid_entry" {
			t.Fatalf("host %q: code %v, want invalid_entry", h, got)
		}
	}
	view := upJSON(t, upReq(t, "GET", "/api/upstream", ""))
	if entries, _ := view["entries"].([]any); len(entries) != 0 {
		t.Fatalf("an empty-label host was persisted: %v", entries)
	}
}

func TestUpstreamR7_ReadModelExposesManualProbeInFlight(t *testing.T) {
	upEnv(t)
	inFlight := func() (bool, bool) {
		probe, _ := upJSON(t, upReq(t, "GET", "/api/upstream", ""))["probe"].(map[string]any)
		v, present := probe["manualInFlight"]
		b, _ := v.(bool)
		return b, present
	}
	if b, present := inFlight(); !present || b {
		t.Fatalf("idle: manualInFlight present=%v value=%v, want present=true value=false", present, b)
	}
	ok, code, _ := upstreamPool.BeginManualProbe(time.Now())
	if !ok {
		t.Fatalf("BeginManualProbe refused: %s", code)
	}
	if b, present := inFlight(); !present || !b {
		upstreamPool.EndManualProbe()
		t.Fatalf("admitted run: manualInFlight present=%v value=%v, want true", present, b)
	}
	upstreamPool.EndManualProbe()
	if b, present := inFlight(); !present || b {
		t.Fatalf("released run: manualInFlight present=%v value=%v, want false", present, b)
	}
}
