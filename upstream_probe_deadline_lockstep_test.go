package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

// PR-C9 K3: the admin frontend sizes a manual probe's request deadline from
// the appliance's per-entry probe bound (the run is sequential). The two
// constants live in different languages; this pins them to each other so a
// change on either side fails the build instead of silently reopening the
// aborted-run defect.
func TestUpstreamProbeDeadline_FrontendLockstep(t *testing.T) {
	src, err := os.ReadFile("frontend/src/api/upstream.ts")
	if err != nil {
		t.Fatalf("read frontend client: %v", err)
	}
	m := regexp.MustCompile(`export const PROBE_PER_ENTRY_MS = ([0-9_]+);`).FindSubmatch(src)
	if m == nil {
		t.Fatal("frontend/src/api/upstream.ts no longer declares PROBE_PER_ENTRY_MS")
	}
	ms, err := strconv.Atoi(strings.ReplaceAll(string(m[1]), "_", ""))
	if err != nil {
		t.Fatalf("PROBE_PER_ENTRY_MS is not an integer: %v", err)
	}
	if got, want := time.Duration(ms)*time.Millisecond, upstream.ProbeTimeout; got != want {
		t.Fatalf("frontend PROBE_PER_ENTRY_MS = %s, engine ProbeTimeout = %s — the manual-probe deadline no longer covers a sequential run", got, want)
	}
}
