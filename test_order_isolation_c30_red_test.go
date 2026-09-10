package main

// test_order_isolation_c30_red_test.go — PR-C30 RED proofs for the two
// failures the seeded determinism run (`-shuffle=1788866999688368609
// -count=2`) produced on the Batch 2 PR head 7fd9c852, written against
// that tree BEFORE any correction.
//
//   C30-A  TestDCFin5_LegacyImportReplaceAndMergeAreDurable read `[]` back
//          from its own settings file after a restart that had just been
//          proven to carry both imported identities on disk. The restart
//          helper (dcFinBoot) resets the live rewriter to "fresh process"
//          and then loads the file; a best-effort admin-settings save still
//          in flight (adminSettingsSave spawns one on every admin mutation,
//          the import's own included) that lands INSIDE that window
//          serializes the now-empty live list as saved-authoritative, and
//          the load reads an empty slice. The PR-C7b class: the helper must
//          drain pending saves BEFORE it simulates the restart.
//   C30-B  TestMatchSchedule_InvalidTimezone asserts a "00:00"–"23:59"
//          window against the WALL CLOCK; the matcher is half-open, so the
//          assertion is false for the last minute of every day (the run
//          crossed 23:59 UTC). Main's own commit 08545fa5 corrected the two
//          sibling tests to "24:00" and left this one behind. The wall pins
//          the class: no test may assert a full-day window that ends at
//          "23:59" against matchSchedule.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// c30ImportTwoRules performs the DCFin5 imports and returns the two
// identities the file was proven to carry.
func c30ImportTwoRules(t *testing.T, settingsPath string) (uuidA, uuidB string) {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode=replace", map[string]any{
		"version":      1,
		"rewriteRules": []map[string]any{{"host": "c30a.example", "req_set": map[string]string{"X-A": "1"}}},
	}))
	if w.Code != 200 {
		t.Fatalf("replace import: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import", map[string]any{
		"version":      1,
		"rewriteRules": []map[string]any{{"host": "c30b.example", "req_add": map[string]string{"X-B": "1"}}},
	}))
	if w.Code != 200 {
		t.Fatalf("merge import: %d %s", w.Code, w.Body.String())
	}
	live := rewriter.List()
	if len(live) != 2 || live[0].StableID == "" || live[1].StableID == "" {
		t.Fatalf("imports must publish two identities, got %+v", live)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !strings.Contains(string(data), live[0].StableID) || !strings.Contains(string(data), live[1].StableID) {
		t.Fatalf("disk must carry both identities before the restart")
	}
	return live[0].StableID, live[1].StableID
}

// C30-A (RED): with a best-effort save held open, the restart helper must
// not return until it is released — a helper that drains cannot.
func TestOrder_DCFinBootDrainsPendingSaves(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	csrTaxIsolate(t)
	snapshotConfigVersionsDir(t)
	if got := dcFinBoot(t, settingsPath, nil); len(got) != 0 {
		t.Fatalf("clean boot: %+v", got)
	}
	uuidA, uuidB := c30ImportTwoRules(t, settingsPath)

	release := make(chan struct{})
	adminSettingsSaveWG.Add(1)
	go func() {
		defer adminSettingsSaveWG.Done()
		<-release
	}()
	released := false
	unblock := func() {
		if !released {
			released = true
			close(release)
		}
	}
	t.Cleanup(unblock)

	done := make(chan []RewriteRule, 1)
	go func() {
		done <- dcFinBoot(t, settingsPath, nil)
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	select {
	case got := <-done:
		t.Fatalf("the restart helper returned while a best-effort save was still pending; that save can land inside the restart window (got %+v)", got)
	default:
	}
	unblock()
	got := <-done
	if len(got) != 2 || got[0].StableID != uuidA || got[1].StableID != uuidB {
		t.Fatalf("imported identities must survive the restart verbatim (%s, %s), got %+v", uuidA, uuidB, got)
	}
}

// C30-A (mechanism control, green at both trees): a save that lands INSIDE
// the restart window — after the fresh-process reset, before the load —
// serializes the empty live list as saved-authoritative and the load reads
// `[]`. This is what the drain prevents; it is not itself a defect (a save
// records the live set by design).
func TestOrder_SaveInsideRestartWindowErasesImportedIdentities(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	csrTaxIsolate(t)
	snapshotConfigVersionsDir(t)
	if got := dcFinBoot(t, settingsPath, nil); len(got) != 0 {
		t.Fatalf("clean boot: %+v", got)
	}
	c30ImportTwoRules(t, settingsPath)
	adminSettingsSaveWG.Wait()

	rewriter.SetRules(nil) // the helper's fresh-process reset
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("the stale save: %v", err)
	}
	loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{DefaultAction: "allow"}, 0)
	LoadAdminSettings(settingsPath)
	if got := rewriter.List(); len(got) != 0 {
		t.Fatalf("a save inside the window records the empty live set; the load must read it back empty, got %+v", got)
	}
}

// C30-B (RED wall): no root test may build a "00:00"–"23:59" schedule. The
// matcher is half-open ("24:00" closes a full day — see
// TestScheduleTimeMatch_FullDayWindowCoversEveryMinute), so a full-day claim
// asserted against the wall clock — directly through matchSchedule, or
// through Evaluate's per-scan clock — is false for one minute in every 1440
// and presents as a flake rather than a defect. The fixed-clock boundary
// pins pass the bounds as arguments, not as schedule fields, and stay
// outside the wall.
func TestScheduleTests_NoWallClockFullDayWindowEndsAt2359(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var offenders []string
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, d := range af.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			if c30BuildsFullDayWindowEndingAt2359(fn.Body) {
				offenders = append(offenders, f+":"+fn.Name.Name)
			}
		}
	}
	if len(offenders) != 0 {
		t.Fatalf("full-day schedules built as \"00:00\"–\"23:59\" (false for the last minute of every day against the wall clock; close a full day with \"24:00\"): %v", offenders)
	}
}

// c30BuildsFullDayWindowEndingAt2359 reports whether a test body carries
// both the `TimeStart: "00:00"` and the `TimeEnd: "23:59"` schedule fields.
func c30BuildsFullDayWindowEndingAt2359(body *ast.BlockStmt) bool {
	startsAt0000, endsAt2359 := false, false
	ast.Inspect(body, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		k, ok := kv.Key.(*ast.Ident)
		if !ok {
			return true
		}
		v, ok := kv.Value.(*ast.BasicLit)
		if !ok {
			return true
		}
		switch {
		case k.Name == "TimeStart" && v.Value == `"00:00"`:
			startsAt0000 = true
		case k.Name == "TimeEnd" && v.Value == `"23:59"`:
			endsAt2359 = true
		}
		return true
	})
	return startsAt0000 && endsAt2359
}
