package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTestFileReadsAreCWDIndependent is an ANTI-REGRESSION WALL. Tests must read the
// SPA and package source files via ABSOLUTE paths anchored to the package source dir
// (staticIndexHTMLPath() / pkgSourceDir()), NEVER via a CWD-relative os.ReadFile /
// os.ReadDir("."). A relative read picks up the wrong file when a concurrent test
// changes the working directory (os.Chdir), which the determinism and -race gates
// catch as a flaky "static/index.html missing …" or a spurious route-count/parity
// divergence. That whole class cost real debugging time to track down; this wall
// keeps it from creeping back.
//
// The check scans every *_test.go file, ignoring comment lines so doc comments that
// mention the patterns do not trip it, and skips this wall file (which names them).
func TestTestFileReadsAreCWDIndependent(t *testing.T) {
	// Forbidden CWD-relative patterns:
	//   1. the SPA read                       → staticIndexHTMLPath()
	//   2. a bare package .go source read     → filepath.Join(pkgSourceDir(), "x.go")
	//   3. enumerating the CWD                → os.ReadDir(pkgSourceDir())
	bareGoRead := regexp.MustCompile(`os\.(?:ReadFile|Open|Stat)\("[^"/]+\.go"\)`)
	forbiddenLiterals := []string{`ReadFile("static/index.html")`, `os.ReadDir(".")`}

	dir := pkgSourceDir() // anchor the scan itself, or it falls to the race it guards
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") || name == "static_read_wall_test.go" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx] // drop the trailing comment
			}
			var hit string
			for _, f := range forbiddenLiterals {
				if strings.Contains(code, f) {
					hit = f
				}
			}
			if hit == "" {
				if m := bareGoRead.FindString(code); m != "" {
					hit = m
				}
			}
			if hit != "" {
				t.Errorf("%s:%d: %q is a CWD-relative read — anchor it to pkgSourceDir()/staticIndexHTMLPath() so a concurrent os.Chdir cannot flake it", name, i+1, hit)
			}
		}
	}
}

// TestTestsDoNotChdirUnsafely is the other half of the wall above. That one
// forbids the READS that a stray working directory corrupts; this one forbids
// the stray working directory itself.
//
// Every hand-rolled `os.Chdir` in a test has the same three failure points, and
// the shipped versions discarded all of them:
//
//	origDir, _ := os.Getwd()                  // may fail
//	_ = os.Chdir(dir)                         // may fail
//	defer func() { _ = os.Chdir(origDir) }()  // may fail
//
// A failed Getwd leaves origDir empty, so the restore silently no-ops and the
// process stays inside a t.TempDir() that cleanup then deletes. From that point
// every CWD-relative read in the package fails with ENOENT — and the next chdir
// test's Getwd fails too, so the breakage LATCHES for the rest of the run. It
// shows up as a scatter of unrelated tests failing at 0.00s under -shuffle,
// i.e. as a flaky determinism gate whose reported victims have nothing to do
// with the cause. Tracking that down cost a full day.
//
// testing.T.Chdir (Go 1.24+) restores via Cleanup and FAILS the test when it
// cannot, so the latch is unreachable. Use it.
func TestTestsDoNotChdirUnsafely(t *testing.T) {
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") || name == "static_read_wall_test.go" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx]
			}
			if strings.Contains(code, "os.Chdir(") {
				t.Errorf("%s:%d: raw os.Chdir in a test — use t.Chdir(dir), which restores via Cleanup and fails loudly instead of latching a broken working directory onto every later test", name, i+1)
			}
		}
	}
}
