package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// rotating_sync_test.go — WriteSync / SyncPath (FE-6A.0 round 5): success
// means the complete record is synchronised, and a rotation synchronises
// the archive and the directory before the acknowledgement.

func TestWriteSync_SynchronisesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	rf, err := NewRotatingFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test
	var seen []string
	t.Cleanup(SetSyncObserverForTest(func(kind, p string) { seen = append(seen, kind+":"+p) }))
	if n, err := rf.WriteSync([]byte("one\n")); err != nil || n != 4 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(seen) != 1 || seen[0] != "file:"+path {
		t.Fatalf("expected exactly one file sync of the current file, got %v", seen)
	}
	if b, _ := os.ReadFile(path); string(b) != "one\n" {
		t.Fatalf("content = %q", b)
	}
}

func TestWriteSync_RotationSynchronisesArchiveAndDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	rf, err := NewRotatingFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test
	line := []byte(strings.Repeat("x", 1023) + "\n")
	for i := 0; i < 1023; i++ { // 1023 KiB: the next 1 KiB line crosses 1 MiB
		if _, err := rf.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	t.Cleanup(SetSyncObserverForTest(func(kind, p string) { seen = append(seen, kind+":"+p) }))
	if _, err := rf.WriteSync(line); err != nil {
		t.Fatal(err)
	}
	// The write above fits exactly; the NEXT one rotates.
	seen = nil
	if _, err := rf.WriteSync([]byte("keyed\n")); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"file:" + path: false, "file:" + path + ".1": false, "dir:" + dir: false}
	for _, s := range seen {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for k, ok := range want {
		if !ok {
			t.Fatalf("rotation must synchronise %s before acknowledging; saw %v", k, seen)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != "keyed\n" {
		t.Fatalf("new current file = %q", b)
	}
	if st, err := os.Stat(path + ".1"); err != nil || st.Size() != 1<<20 {
		t.Fatalf("archive stat = %v %v", st, err)
	}
}

func TestSyncPath_ReportsFileAndDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var seen []string
	t.Cleanup(SetSyncObserverForTest(func(kind, p string) { seen = append(seen, kind+":"+p) }))
	if err := SyncPath(file); err != nil {
		t.Fatal(err)
	}
	if err := SyncPath(dir); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != "file:"+file || seen[1] != "dir:"+dir {
		t.Fatalf("seen = %v", seen)
	}
	if err := SyncPath(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing path must not report as synchronised")
	}
}

// ─── FindAndSync (round 6) ──────────────────────────────────────────────────

func TestFindAndSync_SynchronisesHolderAndDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	rf, err := NewRotatingFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test
	if _, err := rf.Write([]byte("a\nkeyed\nb\n")); err != nil {
		t.Fatal(err)
	}
	var seen []string
	t.Cleanup(SetSyncObserverForTest(func(kind, p string) { seen = append(seen, kind+":"+p) }))
	found, err := rf.FindAndSync(func(l []byte) bool { return string(l) == "keyed" })
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if len(seen) != 2 || seen[0] != "file:"+path || seen[1] != "dir:"+dir {
		t.Fatalf("holder then directory must be synchronised; saw %v", seen)
	}
	if found, err := rf.FindAndSync(func([]byte) bool { return false }); err != nil || found {
		t.Fatalf("absent: found=%v err=%v", found, err)
	}
}

func TestFindAndSync_FindsTheArchiveGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	if err := os.WriteFile(path+".1", []byte("old\nkeyed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rf, err := NewRotatingFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test
	var seen []string
	t.Cleanup(SetSyncObserverForTest(func(kind, p string) { seen = append(seen, kind+":"+p) }))
	found, err := rf.FindAndSync(func(l []byte) bool { return string(l) == "keyed" })
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if len(seen) != 2 || seen[0] != "file:"+path+".1" || seen[1] != "dir:"+dir {
		t.Fatalf("the ARCHIVE holder then the directory; saw %v", seen)
	}
}

func TestFindAndSync_DirectoryFaultIsNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	rf, err := NewRotatingFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test
	if _, err := rf.Write([]byte("keyed\n")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(SetSyncHookForTest(func(kind, _ string) error {
		if kind == "dir" {
			return errors.New("fsync(dir): injected")
		}
		return nil
	}))
	found, err := rf.FindAndSync(func(l []byte) bool { return string(l) == "keyed" })
	if err == nil || found {
		t.Fatalf("a directory that cannot be synchronised must not prove the record: found=%v err=%v", found, err)
	}
}

func TestFindAndSync_HoldsTheGenerationAgainstAConcurrentRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	rf, err := NewRotatingFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test
	if _, err := rf.Write([]byte("keyed\n")); err != nil {
		t.Fatal(err)
	}
	big := []byte(strings.Repeat("z", 1<<20) + "\n") // any Write of this rotates
	entered, release := make(chan struct{}), make(chan struct{})
	writeDone := make(chan struct{})
	var order []string
	var mu sync.Mutex
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }
	t.Cleanup(SetSyncObserverForTest(func(kind, p string) { note(kind + ":" + filepath.Base(p)) }))
	go func() {
		_, _ = rf.FindAndSync(func(l []byte) bool {
			if string(l) == "keyed" {
				close(entered) // found — now park while a rotation is attempted
				<-release
				return true
			}
			return false
		})
		note("find-returned")
	}()
	<-entered
	go func() {
		_, _ = rf.Write(big) // must block until FindAndSync releases the generation
		note("rotated")
		close(writeDone)
	}()
	close(release)
	<-writeDone
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	want := []string{"file:log", "dir:" + filepath.Base(dir), "find-returned", "rotated"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the rotation must wait for the found generation to be proven: got %v want %v", got, want)
	}
	if b, _ := os.ReadFile(path + ".1"); string(b) != "keyed\n" {
		t.Fatalf("archive = %q", b)
	}
}
