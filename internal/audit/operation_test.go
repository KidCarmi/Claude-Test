package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// operation_test.go — the exactly-once, durably-proven operation-keyed
// append (FE-6A.0 round 4).

func opEntry(id string) Entry {
	return Entry{TS: 1, Time: "t", Actor: "a", Action: "idp.create", Object: "p", Detail: "d", OperationID: id}
}

func countKeyed(t *testing.T, path, id string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(b), `"operationId":"`+id+`"`)
}

func TestAppendOperation_DurableExactlyOnceAcrossRetries(t *testing.T) {
	t.Cleanup(ResetForTest())
	t.Cleanup(ResetWriteErrorsForTest())
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := Init(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Close(); ClearPersistForTest() })
	const id = "0f0f0f0f-0000-4000-8000-000000000001"
	for i := 0; i < 3; i++ {
		durable, err := AppendOperation(opEntry(id))
		if err != nil || !durable {
			t.Fatalf("attempt %d: durable=%v err=%v", i, durable, err)
		}
	}
	if n := countKeyed(t, path, id); n != 1 {
		t.Fatalf("durable entries = %d, want 1", n)
	}
	n := 0
	for _, e := range Get() {
		if e.OperationID == id {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("ring entries = %d, want 1", n)
	}
	if ok, err := HasOperation("idp.create", id); err != nil || !ok {
		t.Fatalf("HasOperation = %v %v", ok, err)
	}
	if ok, _ := HasOperation("idp.delete", id); ok {
		t.Fatal("the key is (action, operationId): a different action must not match")
	}
}

func TestAppendOperation_FindsTheEntryInTheRotatedArchive(t *testing.T) {
	t.Cleanup(ResetForTest())
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	const id = "0f0f0f0f-0000-4000-8000-000000000002"
	if err := os.WriteFile(path+".1", []byte(`{"ts":1,"action":"idp.create","object":"p","operationId":"`+id+`"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Close(); ClearPersistForTest() })
	durable, err := AppendOperation(opEntry(id))
	if err != nil || !durable {
		t.Fatalf("durable=%v err=%v", durable, err)
	}
	if n := countKeyed(t, path, id); n != 0 {
		t.Fatalf("an entry already durable in the archive was re-appended (%d)", n)
	}
}

// failSyncWriter is a SYNCHRONISING sink whose append fails.
type failSyncWriter struct{ err error }

func (f failSyncWriter) Write([]byte) (int, error)                 { return 0, f.err }
func (f failSyncWriter) WriteSync([]byte) (int, error)             { return 0, f.err }
func (failSyncWriter) FindAndSync(func([]byte) bool) (bool, error) { return false, nil }

func TestAppendOperation_NonSyncableSinkIsRefusedNotTrusted(t *testing.T) {
	t.Cleanup(ResetForTest())
	t.Cleanup(ResetWriteErrorsForTest())
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := Init(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Close(); ClearPersistForTest() })
	t.Cleanup(SetPersistForTest(&countingWriter{})) // io.Writer only: cannot fsync
	const id = "0f0f0f0f-0000-4000-8000-000000000006"
	durable, err := AppendOperation(opEntry(id))
	if !errors.Is(err, ErrSinkNotSyncable) || durable {
		t.Fatalf("a sink that cannot synchronise must never be acknowledged: durable=%v err=%v", durable, err)
	}
	if n := countKeyed(t, path, id); n != 0 || len(Get()) != 0 {
		t.Fatalf("nothing may be appended through an unsyncable sink (file=%d ring=%d)", n, len(Get()))
	}
}

func TestAppendOperation_WriteFailureAddsNothingAnywhere(t *testing.T) {
	t.Cleanup(ResetForTest())
	t.Cleanup(ResetWriteErrorsForTest())
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := Init(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Close(); ClearPersistForTest() })
	restore := SetPersistForTest(failSyncWriter{err: errors.New("enospc")})
	const id = "0f0f0f0f-0000-4000-8000-000000000003"
	durable, err := AppendOperation(opEntry(id))
	if err == nil || durable {
		t.Fatalf("a failed durable write must be reported: durable=%v err=%v", durable, err)
	}
	for _, e := range Get() {
		if e.OperationID == id {
			t.Fatal("a failed durable append must not reach the ring (the caller retries the whole append)")
		}
	}
	if WriteErrors() != 1 {
		t.Fatalf("the loss must be charged; WriteErrors = %d", WriteErrors())
	}
	restore()
	if durable, err := AppendOperation(opEntry(id)); err != nil || !durable {
		t.Fatalf("retry after recovery: durable=%v err=%v", durable, err)
	}
	if n := countKeyed(t, path, id); n != 1 {
		t.Fatalf("durable entries after recovery = %d, want 1", n)
	}
}

func TestAppendOperation_MemorySinkHoldsTheEntryOnce(t *testing.T) {
	t.Cleanup(ResetForTest())
	const id = "0f0f0f0f-0000-4000-8000-000000000004"
	for i := 0; i < 2; i++ {
		durable, err := AppendOperation(opEntry(id))
		if err != nil || durable {
			t.Fatalf("memory sink: durable=%v err=%v", durable, err)
		}
	}
	n := 0
	for _, e := range Get() {
		if e.OperationID == id {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("ring entries = %d, want 1", n)
	}
	if ok, err := HasOperation("idp.create", id); err != nil || !ok {
		t.Fatalf("HasOperation on the memory sink = %v %v", ok, err)
	}
}

func TestAppendOperation_RefusesAnEntryWithoutAKey(t *testing.T) {
	t.Cleanup(ResetForTest())
	if _, err := AppendOperation(Entry{Action: "idp.create"}); !errors.Is(err, ErrOperationIDRequired) {
		t.Fatalf("err = %v", err)
	}
	if len(Get()) != 0 {
		t.Fatal("nothing may be appended without a key")
	}
}

func TestHasOperation_UnreadableRecordIsAnErrorNotAbsent(t *testing.T) {
	t.Cleanup(ResetForTest())
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := Init(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Close(); ClearPersistForTest() })
	// The archive becomes a directory: unreadable, not absent.
	if err := os.MkdirAll(path+".1", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := HasOperation("idp.create", "0f0f0f0f-0000-4000-8000-000000000005"); err == nil {
		t.Fatal("an unreadable durable record must be reported, never read as absent")
	}
	if durable, err := AppendOperation(opEntry("0f0f0f0f-0000-4000-8000-000000000005")); err == nil || durable {
		t.Fatalf("an unknowable record must not become an append: durable=%v err=%v", durable, err)
	}
}

// ─── round 6 ────────────────────────────────────────────────────────────────

// TestPersistEntryDurable_ZeroByteRepairIsHandedBack pins GR1 at the unit:
// a consumed repair whose write moved zero bytes is restored, so the next
// record is still prefixed with the boundary newline.
func TestPersistEntryDurable_ZeroByteRepairIsHandedBack(t *testing.T) {
	t.Cleanup(ResetForTest())
	t.Cleanup(ResetWriteErrorsForTest())
	needsBoundaryRepair.Store(true)
	var rec zeroByteWriter
	if err := persistEntryDurable(&rec, "p", opEntry("0a0a0a0a-0000-4000-8000-000000000071")); err == nil {
		t.Fatal("a zero-byte write must fail")
	}
	if !needsBoundaryRepair.Load() {
		t.Fatal("the repair consumed by a zero-byte attempt must be handed back")
	}
	rec.ok = true
	if err := persistEntryDurable(&rec, "p", opEntry("0a0a0a0a-0000-4000-8000-000000000071")); err != nil {
		t.Fatal(err)
	}
	if len(rec.buf) == 0 || rec.buf[0] != '\n' {
		t.Fatalf("the retry must carry the boundary newline; got %q", rec.buf[:1])
	}
	if needsBoundaryRepair.Load() {
		t.Fatal("a complete write clears the repair")
	}
}

type zeroByteWriter struct {
	ok  bool
	buf []byte
}

func (r *zeroByteWriter) Write(p []byte) (int, error) { return r.WriteSync(p) }
func (r *zeroByteWriter) WriteSync(p []byte) (int, error) {
	if !r.ok {
		return 0, errors.New("injected zero-byte failure")
	}
	r.buf = append(r.buf, p...)
	return len(p), nil
}
func (r *zeroByteWriter) FindAndSync(func([]byte) bool) (bool, error) { return false, nil }
