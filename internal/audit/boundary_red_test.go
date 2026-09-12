package audit

// boundary_red_test.go — FE-6A.0 correction round 6, RED row GR1 (external
// review of `e5d66a59`): a partial write, followed by a ZERO-byte failed
// repair attempt, followed by a successful retry must never acknowledge a
// record that is not an independently parseable keyed JSONL line. The
// best-effort path restores the boundary-repair flag when the attempted
// repair moved zero bytes; the durable path consumed it and lost it.

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// scriptedSink appends to the real audit file with one scripted outcome per
// attempt: "partial" writes a prefix and fails, "zero" writes nothing and
// fails, "ok" appends the whole record and synchronises.
type scriptedSink struct {
	path    string
	f       *os.File
	script  []string
	attempt int
}

func (s *scriptedSink) Write(p []byte) (int, error) { return s.WriteSync(p) }

func (s *scriptedSink) WriteSync(p []byte) (int, error) {
	step := "ok"
	if s.attempt < len(s.script) {
		step = s.script[s.attempt]
	}
	s.attempt++
	switch step {
	case "partial":
		n, _ := s.f.Write(p[:len(p)/3])
		return n, errors.New("write: input/output error (injected, partial)")
	case "zero":
		return 0, errors.New("write: input/output error (injected, zero bytes)")
	default:
		n, err := s.f.Write(p)
		if err != nil {
			return n, err
		}
		return n, s.f.Sync()
	}
}

// FindAndSync is the sink-owned find + synchronise primitive (round 6):
// scan this generation for a matching line and synchronise its file and
// directory before reporting it found.
func (s *scriptedSink) FindAndSync(match func(line []byte) bool) (bool, error) {
	f, err := os.Open(s.path) // #nosec G304 -- test temp path
	if err != nil {
		return false, err
	}
	defer f.Close() //nolint:errcheck // test
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<20)
	for sc.Scan() {
		if match(sc.Bytes()) {
			if err := s.f.Sync(); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, sc.Err()
}

func parseableKeyed(t *testing.T, path, id string) (parseable, lines int) {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // test
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		lines++
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.OperationID == id {
			parseable++
		}
	}
	return parseable, lines
}

func TestFE6A0G_GR1_ZeroByteFailedRepairNeverAcknowledgesAMalformedRecord(t *testing.T) {
	t.Cleanup(ResetForTest())
	t.Cleanup(ResetWriteErrorsForTest())
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := Init(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Close(); ClearPersistForTest() })
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	sink := &scriptedSink{path: path, f: f, script: []string{"partial", "zero", "ok"}}
	t.Cleanup(SetPersistForTest(sink))
	const id = "0a0a0a0a-0000-4000-8000-000000000061"
	e := opEntry(id)
	e.Detail = "a detail long enough that a one-third prefix is a truncated JSON fragment"
	// attempt 1: partial — leaves a fragment with no newline.
	if durable, err := AppendOperation(e); err == nil || durable {
		t.Fatalf("attempt 1 must fail: durable=%v err=%v", durable, err)
	}
	// attempt 2: the repair newline is attempted, ZERO bytes land, it fails.
	if durable, err := AppendOperation(e); err == nil || durable {
		t.Fatalf("attempt 2 must fail: durable=%v err=%v", durable, err)
	}
	// attempt 3: the retry succeeds — but only a record standing on its own
	// line is an audit; one glued onto the fragment is neither keyed nor
	// parseable and must not be acknowledged as durable.
	durable, err := AppendOperation(e)
	parseable, _ := parseableKeyed(t, path, id)
	if durable && err == nil && parseable != 1 {
		t.Fatalf("GR1: durable=true was acknowledged while the file holds %d independently parseable keyed entries — the boundary-repair state was lost by the zero-byte attempt and the record was glued onto the fragment", parseable)
	}
	if err != nil || !durable {
		t.Fatalf("attempt 3 with a working sink must succeed: durable=%v err=%v", durable, err)
	}
	if ok, herr := HasOperation("idp.create", id); herr != nil || !ok {
		t.Fatalf("the acknowledged record must be findable by its key: %v %v", ok, herr)
	}
}
