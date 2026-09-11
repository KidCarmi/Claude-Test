package main

// Nightly QA edge-case pass: readTarball had no bound on a tar entry's
// declared size before calling io.ReadAll(tr) on its body. A highly
// compressible payload (e.g. all-zero bytes) lets a tiny .tar.gz file declare
// an enormous decompressed size in its tar header — a classic decompression
// bomb — and readTarball is reached by `culvert --restore` (dry-run, no
// --confirm needed) on any tarball path an operator points it at, so a
// corrupted or hostile backup file drives an unbounded in-memory allocation.
//
// Every other tar/gzip consumer in this codebase already bounds this:
// release_catalog_bundle.go checks hdr.Size against catalogMaxReadBytes per
// entry, and support_validate.go wraps the gzip reader in an
// io.LimitReader(maxValidateDecompressed) before untarring. restore.go was
// the one place carrying no such guard despite documenting (runBackupWith)
// that a real backup is "well under 100MB".

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// zeroReader yields an endless stream of zero bytes without allocating a
// buffer the size of what's requested — lets the test build a many-hundred-
// MiB decompressed payload while writing (and, pre-fix, reading back) only a
// few KB of actual gzip-compressed bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// writeDecompressionBombTarball builds a minimal tar.gz whose single entry's
// tar header declares declaredSize bytes of (all-zero, so highly compressible)
// content under the data/ namespace readTarball requires.
func writeDecompressionBombTarball(t *testing.T, destPath string, declaredSize int64) {
	t.Helper()
	out, err := os.Create(destPath) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("create dest: %v", err)
	}
	defer func() { _ = out.Close() }()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	hdr := &tar.Header{
		Name:     "data/blocklist.txt",
		Mode:     0o600,
		Size:     declaredSize,
		Typeflag: tar.TypeReg,
		ModTime:  time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := io.CopyN(tw, zeroReader{}, declaredSize); err != nil {
		t.Fatalf("write bomb body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
}

// TestReadTarball_RejectsOversizedEntry proves readTarball refuses a tarball
// entry whose declared size exceeds a sane bound, instead of allocating it in
// full via io.ReadAll. Uses 300 MiB (comfortably above any real backup per
// runBackupWith's own "well under 100MB" comment, and above the 256 MiB bound
// the fix introduces) so the assertion is unambiguous either way.
func TestReadTarball_RejectsOversizedEntry(t *testing.T) {
	const bombSize = 300 << 20 // 300 MiB declared/decompressed
	path := filepath.Join(t.TempDir(), "bomb.tar.gz")
	writeDecompressionBombTarball(t, path, bombSize)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat bomb tarball: %v", err)
	}
	if info.Size() > 1<<20 {
		t.Fatalf("test setup: bomb tarball is %d bytes on disk, expected it to compress to well under 1 MiB", info.Size())
	}

	if _, _, err := readTarball(path, ""); err == nil {
		t.Fatalf("readTarball accepted a %d-byte declared entry from a %d-byte file — decompression bomb not bounded", bombSize, info.Size())
	}
}

// TestReadTarball_AcceptsEntryUnderTheBound is the control: an entry sized
// comfortably under the new bound must still read normally, so the fix
// narrows nothing about legitimate (if unusually large) backups.
func TestReadTarball_AcceptsEntryUnderTheBound(t *testing.T) {
	const size = 1 << 20 // 1 MiB — far under any reasonable bound
	path := filepath.Join(t.TempDir(), "normal.tar.gz")
	writeDecompressionBombTarball(t, path, size)

	files, _, err := readTarball(path, "")
	if err != nil {
		t.Fatalf("readTarball rejected a normal %d-byte entry: %v", size, err)
	}
	if len(files["data/blocklist.txt"]) != size {
		t.Fatalf("got %d bytes back, want %d", len(files["data/blocklist.txt"]), size)
	}
}

// writeSplitDecompressionBombTarball builds a tar.gz with entryCount distinct
// data/* entries, each declaring entrySize bytes — every entry individually
// under maxRestoreEntryBytes, but summing well past it. Proves the per-entry
// bound alone (Codex review, PR #1344: a hostile archive can split its
// payload across many uniquely named entries each at or under the per-entry
// cap) is not sufficient.
func writeSplitDecompressionBombTarball(t *testing.T, destPath string, entryCount int, entrySize int64) {
	t.Helper()
	out, err := os.Create(destPath) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("create dest: %v", err)
	}
	defer func() { _ = out.Close() }()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	for i := 0; i < entryCount; i++ {
		hdr := &tar.Header{
			Name:     fmt.Sprintf("data/part-%d.txt", i),
			Mode:     0o600,
			Size:     entrySize,
			Typeflag: tar.TypeReg,
			ModTime:  time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %d: %v", i, err)
		}
		if _, err := io.CopyN(tw, zeroReader{}, entrySize); err != nil {
			t.Fatalf("write bomb body %d: %v", i, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
}

// TestReadTarball_RejectsOversizedAggregate proves readTarball also bounds
// the SUM of declared entry sizes, not just each entry individually. Each of
// 4 entries here declares 200 MiB — comfortably under the 256 MiB per-entry
// bound on its own — but the 800 MiB total exceeds the 512 MiB aggregate
// bound, which a per-entry-only check would never catch.
func TestReadTarball_RejectsOversizedAggregate(t *testing.T) {
	const entrySize = 200 << 20 // 200 MiB per entry, under the per-entry cap
	const entryCount = 4        // 800 MiB total, over the aggregate cap
	path := filepath.Join(t.TempDir(), "split-bomb.tar.gz")
	writeSplitDecompressionBombTarball(t, path, entryCount, entrySize)

	if _, _, err := readTarball(path, ""); err == nil {
		t.Fatalf("readTarball accepted %d entries of %d bytes each (all individually under the per-entry bound) — aggregate decompression bomb not bounded", entryCount, entrySize)
	}
}
