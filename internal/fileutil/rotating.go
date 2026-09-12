package fileutil

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RotatingFile wraps a log file and rotates it when it exceeds maxBytes.
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

// NewRotatingFile opens path for append and returns a writer that rotates
// the file to path+".1" when it exceeds maxMB (<=0 falls back to 50 MB).
func NewRotatingFile(path string, maxMB int) (*RotatingFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	info, _ := f.Stat()
	var sz int64
	if info != nil {
		sz = info.Size()
	}
	maxBytes := int64(maxMB) * 1024 * 1024
	if maxBytes <= 0 {
		// Zero or negative (e.g. a stray -log-max-mb -1) would make the
		// Write-time rotation check size+len > maxBytes always true, rotating
		// on every write and thrashing the disk. Fall back to the default.
		maxBytes = 50 * 1024 * 1024 // 50 MB default
	}
	return &RotatingFile{path: path, maxBytes: maxBytes, file: f, size: sz}, nil
}

// Write appends p, rotating first when the size cap would be exceeded.
// Best-effort durability: the bytes are handed to the kernel, not
// synchronised — the contract every process-log / request-log caller wants.
// A caller that must KNOW the record reached stable storage uses WriteSync.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, _, err := r.writeLocked(p)
	return n, err
}

// WriteSync appends p and returns only once the COMPLETE record is on
// stable storage: the current file is fsync'd after the write, and when the
// write rotated, the archive file and the directory (which carries the
// rename and the new file's existence) are synchronised too. A short write
// or any synchronisation failure is returned — the bytes may sit in the page
// cache, but the caller must not treat them as durable. Every completed
// synchronisation is reported to the test observer (kind "file"/"dir").
func (r *RotatingFile) WriteSync(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, rotated, err := r.writeLocked(p)
	if err != nil {
		return n, err
	}
	if n < len(p) {
		return n, fmt.Errorf("rotating file %s: short write (%d of %d)", r.path, n, len(p))
	}
	if err := beforeSync("file", r.path); err != nil {
		return n, fmt.Errorf("rotating file %s: fsync: %w", r.path, err)
	}
	if err := r.file.Sync(); err != nil {
		return n, fmt.Errorf("rotating file %s: fsync: %w", r.path, err)
	}
	noteSync("file", r.path)
	if rotated {
		if err := SyncPath(r.path + ".1"); err != nil {
			return n, err
		}
		if err := SyncPath(filepath.Dir(r.path)); err != nil {
			return n, err
		}
	}
	return n, nil
}

// SyncPath fsyncs one file or directory and reports it to the test
// observer. It is the "synchronise the containing file" step a durability
// retry needs when the record is already readable but its synchronisation
// is uncertain.
func SyncPath(path string) error {
	if err := beforeSync("path", path); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	f, err := os.Open(path) // #nosec G304 -- caller-owned path; read-only handle
	if err != nil {
		return fmt.Errorf("sync %s: open: %w", path, err)
	}
	kind := "file"
	if st, serr := f.Stat(); serr == nil && st.IsDir() {
		kind = "dir"
	}
	if err := beforeSync(kind, path); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil {
		return fmt.Errorf("sync %s: %w", path, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("sync %s: close: %w", path, closeErr)
	}
	noteSync(kind, path)
	return nil
}

// writeLocked appends p under r.mu, rotating first when the size cap would
// be exceeded; rotated reports whether this call rotated.
func (r *RotatingFile) writeLocked(p []byte) (n int, rotated bool, err error) {
	if r.file != nil && r.size+int64(len(p)) > r.maxBytes {
		rotated = true
		r.file.Close()
		r.file = nil
		r.size = 0
		// Remove any previous rotated file before renaming the current one.
		// This prevents unbounded growth from accumulating stale .1 files.
		_ = os.Remove(r.path + ".1")
		_ = os.Rename(r.path, r.path+".1")
	}
	if r.file == nil {
		// Fresh open after rotation — or a reopen retry after a rotation
		// whose reopen failed (e.g. disk full). Retrying here, OUTSIDE the
		// rotation branch, is load-bearing: re-entering rotation on the next
		// write would os.Remove the just-rotated .1 archive, destroying the
		// only surviving copy of the log data.
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return 0, rotated, err
		}
		r.file = f
		r.size = 0
		if info, statErr := f.Stat(); statErr == nil {
			r.size = info.Size()
		}
	}

	n, err = r.file.Write(p)
	r.size += int64(n)
	return n, rotated, err
}

// Close closes the underlying file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}
