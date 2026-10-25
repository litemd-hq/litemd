package files

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	// ErrTooLarge is returned when the stream exceeds the allowed maximum.
	ErrTooLarge = errors.New("payload exceeds allowed size")

	// tempPrefix marks in-flight atomic writes; the janitor cleans stale ones.
	tempPrefix = ".litemd-"
)

// WriteResult reports what was durably written.
type WriteResult struct {
	SHA256 string
	Size   int64
}

// VerifyFunc inspects a fully-written temp file before it is renamed into
// place, and receives what was written. Returning an error aborts the write and
// leaves any existing file untouched.
type VerifyFunc func(path string, res WriteResult) error

type atomicOptions struct {
	verify []VerifyFunc
}

// Option configures AtomicWrite.
type Option func(*atomicOptions)

// WithVerify registers a check that runs against the completed temp file before
// the rename. Multiple verifiers run in the order registered; the first error
// aborts the write and leaves any existing file untouched.
func WithVerify(fn VerifyFunc) Option {
	return func(o *atomicOptions) { o.verify = append(o.verify, fn) }
}

// AtomicWrite streams r into a temp file in the destination directory,
// fsyncs it, renames it onto final (atomic on POSIX; on Windows Go uses
// MoveFileEx with REPLACE_EXISTING), then best-effort fsyncs the directory.
// On any error the temp file is removed and final is left untouched.
func AtomicWrite(final string, r io.Reader, maxBytes int64, opts ...Option) (*WriteResult, error) {
	var o atomicOptions
	for _, opt := range opts {
		opt(&o)
	}

	dir := filepath.Dir(final)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	hash := sha256.New()
	limit := maxBytes + 1
	if maxBytes <= 0 {
		limit = 0 // unlimited
	}
	size, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(r, limit))
	if err != nil {
		cleanup()
		return nil, err
	}
	if maxBytes > 0 && size > maxBytes {
		cleanup()
		return nil, ErrTooLarge
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, err
	}

	res := WriteResult{SHA256: hex.EncodeToString(hash.Sum(nil)), Size: size}
	for _, verify := range o.verify {
		if err := verify(tmpName, res); err != nil {
			os.Remove(tmpName)
			return nil, err
		}
	}
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return nil, err
	}
	syncDir(dir) // best-effort; not fully supported on Windows

	return &res, nil
}

// syncDir fsyncs a directory so the rename is durable. On Windows opening
// directories for sync may fail; that failure is intentionally ignored.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}

// CleanupTemps removes stale temp files (older than maxAge) anywhere under
// root. Called at startup and periodically; tolerates a missing root.
func CleanupTemps(root string, maxAge time.Duration) {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // keep walking on per-entry errors
		}
		name := d.Name()
		if !strings.HasPrefix(name, tempPrefix) {
			return nil
		}
		fi, err := d.Info()
		if err != nil || fi.ModTime().After(cutoff) {
			return nil //nolint:nilerr // keep walking on per-entry errors
		}
		_ = os.Remove(path)
		return nil
	})
}
