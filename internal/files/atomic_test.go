package files

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sha256("hello")
const helloSum = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

func TestAtomicWriteAndHash(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "nested", "f.txt")

	res, err := AtomicWrite(final, strings.NewReader("hello"), 1024)
	if err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	if res.Size != 5 {
		t.Errorf("size = %d, want 5", res.Size)
	}
	if res.SHA256 != helloSum {
		t.Errorf("sha = %s, want %s", res.SHA256, helloSum)
	}
	got, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want hello", got)
	}
}

func TestAtomicWriteTooLarge(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "f")

	if _, err := AtomicWrite(final, strings.NewReader("0123456789"), 5); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if _, err := os.Stat(final); !os.IsNotExist(err) {
		t.Error("an oversized write must not create the final file")
	}
}

func TestAtomicWriteVerifyAbortsAndPreservesOld(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(final, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("reject")
	_, err := AtomicWrite(final, strings.NewReader("new"), 1024,
		WithVerify(func(string, WriteResult) error { return sentinel }))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}

	got, _ := os.ReadFile(final)
	if string(got) != "old" {
		t.Errorf("prior content clobbered: %q", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestAtomicWriteVerifiersChainInOrder(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "f.txt")

	var order []string
	_, err := AtomicWrite(final, strings.NewReader("x"), 1024,
		WithVerify(func(string, WriteResult) error { order = append(order, "first"); return nil }),
		WithVerify(func(string, WriteResult) error { order = append(order, "second"); return nil }),
	)
	if err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Errorf("verifier order = %v, want [first second]", order)
	}
}

func TestCleanupTemps(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, tempPrefix+"stale")
	fresh := filepath.Join(dir, tempPrefix+"fresh")
	real := filepath.Join(dir, "real.txt")
	for _, p := range []string{stale, fresh, real} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, past, past); err != nil {
		t.Fatal(err)
	}

	CleanupTemps(dir, time.Hour)

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale temp file should be removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("fresh temp file should be kept")
	}
	if _, err := os.Stat(real); err != nil {
		t.Error("non-temp file should be kept")
	}
}
