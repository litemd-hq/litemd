package files

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanRelPathRejects(t *testing.T) {
	bad := []string{
		"",
		"/etc/passwd",
		"../escape",
		"a/../../b",
		"a/./b",
		"a/..",
		`back\slash`,
		"CON",
		"aux.txt",
		"trailing.",
		"trail ",
		"a//../b",
		"has:colon",
		"star*",
		"nul\x00byte",
	}
	for _, p := range bad {
		if got, err := CleanRelPath(p); err == nil {
			t.Errorf("CleanRelPath(%q) = %q, want error", p, got)
		}
	}
}

func TestCleanRelPathAccepts(t *testing.T) {
	cases := map[string]string{
		"a/b.md":           "a/b.md",
		"notes/x":          "notes/x",
		"a//b":             "a/b",
		"./a/b":            "a/b",
		"deep/a/b/c/d.txt": "deep/a/b/c/d.txt",
	}
	for in, want := range cases {
		got, err := CleanRelPath(in)
		if err != nil {
			t.Errorf("CleanRelPath(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("CleanRelPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveStaysUnderRoot(t *testing.T) {
	root := t.TempDir()
	abs, err := Resolve(root, "a/b.md")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.HasPrefix(abs, root) {
		t.Errorf("resolved %q escapes root %q", abs, root)
	}
}

func TestCheckSymlinksRejectsEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}

	if err := CheckSymlinks(root, filepath.Join(root, "link", "secret")); err == nil {
		t.Error("symlink escaping the root should be rejected")
	}

	plain := filepath.Join(root, "plain.txt")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSymlinks(root, plain); err != nil {
		t.Errorf("plain in-root path rejected: %v", err)
	}
}

func TestCheckSymlinksAllowsMissing(t *testing.T) {
	root := t.TempDir()
	if err := CheckSymlinks(root, filepath.Join(root, "not", "created", "yet.md")); err != nil {
		t.Errorf("nonexistent path rejected: %v", err)
	}
}
