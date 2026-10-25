package files

import (
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzCleanRelPath asserts the security invariant we actually care about: an
// accepted path can never resolve outside the user root, is always a cleaned
// relative path, and never contains a traversal segment.
func FuzzCleanRelPath(f *testing.F) {
	seeds := []string{
		"a/b.md", "notes/x", "./a/b", "a//b", "", "/etc/passwd", "../escape",
		"a/../../b", "a/./b", "CON", "aux.txt", "trailing.", `back\slash`,
		"has:colon", "star*", "nul\x00byte", "ünïcøde/文件.md", strings.Repeat("a/", 40),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	root := f.TempDir()

	f.Fuzz(func(t *testing.T, raw string) {
		clean, err := CleanRelPath(raw)
		if err != nil {
			return
		}
		if clean == "" {
			t.Fatal("accepted an empty path")
		}
		if strings.HasPrefix(clean, "/") {
			t.Fatalf("accepted an absolute path: %q", clean)
		}
		for _, seg := range strings.Split(clean, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("accepted traversal segment in %q", clean)
			}
		}
		if clean != path.Clean(clean) {
			t.Fatalf("result is not clean: %q", clean)
		}
		if len(strings.Split(clean, "/")) > MaxPathDepth {
			t.Fatalf("accepted a path deeper than MaxPathDepth: %q", clean)
		}

		// The decisive check: the resolved path must stay under the root.
		abs, err := Resolve(root, clean)
		if err != nil {
			t.Fatalf("Resolve rejected an accepted path %q: %v", clean, err)
		}
		rel, err := filepathRel(root, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string('/')) {
			t.Fatalf("path %q resolved outside the root: %q", clean, abs)
		}
	})
}

// filepathRel is a tiny indirection so the fuzz body reads clearly.
func filepathRel(root, target string) (string, error) { return filepath.Rel(root, target) }

// FuzzParse checks the document parser never panics and always returns
// normalized, de-duplicated output.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"---\ntitle: x\ntags: [a, b]\n---\n# h\n",
		"[[Beta]] [[Beta|alias]] #tag\n",
		"```\n[[fenced]] #fenced\n```\n",
		"---\n",
		"",
		"#\n",
		"[[{{.}}]]",
		"---\ntags: 'unterminated\n---\nbody",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		meta, links := Parse(content)
		if meta == nil {
			t.Fatal("Parse returned nil metadata")
		}

		seenTag := map[string]bool{}
		for _, tag := range meta.Tags {
			if tag == "" {
				t.Error("empty tag emitted")
			}
			if tag != NormalizeTag(tag) {
				t.Errorf("tag %q is not normalized", tag)
			}
			if seenTag[tag] {
				t.Errorf("tag %q emitted twice", tag)
			}
			seenTag[tag] = true
		}

		seenKey := map[string]bool{}
		for _, l := range links {
			if l == "" {
				t.Error("empty link emitted")
			}
			key := LinkKey(l)
			if key == "" {
				t.Errorf("link %q has an empty key", l)
			}
			if seenKey[key] {
				t.Errorf("link key %q emitted twice", key)
			}
			seenKey[key] = true
		}
	})
}

// FuzzIsMarkdownFile is a cheap invariant: the result must not depend on the
// case of the extension.
func FuzzIsMarkdownFile(f *testing.F) {
	for _, s := range []string{"a.md", "A.MD", "a.markdown", "a.txt", "", "."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if IsMarkdownFile(p) != IsMarkdownFile(strings.ToUpper(p)) {
			t.Errorf("extension detection is case sensitive for %q", p)
		}
	})
}
