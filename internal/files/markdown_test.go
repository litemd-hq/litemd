package files

import (
	"reflect"
	"strings"
	"testing"
)

func TestIsMarkdownFile(t *testing.T) {
	cases := map[string]bool{
		"notes/hello.md":      true,
		"README.MD":           true,
		"docs/guide.markdown": true,
		"image.png":           false,
		"data.md.txt":         false,
		"folder.md/plain":     false,
		"no-extension":        false,
	}
	for path, want := range cases {
		if got := IsMarkdownFile(path); got != want {
			t.Errorf("IsMarkdownFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestExtractMetadataFrontmatter(t *testing.T) {
	doc := strings.Join([]string{
		"---",
		"title: My Note",
		"tags: [work, ideas]",
		"author: alice",
		"---",
		"# Body",
		"content here",
	}, "\n")

	meta, err := ExtractMetadata(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if meta.Title != "My Note" {
		t.Errorf("Title = %q, want %q", meta.Title, "My Note")
	}
	if want := []string{"work", "ideas"}; !reflect.DeepEqual(meta.Tags, want) {
		t.Errorf("Tags = %v, want %v", meta.Tags, want)
	}
	if meta.Extra["author"] != "alice" {
		t.Errorf("Extra[author] = %q, want %q", meta.Extra["author"], "alice")
	}
}

func TestExtractMetadataCommaTags(t *testing.T) {
	doc := "---\ntags: one, two,three\n---\nbody\n"
	meta, err := ExtractMetadata(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if want := []string{"one", "two", "three"}; !reflect.DeepEqual(meta.Tags, want) {
		t.Errorf("Tags = %v, want %v", meta.Tags, want)
	}
}

func TestExtractMetadataQuotedValues(t *testing.T) {
	doc := "---\ntitle: \"Hello: World\"\ntags: ['a', 'b']\n---\n"
	meta, err := ExtractMetadata(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if meta.Title != "Hello: World" {
		t.Errorf("Title = %q, want %q", meta.Title, "Hello: World")
	}
	if want := []string{"a", "b"}; !reflect.DeepEqual(meta.Tags, want) {
		t.Errorf("Tags = %v, want %v", meta.Tags, want)
	}
}

func TestExtractMetadataNoFrontmatter(t *testing.T) {
	doc := "# Just a heading\n\nsome text\n"
	meta, err := ExtractMetadata(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if meta == nil {
		t.Fatal("metadata must be non-nil")
	}
	if meta.Title != "" || meta.Tags != nil || len(meta.Extra) != 0 {
		t.Errorf("expected empty metadata, got %+v", meta)
	}
}

func TestExtractMetadataUnterminated(t *testing.T) {
	doc := "---\ntitle: broken\nno closing delimiter\n"
	meta, err := ExtractMetadata(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if meta.Title != "" {
		t.Errorf("unterminated frontmatter must not yield metadata, got %+v", meta)
	}
}

func TestValidateMarkdown(t *testing.T) {
	if err := ValidateMarkdown([]byte("# ok\n")); err != nil {
		t.Errorf("valid markdown rejected: %v", err)
	}
	if err := ValidateMarkdown(nil); err != nil {
		t.Errorf("empty content should be valid: %v", err)
	}
	if err := ValidateMarkdown([]byte{0xff, 0xfe, 0x00}); err == nil {
		t.Error("invalid UTF-8 should be rejected")
	}
}

func TestUTF8ValidatorStreaming(t *testing.T) {
	// Split a multi-byte rune across two Write calls to exercise carry-over.
	v := NewUTF8Validator()
	s := []byte("caf\u00e9 \U0001F600 done")
	if _, err := v.Write(s[:5]); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := v.Write(s[5:]); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := v.Err(); err != nil {
		t.Errorf("valid stream rejected: %v", err)
	}

	// A stream ending mid-rune is invalid.
	v2 := NewUTF8Validator()
	if _, err := v2.Write([]byte{0xE2, 0x82}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := v2.Err(); err == nil {
		t.Error("truncated rune should be rejected")
	}

	// Invalid continuation in the middle is caught.
	v3 := NewUTF8Validator()
	if _, err := v3.Write([]byte{'a', 0xE2, 0x28, 0xA1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := v3.Err(); err == nil {
		t.Error("invalid continuation should be rejected")
	}
}
