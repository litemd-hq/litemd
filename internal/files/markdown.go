package files

import (
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// ExtractMetadata parses YAML-style frontmatter from the start of a Markdown
// file. A file with no frontmatter yields an empty (non-nil) metadata value.
func ExtractMetadata(r io.Reader) (*MarkdownMetadata, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxParseBytes))
	if err != nil {
		return nil, err
	}
	meta, _ := Parse(data)
	return meta, nil
}

// parseFrontmatter fills meta from simple "key: value" frontmatter lines.
// It intentionally handles only the flat subset used by note apps: scalar
// keys plus comma-separated or bracketed tag lists.
func parseFrontmatter(front string, meta *MarkdownMetadata) {
	for _, line := range strings.Split(front, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		switch key {
		case "title":
			meta.Title = unquote(value)
		case "tags":
			meta.Tags = parseTags(value)
		default:
			meta.Extra[key] = unquote(value)
		}
	}
}

// parseTags accepts "a, b", "[a, b]" and "- a\n- b"-style single-line input.
func parseTags(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	var tags []string
	for _, tag := range strings.Split(value, ",") {
		tag = unquote(strings.TrimSpace(tag))
		if tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// ErrInvalidEncoding reports Markdown content that is not valid UTF-8.
var ErrInvalidEncoding = errors.New("invalid UTF-8 content")

// ValidateMarkdown reports whether content is valid UTF-8. Empty content is
// considered valid Markdown.
func ValidateMarkdown(content []byte) error {
	v := NewUTF8Validator()
	_, _ = v.Write(content)
	return v.Err()
}

// UTF8Validator incrementally checks that a byte stream is valid UTF-8 while
// remembering at most three trailing bytes of an as-yet-incomplete rune. This
// lets callers validate large uploads in constant memory as they stream. It is
// not safe for concurrent use.
type UTF8Validator struct {
	partial [utf8.UTFMax]byte
	n       int
	bad     bool
}

// NewUTF8Validator returns a validator ready for streaming use.
func NewUTF8Validator() *UTF8Validator { return &UTF8Validator{} }

// Write consumes bytes without retaining them; it never reports an error so it
// can be used as the sink of an io.MultiWriter/TeeReader. Call Err afterwards.
func (v *UTF8Validator) Write(p []byte) (int, error) {
	if v.bad {
		return len(p), nil
	}
	buf := make([]byte, 0, v.n+len(p))
	buf = append(buf, v.partial[:v.n]...)
	v.n = 0
	buf = append(buf, p...)

	i := 0
	for i < len(buf) {
		b := buf[i]
		var need int
		switch {
		case b < 0x80:
			i++
			continue
		case b < 0xC2: // stray continuation or overlong lead byte
			v.bad = true
			return len(p), nil
		case b < 0xE0:
			need = 2
		case b < 0xF0:
			need = 3
		case b < 0xF5:
			need = 4
		default:
			v.bad = true
			return len(p), nil
		}
		if len(buf)-i < need {
			break // incomplete rune: carry the remainder to the next Write
		}
		if !utf8.Valid(buf[i : i+need]) {
			v.bad = true
			return len(p), nil
		}
		i += need
	}
	if i < len(buf) {
		v.n = copy(v.partial[:], buf[i:])
	}
	return len(p), nil
}

// Err reports whether the bytes seen so far are invalid UTF-8, including a
// stream that ends in the middle of a multi-byte rune.
func (v *UTF8Validator) Err() error {
	if v.bad || v.n > 0 {
		return ErrInvalidEncoding
	}
	return nil
}

// IsMarkdownFile reports whether the path carries a Markdown extension.
func IsMarkdownFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".markdown")
}
