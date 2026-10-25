package files

import (
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// maxParseBytes bounds how much of a note is scanned for links and inline
// tags. Notes beyond this are indexed only up to the limit.
const maxParseBytes = 4 << 20

var (
	reFence      = regexp.MustCompile("(?s)```.*?```")
	reInlineCode = regexp.MustCompile("`[^`\n]*`")
	reWikiLink   = regexp.MustCompile(`\[\[([^\[\]]+)\]\]`)
	reInlineTag  = regexp.MustCompile(`(?:^|[\s(])#([A-Za-z0-9_][A-Za-z0-9_./-]*)`)
)

// Parse extracts frontmatter metadata, inline tags and outgoing wikilinks from
// a Markdown document. Frontmatter and body tags are merged then normalized and
// de-duplicated (order preserved). Fenced and inline code are ignored.
func Parse(content []byte) (*MarkdownMetadata, []string) {
	meta, body := splitFrontmatter(content)
	body = stripCode(body)

	tags := append(append([]string(nil), meta.Tags...), inlineTags(body)...)
	meta.Tags = normalizeTags(tags)

	return meta, wikiLinks(body)
}

// ParseFile reads up to maxParseBytes of the file at abs and parses it.
func ParseFile(abs string) (*MarkdownMetadata, []string, error) {
	f, err := os.Open(abs)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxParseBytes))
	if err != nil {
		return nil, nil, err
	}
	meta, links := Parse(data)
	return meta, links, nil
}

// splitFrontmatter separates a leading YAML frontmatter block from the body.
// An absent or unterminated block yields empty metadata and the input as body.
func splitFrontmatter(content []byte) (*MarkdownMetadata, string) {
	meta := &MarkdownMetadata{Extra: map[string]string{}}
	s := strings.TrimPrefix(string(content), "\ufeff")

	nl := strings.IndexByte(s, '\n')
	if nl < 0 || strings.TrimSpace(s[:nl]) != "---" {
		return meta, s
	}
	rest := s[nl+1:]

	start, end, ok := closingFence(rest)
	if !ok {
		return meta, s
	}
	parseFrontmatter(rest[:start], meta)
	return meta, rest[end:]
}

// closingFence locates the first "---" line in s, returning the byte range of
// that line (including its trailing newline).
func closingFence(s string) (start, end int, ok bool) {
	off := 0
	for off <= len(s) {
		next := strings.IndexByte(s[off:], '\n')
		lineEnd := len(s)
		if next >= 0 {
			lineEnd = off + next + 1
		}
		if strings.TrimSpace(s[off:lineEnd]) == "---" {
			return off, lineEnd, true
		}
		if next < 0 {
			break
		}
		off = lineEnd
	}
	return 0, 0, false
}

// stripCode blanks out fenced code blocks and inline code spans so their
// contents cannot be mistaken for links or tags.
func stripCode(s string) string {
	s = reFence.ReplaceAllString(s, " ")
	return reInlineCode.ReplaceAllString(s, " ")
}

// wikiLinks returns the de-duplicated wikilink targets in first-seen order.
func wikiLinks(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reWikiLink.FindAllStringSubmatch(s, -1) {
		target := LinkTarget(m[1])
		key := LinkKey(target)
		if target == "" || key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, target)
	}
	return out
}

// inlineTags returns "#tag" style tags found in body text.
func inlineTags(s string) []string {
	var out []string
	for _, m := range reInlineTag.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// NormalizeTag lowercases a tag and strips a leading '#'.
func NormalizeTag(tag string) string {
	tag = strings.TrimSpace(tag)
	tag = strings.TrimPrefix(tag, "#")
	return strings.ToLower(tag)
}

// normalizeTags normalizes, drops empties and de-duplicates, preserving order.
func normalizeTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		n := NormalizeTag(t)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// LinkTarget strips an alias ("|x") and heading anchor ("#x") from a raw
// wikilink payload. A pure anchor ("#heading") yields "".
func LinkTarget(raw string) string {
	s := raw
	if i := strings.IndexByte(s, '|'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// LinkKey canonicalizes a link target or note path to the key used for
// backlink matching: the base name without extension, lowercased. This mirrors
// the common "shortest path" wikilink resolution used by note apps.
func LinkKey(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	base := path.Base(strings.ReplaceAll(target, "\\", "/"))
	if ext := path.Ext(base); ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	return strings.ToLower(base)
}
