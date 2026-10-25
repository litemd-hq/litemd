package files

import (
	"reflect"
	"testing"
)

func TestParseMergesAndNormalizesTags(t *testing.T) {
	doc := "---\ntags: [Work, ideas]\n---\n\n# Heading\n\nbody #Ideas and #work and #new\n"
	meta, links := Parse([]byte(doc))
	if len(links) != 0 {
		t.Errorf("unexpected links: %v", links)
	}
	want := []string{"work", "ideas", "new"}
	if !reflect.DeepEqual(meta.Tags, want) {
		t.Errorf("tags = %v, want %v", meta.Tags, want)
	}
}

func TestParseWikilinks(t *testing.T) {
	doc := "See [[Beta]], [[Beta|the beta]], [[dir/Alpha.md]], [[Beta#section]], [[#anchor]].\n"
	_, links := Parse([]byte(doc))
	want := []string{"Beta", "dir/Alpha.md"}
	if !reflect.DeepEqual(links, want) {
		t.Errorf("links = %v, want %v", links, want)
	}
}

func TestParseIgnoresCode(t *testing.T) {
	doc := "real [[keep]]\n\n```\n[[fenced]] #fencedtag\n```\n\ninline `[[coded]] #codetag` done\n"
	meta, links := Parse([]byte(doc))
	if !reflect.DeepEqual(links, []string{"keep"}) {
		t.Errorf("links = %v, want [keep]", links)
	}
	if len(meta.Tags) != 0 {
		t.Errorf("tags from code should be ignored, got %v", meta.Tags)
	}
}

func TestParseSlashTags(t *testing.T) {
	meta, _ := Parse([]byte("tagged #project/alpha here\n"))
	if !reflect.DeepEqual(meta.Tags, []string{"project/alpha"}) {
		t.Errorf("tags = %v, want [project/alpha]", meta.Tags)
	}
}

func TestLinkKeyAndTarget(t *testing.T) {
	keyCases := map[string]string{
		"notes/Foo.md":   "foo",
		"Foo":            "foo",
		"a/b/c.markdown": "c",
		"dir\\Win.md":    "win",
		"UPPER.MD":       "upper",
		"trailing/":      "trailing",
		"":               "",
	}
	for in, want := range keyCases {
		if got := LinkKey(in); got != want {
			t.Errorf("LinkKey(%q) = %q, want %q", in, got, want)
		}
	}

	targetCases := map[string]string{
		"Beta":         "Beta",
		"Beta|alias":   "Beta",
		"dir/Alpha.md": "dir/Alpha.md",
		"Beta#section": "Beta",
		"#only-anchor": "",
		"  spaced  ":   "spaced",
	}
	for in, want := range targetCases {
		if got := LinkTarget(in); got != want {
			t.Errorf("LinkTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeTag(t *testing.T) {
	cases := map[string]string{
		"#Work":   "work",
		" Ideas ": "ideas",
		"":        "",
	}
	for in, want := range cases {
		if got := NormalizeTag(in); got != want {
			t.Errorf("NormalizeTag(%q) = %q, want %q", in, got, want)
		}
	}
}
