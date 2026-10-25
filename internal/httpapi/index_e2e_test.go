package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func getJSON[T any](t *testing.T, env *testEnv, path string) T {
	t.Helper()
	resp := env.do(t, http.MethodGet, path, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", path, resp.StatusCode)
	}
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return v
}

func put(t *testing.T, env *testEnv, path, body string) {
	t.Helper()
	env.create(t, path, []byte(body))
}

type tagsResp struct {
	Tags []struct {
		Tag   string `json:"tag"`
		Count int    `json:"count"`
	} `json:"tags"`
}

type filesResp struct {
	Files []struct {
		Path     string `json:"path"`
		Deleted  bool   `json:"deleted"`
		Metadata *struct {
			Tags []string `json:"tags"`
		} `json:"metadata"`
		Links []string `json:"links"`
	} `json:"files"`
}

// livePaths returns the set of non-deleted paths from a manifest response.
func livePaths(t *testing.T, env *testEnv) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range getJSON[filesResp](t, env, "/api/v1/files").Files {
		if !f.Deleted {
			out[f.Path] = true
		}
	}
	return out
}

type linksResp struct {
	Path  string `json:"path"`
	Links []struct {
		Target   string `json:"target"`
		Resolved string `json:"resolved"`
		Exists   bool   `json:"exists"`
	} `json:"links"`
}

type backlinksResp struct {
	Path      string `json:"path"`
	Backlinks []struct {
		Path  string `json:"path"`
		Title string `json:"title"`
	} `json:"backlinks"`
}

type graphResp struct {
	Nodes []struct {
		Path  string `json:"path"`
		Title string `json:"title"`
	} `json:"nodes"`
	Edges []struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"edges"`
}

func seedVault(t *testing.T, env *testEnv) {
	t.Helper()
	put(t, env, "/api/v1/files/a.md", "---\ntitle: Alpha\ntags: [work]\n---\n# A\n\nSee [[b]] and [[missing]]. #inline\n")
	put(t, env, "/api/v1/files/b.md", "---\ntitle: Beta\n---\n# B\n\nBack to [[a]]\n")
}

func TestTagIndex(t *testing.T) {
	env := newTestEnv(t)
	seedVault(t, env)

	tags := getJSON[tagsResp](t, env, "/api/v1/tags")
	got := map[string]int{}
	for _, tc := range tags.Tags {
		got[tc.Tag] = tc.Count
	}
	if got["work"] != 1 {
		t.Errorf("work count = %d, want 1 (all: %+v)", got["work"], tags.Tags)
	}
	if got["inline"] != 1 {
		t.Errorf("inline count = %d, want 1 (all: %+v)", got["inline"], tags.Tags)
	}

	files := getJSON[filesResp](t, env, "/api/v1/tags/work")
	if len(files.Files) != 1 || files.Files[0].Path != "a.md" {
		t.Errorf("tag work files = %+v, want [a.md]", files.Files)
	}

	// b.md carries no tags.
	if got := getJSON[filesResp](t, env, "/api/v1/tags/work"); len(got.Files) != 1 {
		t.Errorf("unexpected extra files: %+v", got.Files)
	}
}

func TestLinksAndBacklinks(t *testing.T) {
	env := newTestEnv(t)
	seedVault(t, env)

	links := getJSON[linksResp](t, env, "/api/v1/links/a.md")
	resolved := map[string]bool{}
	exists := map[string]bool{}
	for _, l := range links.Links {
		resolved[l.Target] = l.Resolved != ""
		exists[l.Target] = l.Exists
	}
	if !exists["b"] || !resolved["b"] {
		t.Errorf("link [[b]] should resolve; got %+v", links.Links)
	}
	if exists["missing"] || resolved["missing"] {
		t.Errorf("link [[missing]] should not resolve; got %+v", links.Links)
	}

	back := getJSON[backlinksResp](t, env, "/api/v1/backlinks/b.md")
	if len(back.Backlinks) != 1 || back.Backlinks[0].Path != "a.md" {
		t.Errorf("backlinks of b.md = %+v, want [a.md]", back.Backlinks)
	}
}

func TestGraphAndUnresolved(t *testing.T) {
	env := newTestEnv(t)
	seedVault(t, env)

	g := getJSON[graphResp](t, env, "/api/v1/graph")
	if len(g.Nodes) != 2 {
		t.Errorf("graph nodes = %d, want 2", len(g.Nodes))
	}
	hasEdge := func(from, to string) bool {
		for _, e := range g.Edges {
			if e.From == from && e.To == to {
				return true
			}
		}
		return false
	}
	if !hasEdge("a.md", "b.md") || !hasEdge("b.md", "a.md") {
		t.Errorf("graph missing expected edges: %+v", g.Edges)
	}

	unres := getJSON[struct {
		Unresolved []struct {
			Name string `json:"name"`
			Refs int    `json:"refs"`
		} `json:"unresolved"`
	}](t, env, "/api/v1/unresolved")
	if len(unres.Unresolved) != 1 || unres.Unresolved[0].Name != "missing" {
		t.Errorf("unresolved = %+v, want [missing]", unres.Unresolved)
	}
}

func TestIndexUpdatedOnOverwriteAndDelete(t *testing.T) {
	env := newTestEnv(t)

	created := env.create(t, "/api/v1/files/n.md", []byte("---\ntags: [old]\n---\nsee [[gone]]\n"))
	if got := getJSON[filesResp](t, env, "/api/v1/tags/old"); len(got.Files) != 1 {
		t.Fatalf("tag old after create = %+v, want [n.md]", got.Files)
	}

	// Overwrite with a different tag and no links.
	updated := env.update(t, "/api/v1/files/n.md", []byte("---\ntags: [new]\n---\nno links now\n"), created.Version)
	if got := getJSON[filesResp](t, env, "/api/v1/tags/old"); len(got.Files) != 0 {
		t.Errorf("stale tag old still present: %+v", got.Files)
	}
	if got := getJSON[filesResp](t, env, "/api/v1/tags/new"); len(got.Files) != 1 {
		t.Errorf("tag new missing: %+v", got.Files)
	}

	// Delete and confirm the index is emptied.
	env.del(t, "/api/v1/files/n.md", updated.Version)
	if got := getJSON[tagsResp](t, env, "/api/v1/tags"); len(got.Tags) != 0 {
		t.Errorf("tags after delete = %+v, want none", got.Tags)
	}
}

func TestReindexRebuildsAndIsIdempotent(t *testing.T) {
	env := newTestEnv(t)
	seedVault(t, env)

	before := getJSON[tagsResp](t, env, "/api/v1/tags")

	if err := env.server.Reindex(); err != nil {
		t.Fatalf("reindex: %v", err)
	}
	v, err := env.server.store.IndexVersion()
	if err != nil {
		t.Fatalf("index version: %v", err)
	}
	if v != currentIndexVersion {
		t.Errorf("index version = %d, want %d", v, currentIndexVersion)
	}

	after := getJSON[tagsResp](t, env, "/api/v1/tags")
	if len(before.Tags) != len(after.Tags) {
		t.Errorf("tag count changed after reindex: before=%+v after=%+v", before.Tags, after.Tags)
	}

	// A second run is a no-op and must not disturb results.
	if err := env.server.Reindex(); err != nil {
		t.Fatalf("second reindex: %v", err)
	}
	again := getJSON[tagsResp](t, env, "/api/v1/tags")
	if len(again.Tags) != len(after.Tags) {
		t.Errorf("tags changed on idempotent reindex: %+v vs %+v", again.Tags, after.Tags)
	}
}
