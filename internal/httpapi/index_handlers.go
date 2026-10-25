package httpapi

import (
	"net/http"
	"path"
	"sort"

	bolt "github.com/litemd-hq/litemd/internal/bolt"
	"github.com/litemd-hq/litemd/internal/files"
)

// currentIndexVersion is bumped whenever the derived index layout changes so
// that existing databases are rebuilt once on startup.
const currentIndexVersion = 1

// Reindex rebuilds the tag and backlink indexes from on-disk Markdown files if
// the stored index version is behind. It is a no-op once up to date.
func (s *Server) Reindex() error {
	v, err := s.store.IndexVersion()
	if err != nil {
		return err
	}
	if v >= currentIndexVersion {
		return nil
	}

	all, err := s.store.AllFiles()
	if err != nil {
		return err
	}
	for i := range all {
		uf := &all[i]
		if !uf.Entry.Deleted && files.IsMarkdownFile(uf.Entry.Path) {
			abs, err := files.Resolve(s.cfg.UserRoot(uf.UserUUID), uf.Entry.Path)
			if err != nil {
				continue
			}
			if meta, links, err := files.ParseFile(abs); err == nil {
				uf.Entry.Metadata = meta
				uf.Entry.Links = links
			}
		}
		if err := s.store.SetEntryIndex(uf.UserUUID, &uf.Entry); err != nil {
			return err
		}
	}
	return s.store.SetIndexVersion(currentIndexVersion)
}

// liveEntries returns the user's non-deleted entries, ordered by path.
func (s *Server) liveEntries(userUUID string) ([]files.Entry, error) {
	all, err := s.store.Manifest(userUUID)
	if err != nil {
		return nil, err
	}
	out := make([]files.Entry, 0, len(all))
	for _, e := range all {
		if !e.Deleted {
			out = append(out, e)
		}
	}
	return out, nil
}

// nameToPath maps each live note's canonical name (LinkKey) to its path. When
// several notes share a name the lexicographically first path wins, mirroring
// deterministic wikilink resolution.
func nameToPath(entries []files.Entry) map[string]string {
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		key := files.LinkKey(e.Path)
		if key == "" {
			continue
		}
		if cur, ok := m[key]; !ok || e.Path < cur {
			m[key] = e.Path
		}
	}
	return m
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	tags, err := s.store.Tags(user.UUID)
	if err != nil {
		s.log.Error("tags", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if tags == nil {
		tags = []bolt.TagCount{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tags": tags})
}

func (s *Server) handleTagFiles(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	entries, err := s.store.FilesByTag(user.UUID, r.PathValue("tag"))
	if err != nil {
		s.log.Error("files by tag", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if entries == nil {
		entries = []files.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": entries})
}

// linkOut describes one outgoing wikilink and, when resolvable, its target.
type linkOut struct {
	Target   string `json:"target"`
	Resolved string `json:"resolved,omitempty"`
	Exists   bool   `json:"exists"`
}

func (s *Server) handleLinks(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	clean, err := files.CleanRelPath(r.PathValue("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}
	entry, err := s.store.GetFile(user.UUID, clean)
	if err != nil || entry.Deleted {
		writeError(w, http.StatusNotFound, "not_found", "file not found")
		return
	}

	entries, err := s.liveEntries(user.UUID)
	if err != nil {
		s.log.Error("live entries", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	names := nameToPath(entries)

	out := make([]linkOut, 0, len(entry.Links))
	for _, target := range entry.Links {
		lo := linkOut{Target: target}
		if p, ok := names[files.LinkKey(target)]; ok {
			lo.Resolved = p
			lo.Exists = true
		}
		out = append(out, lo)
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": clean, "links": out})
}

type backlinkOut struct {
	Path  string `json:"path"`
	Title string `json:"title,omitempty"`
}

func (s *Server) handleBacklinks(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	clean, err := files.CleanRelPath(r.PathValue("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}
	sources, err := s.store.Backlinks(user.UUID, files.LinkKey(clean))
	if err != nil {
		s.log.Error("backlinks", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	out := make([]backlinkOut, 0, len(sources))
	for _, src := range sources {
		if src == clean {
			continue // a note linking to itself is not a backlink
		}
		bo := backlinkOut{Path: src}
		if e, err := s.store.GetFile(user.UUID, src); err == nil && e.Metadata != nil {
			bo.Title = e.Metadata.Title
		}
		out = append(out, bo)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	writeJSON(w, http.StatusOK, map[string]any{"path": clean, "backlinks": out})
}

type graphNode struct {
	Path  string `json:"path"`
	Title string `json:"title,omitempty"`
}

type graphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	entries, err := s.liveEntries(user.UUID)
	if err != nil {
		s.log.Error("live entries", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	names := nameToPath(entries)

	nodes := make([]graphNode, 0, len(entries))
	for _, e := range entries {
		n := graphNode{Path: e.Path}
		if e.Metadata != nil {
			n.Title = e.Metadata.Title
		}
		nodes = append(nodes, n)
	}
	seen := map[graphEdge]bool{}
	var edges []graphEdge
	for _, e := range entries {
		for _, target := range e.Links {
			to, ok := names[files.LinkKey(target)]
			if !ok || to == e.Path {
				continue
			}
			edge := graphEdge{From: e.Path, To: to}
			if seen[edge] {
				continue
			}
			seen[edge] = true
			edges = append(edges, edge)
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})
	if edges == nil {
		edges = []graphEdge{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges})
}

// unresolvedTarget is a note referenced by others but not yet created.
type unresolvedTarget struct {
	Name string `json:"name"`
	Refs int    `json:"refs"`
}

// handleUnresolved lists link targets that do not correspond to a live note,
// which is useful for "create these notes next" style UIs.
func (s *Server) handleUnresolved(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	entries, err := s.liveEntries(user.UUID)
	if err != nil {
		s.log.Error("live entries", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	names := nameToPath(entries)

	counts := map[string]int{}
	for _, e := range entries {
		for _, target := range e.Links {
			key := files.LinkKey(target)
			if key == "" {
				continue
			}
			if _, ok := names[key]; ok {
				continue
			}
			counts[path.Base(target)]++
		}
	}
	out := make([]unresolvedTarget, 0, len(counts))
	for name, refs := range counts {
		out = append(out, unresolvedTarget{Name: name, Refs: refs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Refs != out[j].Refs {
			return out[i].Refs > out[j].Refs
		}
		return out[i].Name < out[j].Name
	})
	writeJSON(w, http.StatusOK, map[string]any{"unresolved": out})
}
