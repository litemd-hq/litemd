package files

import (
	"strings"
	"time"
)

// Folder is a first-class directory record. Folders have no bytes on disk of
// their own: they exist so that an empty folder can be synced between devices
// and so that a rename can be expressed as a single operation. Tombstones
// (Deleted=true) stay in the manifest so other clients learn about deletions.
type Folder struct {
	Path    string    `json:"path"`
	Version uint64    `json:"version"`
	ModTime time.Time `json:"mtime"`
	Deleted bool      `json:"deleted,omitempty"`
}

// AncestorDirs returns the proper ancestor directories of a clean relative
// path, outermost first. The path itself is excluded:
//
//	"a/b/c.md" -> ["a", "a/b"]
//	"a/b"      -> ["a"]
//	"a.md"     -> nil
func AncestorDirs(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

// IsUnder reports whether clean is clean itself or lives beneath it.
func IsUnder(clean, dir string) bool {
	return clean == dir || strings.HasPrefix(clean, dir+"/")
}
