package files

import (
	"time"
)

// Entry describes one file in a user's namespace. Tombstones (Deleted=true)
// stay in the manifest so other clients learn about deletions during sync.
type Entry struct {
	Path    string    `json:"path"`
	Version uint64    `json:"version"`
	SHA256  string    `json:"sha256"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mtime"`
	Deleted bool      `json:"deleted,omitempty"`

	// Metadata carries parsed Markdown frontmatter. It is nil for non-Markdown
	// files and for entries written before this field existed.
	Metadata *MarkdownMetadata `json:"metadata,omitempty"`

	// Links lists outgoing wikilink targets ([[...]]) in first-seen order.
	// Targets are stored as written minus any alias/anchor.
	Links []string `json:"links,omitempty"`

	// ContentType is the MIME type served on download, determined from the path
	// extension or by sniffing the file's leading bytes. Empty for entries
	// written before this field existed; the server derives it on demand.
	ContentType string `json:"content_type,omitempty"`
}

// MarkdownMetadata represents structured metadata extracted from a Markdown file
type MarkdownMetadata struct {
	Title string            `json:"title,omitempty"`
	Tags  []string          `json:"tags,omitempty"`
	Extra map[string]string `json:"extra,omitempty"`
}

// MaxPathDepth limits directory nesting for any single file.
const MaxPathDepth = 32
