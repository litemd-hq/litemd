package httpapi

import (
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/litemd-hq/litemd/internal/files"
)

// defaultContentType is used when nothing more specific can be determined.
const defaultContentType = "application/octet-stream"

// activeContentTypes are types a browser will parse and execute. Serving any of
// these inline from the API origin would make nosniff an XSS vector, so they are
// downgraded to an inert type that forces a download.
var activeContentTypes = map[string]bool{
	"text/html":                true,
	"application/xhtml+xml":    true,
	"image/svg+xml":            true,
	"text/xml":                 true,
	"application/xml":          true,
	"text/javascript":          true,
	"application/javascript":   true,
	"application/ecmascript":   true,
	"text/ecmascript":          true,
	"application/x-javascript": true,
}

// contentTypeFor determines the MIME type of a stored file. The path extension
// wins because it is deterministic; when the extension is unknown the file's
// leading bytes are sniffed. Markdown files always report text/markdown.
//
// The client-supplied request Content-Type is deliberately ignored so a client
// cannot label a blob as text/html and have it rendered.
func contentTypeFor(cleanPath, abs string) string {
	if files.IsMarkdownFile(cleanPath) {
		return "text/markdown; charset=utf-8"
	}
	if ct := mime.TypeByExtension(filepath.Ext(cleanPath)); ct != "" && ct != defaultContentType {
		return sanitizeContentType(ct)
	}
	f, err := os.Open(abs)
	if err != nil {
		return defaultContentType
	}
	defer f.Close()
	return sanitizeContentType(sniffContentType(f))
}

// sniffContentType classifies a stream from its first 512 bytes.
func sniffContentType(r io.Reader) string {
	var buf [512]byte
	n, _ := io.ReadFull(r, buf[:])
	if n == 0 {
		return defaultContentType
	}
	if ct := http.DetectContentType(buf[:n]); ct != "" {
		return ct
	}
	return defaultContentType
}

// sanitizeContentType downgrades browser-executed types to an inert one.
func sanitizeContentType(ct string) string {
	ct = strings.TrimSpace(ct)
	base := strings.ToLower(ct)
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = strings.TrimSpace(base[:i])
	}
	if activeContentTypes[base] {
		return defaultContentType
	}
	return ct
}
