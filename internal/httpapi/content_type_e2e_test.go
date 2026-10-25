package httpapi

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/litemd-hq/litemd/internal/files"
)

var pngBytes = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 'I', 'H', 'D', 'R'}

func uploadEntry(t *testing.T, env *testEnv, path string, body []byte) files.Entry {
	t.Helper()
	return env.create(t, path, body)
}

func TestContentTypeByExtension(t *testing.T) {
	env := newTestEnv(t)

	e := uploadEntry(t, env, "/api/v1/files/media/pic.png", pngBytes)
	if e.ContentType != "image/png" {
		t.Errorf("png content_type = %q, want image/png", e.ContentType)
	}

	// The stored type is served back on download.
	resp := env.do(t, http.MethodGet, "/api/v1/files/media/pic.png", nil)
	defer resp.Body.Close()
	if got := resp.Header.Get("Content-Type"); got != "image/png" {
		t.Errorf("download Content-Type = %q, want image/png", got)
	}
}

func TestContentTypeMarkdown(t *testing.T) {
	env := newTestEnv(t)
	e := uploadEntry(t, env, "/api/v1/files/note.md", []byte("# hi\n"))
	if e.ContentType != "text/markdown; charset=utf-8" {
		t.Errorf("markdown content_type = %q", e.ContentType)
	}
}

func TestContentTypeSniffsUnknownExtension(t *testing.T) {
	env := newTestEnv(t)
	e := uploadEntry(t, env, "/api/v1/files/blob.bin", pngBytes)
	if e.ContentType != "image/png" {
		t.Errorf("sniffed content_type = %q, want image/png", e.ContentType)
	}
}

func TestContentTypeDowngradesActiveTypes(t *testing.T) {
	env := newTestEnv(t)

	// SVG is scriptable; it must not be served as image/svg+xml.
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	e := uploadEntry(t, env, "/api/v1/files/x.svg", svg)
	if e.ContentType != defaultContentType {
		t.Errorf("svg content_type = %q, want %q", e.ContentType, defaultContentType)
	}

	// HTML smuggled behind an unknown extension must not become text/html.
	e = uploadEntry(t, env, "/api/v1/files/page.dat", []byte("<!DOCTYPE html><script>alert(1)</script>"))
	if e.ContentType == "text/html; charset=utf-8" || e.ContentType == "text/html" {
		t.Errorf("html sniffed as %q, want inert type", e.ContentType)
	}
}

func TestContentTypeFallbackForLegacyEntries(t *testing.T) {
	dir := t.TempDir()

	png := filepath.Join(dir, "old.png")
	if err := os.WriteFile(png, pngBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := contentTypeFor("old.png", png); got != "image/png" {
		t.Errorf("legacy png = %q, want image/png", got)
	}

	// Legacy entry with no usable extension: sniffing kicks in.
	blob := filepath.Join(dir, "old")
	if err := os.WriteFile(blob, pngBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := contentTypeFor("old", blob); got != "image/png" {
		t.Errorf("legacy blob = %q, want image/png", got)
	}

	missing := filepath.Join(dir, "gone.unknownext")
	if got := contentTypeFor("gone.unknownext", missing); got != defaultContentType {
		t.Errorf("missing file = %q, want %q", got, defaultContentType)
	}
}
