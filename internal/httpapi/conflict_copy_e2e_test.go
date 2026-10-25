package httpapi

import (
	"fmt"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/litemd-hq/litemd/internal/files"
)

// conflictCopyPath implements the documented client-side convention for naming
// a conflict copy: insert a marker before the extension so the server still
// derives the correct content type, and keep the name free of characters the
// path validator rejects (notably ':').
//
//	notes/photo.jpg -> notes/photo (conflict copy phone 2026-10-25T18-30-00Z).jpg
func conflictCopyPath(original, device string, at time.Time) string {
	dir, base := path.Split(original)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	stamp := at.UTC().Format("2006-01-02T15-04-05Z")
	return fmt.Sprintf("%s%s (conflict copy %s %s)%s", dir, stem, device, stamp, ext)
}

// makeConflict drives a two-device conflict on path and returns the winning
// (server) entry. "theirs" is written by the server, then a stale writer
// holding version 1 is rejected.
func makeConflict(t *testing.T, env *testEnv, path string, theirs, mine []byte) (winner files.Entry) {
	t.Helper()
	v1 := env.create(t, path, []byte("original"))
	winner = env.update(t, path, theirs, v1.Version)

	resp := env.doH(t, http.MethodPut, path, mine,
		map[string]string{"If-Match": fmt.Sprintf("%d", v1.Version)})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale write status = %d, want 409", resp.StatusCode)
	}
	if e := decodeErr(t, resp).Error.ServerEntry; e == nil || e.Version != winner.Version {
		t.Fatalf("409 should carry the winner (v%d)", winner.Version)
	}
	return winner
}

func jpegBody(marker string) []byte {
	// JPEG magic + a marker so two copies have different sha256 values.
	return append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte(marker)...)
}

func TestConflictCopyKeepBoth(t *testing.T) {
	env := newTestEnv(t)
	const p = "/api/v1/files/notes/photo.jpg"

	theirs, mine := jpegBody("theirs"), jpegBody("mine")
	winner := makeConflict(t, env, p, theirs, mine)

	// Device B preserves its own bytes under a conflict-copy name using the
	// ordinary create-only precondition. No server support is involved.
	copyPath := "/api/v1/files/" + conflictCopyPath("notes/photo.jpg", "phone", time.Now())
	copied := env.create(t, copyPath, mine)
	if copied.SHA256 == winner.SHA256 {
		t.Fatal("conflict copy should differ from the winner")
	}
	// The extension is preserved, so the content type is still correct.
	if copied.ContentType != "image/jpeg" {
		t.Errorf("conflict copy content_type = %q, want image/jpeg", copied.ContentType)
	}

	// Both versions are now visible to every device in the manifest.
	copyRel := strings.TrimPrefix(copyPath, "/api/v1/files/")
	paths := livePaths(t, env)
	if !paths["notes/photo.jpg"] || !paths[copyRel] {
		t.Fatalf("manifest should hold both versions, got %+v", paths)
	}

	// Resolve as "keep both": promote the copy to a chosen name, drop the
	// placeholder. The canonical path keeps the server's version.
	final := env.create(t, "/api/v1/files/notes/photo (phone).jpg", mine)
	if final.SHA256 != copied.SHA256 {
		t.Errorf("promoted file sha = %s, want %s", final.SHA256, copied.SHA256)
	}
	env.del(t, copyPath, copied.Version)

	names := livePaths(t, env)
	if names[copyRel] {
		t.Errorf("placeholder %q should have been deleted", copyRel)
	}
	if !names["notes/photo.jpg"] || !names["notes/photo (phone).jpg"] {
		t.Errorf("expected the original and the promoted copy, got %+v", names)
	}
}

func TestConflictCopyResolveKeepMine(t *testing.T) {
	env := newTestEnv(t)
	const p = "/api/v1/files/photo.jpg"

	theirs, mine := jpegBody("theirs"), jpegBody("mine")
	winner := makeConflict(t, env, p, theirs, mine)

	copyPath := "/api/v1/files/" + conflictCopyPath("photo.jpg", "laptop", time.Now())
	copied := env.create(t, copyPath, mine)

	// Keep mine: overwrite the canonical path using the version just learned,
	// then drop the placeholder.
	final := env.update(t, p, mine, winner.Version)
	if final.SHA256 != copied.SHA256 {
		t.Errorf("canonical sha = %s, want %s (mine)", final.SHA256, copied.SHA256)
	}
	env.del(t, copyPath, copied.Version)

	got := env.do(t, http.MethodGet, p, nil)
	defer got.Body.Close()
	if got.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d, want 200", got.StatusCode)
	}
	if etag := got.Header.Get("ETag"); etag != `"`+final.SHA256+`"` {
		t.Errorf("canonical content not the kept version: etag=%s want %s", etag, final.SHA256)
	}
}

func TestConflictCopyResolveKeepTheirs(t *testing.T) {
	env := newTestEnv(t)
	const p = "/api/v1/files/photo.jpg"

	theirs, mine := jpegBody("theirs"), jpegBody("mine")
	winner := makeConflict(t, env, p, theirs, mine)

	copyPath := "/api/v1/files/" + conflictCopyPath("photo.jpg", "tablet", time.Now())
	copied := env.create(t, copyPath, mine)

	// Keep theirs: just discard the placeholder; the canonical path is untouched.
	env.del(t, copyPath, copied.Version)

	names := livePaths(t, env)
	if len(names) != 1 || !names["photo.jpg"] {
		t.Fatalf("expected only photo.jpg to remain, got %+v", names)
	}
	head := env.do(t, http.MethodGet, p, nil)
	defer head.Body.Close()
	if etag := head.Header.Get("ETag"); etag != `"`+winner.SHA256+`"` {
		t.Errorf("canonical changed unexpectedly: etag=%s want %s", etag, winner.SHA256)
	}
}

func TestConflictCopyNameCollisionRetried(t *testing.T) {
	env := newTestEnv(t)
	const p = "/api/v1/files/photo.jpg"
	env.create(t, p, jpegBody("original"))

	// The conventional name already exists (e.g. a real file, or an earlier
	// conflict) so create-only fails and the client must pick another name.
	name := "/api/v1/files/" + conflictCopyPath("photo.jpg", "phone", time.Now())
	env.create(t, name, jpegBody("first"))

	resp := env.doH(t, http.MethodPut, name, jpegBody("second"), map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("collision status = %d, want 412", resp.StatusCode)
	}

	// Retry with a disambiguated suffix; the extension stays last.
	retry := "/api/v1/files/photo (conflict copy phone 2).jpg"
	env.create(t, retry, jpegBody("second"))
}
