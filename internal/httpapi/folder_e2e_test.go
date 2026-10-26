package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
)

type folderManifestResp struct {
	Folders []struct {
		Path    string `json:"path"`
		Version uint64 `json:"version"`
		Deleted bool   `json:"deleted"`
	} `json:"folders"`
}

func folderList(t *testing.T, env *testEnv) folderManifestResp {
	t.Helper()
	return getJSON[folderManifestResp](t, env, "/api/v1/folders")
}

// liveFolderVersions maps each live folder path to its version.
func liveFolderVersions(t *testing.T, env *testEnv) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	for _, f := range folderList(t, env).Folders {
		if !f.Deleted {
			out[f.Path] = f.Version
		}
	}
	return out
}

func createFolder(t *testing.T, env *testEnv, path string) uint64 {
	t.Helper()
	resp := env.doH(t, http.MethodPut, "/api/v1/folders/"+path, nil,
		map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create folder %s status = %d, want 201", path, resp.StatusCode)
	}
	var f struct {
		Path    string `json:"path"`
		Version uint64 `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&f); err != nil {
		t.Fatalf("decode folder: %v", err)
	}
	if f.Path != path || f.Version == 0 {
		t.Fatalf("folder = %+v, want path %q with a version", f, path)
	}
	return f.Version
}

type folderErrEnvelope struct {
	Error struct {
		Code        string `json:"code"`
		ServerEntry struct {
			Path    string `json:"path"`
			Version uint64 `json:"version"`
		} `json:"server_entry"`
	} `json:"error"`
}

func TestFolderEmptyLifecycle(t *testing.T) {
	env := newTestEnv(t)
	version := createFolder(t, env, "notes")

	if _, ok := liveFolderVersions(t, env)["notes"]; !ok {
		t.Fatal("empty folder not listed after create")
	}

	resp := env.doH(t, http.MethodDelete, "/api/v1/folders/notes", nil,
		map[string]string{"If-Match": strconv.FormatUint(version, 10)})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", resp.StatusCode)
	}

	var tombstoned bool
	for _, f := range folderList(t, env).Folders {
		if f.Path == "notes" {
			tombstoned = f.Deleted
		}
	}
	if !tombstoned {
		t.Fatal("expected a tombstone for the deleted folder")
	}
	if _, ok := liveFolderVersions(t, env)["notes"]; ok {
		t.Fatal("deleted folder still reported live")
	}

	// A tombstone is not a live folder, so create-only revives it.
	if again := createFolder(t, env, "notes"); again <= version {
		t.Errorf("revived version %d should exceed tombstone %d", again, version)
	}
}

func TestFolderCreateOverExistingConflicts(t *testing.T) {
	env := newTestEnv(t)
	createFolder(t, env, "notes")

	resp := env.doH(t, http.MethodPut, "/api/v1/folders/notes", nil,
		map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412", resp.StatusCode)
	}
	var env2 folderErrEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env2.Error.Code != "precondition_failed" {
		t.Errorf("code = %q, want precondition_failed", env2.Error.Code)
	}
	if env2.Error.ServerEntry.Path != "notes" {
		t.Errorf("server_entry.path = %q, want notes", env2.Error.ServerEntry.Path)
	}
}

func TestFolderRequiresPrecondition(t *testing.T) {
	env := newTestEnv(t)
	resp := env.do(t, http.MethodPut, "/api/v1/folders/notes", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428", resp.StatusCode)
	}
}

func TestFolderAncestorsAutoCreated(t *testing.T) {
	env := newTestEnv(t)
	env.create(t, "/api/v1/files/a/b/c.md", []byte("hi"))

	live := liveFolderVersions(t, env)
	if _, ok := live["a"]; !ok {
		t.Errorf("folder a missing: %v", live)
	}
	if _, ok := live["a/b"]; !ok {
		t.Errorf("folder a/b missing: %v", live)
	}
}

func TestFolderMove(t *testing.T) {
	env := newTestEnv(t)
	env.create(t, "/api/v1/files/notes/a.md", []byte("A"))
	env.create(t, "/api/v1/files/notes/deep/b.md", []byte("B"))
	version := liveFolderVersions(t, env)["notes"]

	resp := env.doH(t, http.MethodPost, "/api/v1/folders/notes", []byte(`{"to":"journal"}`),
		map[string]string{"If-Match": strconv.FormatUint(version, 10)})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("move status = %d, body %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	live := livePaths(t, env)
	if !live["journal/a.md"] || !live["journal/deep/b.md"] {
		t.Fatalf("moved files not live: %v", live)
	}
	if live["notes/a.md"] || live["notes/deep/b.md"] {
		t.Fatalf("old file paths still live: %v", live)
	}
	folders := liveFolderVersions(t, env)
	if _, ok := folders["journal"]; !ok {
		t.Errorf("journal folder missing: %v", folders)
	}
	if _, ok := folders["journal/deep"]; !ok {
		t.Errorf("journal/deep folder missing: %v", folders)
	}
	if _, ok := folders["notes"]; ok {
		t.Errorf("notes folder still live: %v", folders)
	}

	// The bytes moved on disk, so the renamed file still downloads.
	resp = env.do(t, http.MethodGet, "/api/v1/files/journal/a.md", nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "A" {
		t.Fatalf("download moved file = %d %q, want 200 \"A\"", resp.StatusCode, body)
	}
}

func TestFolderMoveCollision(t *testing.T) {
	env := newTestEnv(t)
	env.create(t, "/api/v1/files/a/x.md", []byte("X"))
	env.create(t, "/api/v1/files/b/x.md", []byte("X"))
	version := liveFolderVersions(t, env)["a"]

	resp := env.doH(t, http.MethodPost, "/api/v1/folders/a", []byte(`{"to":"b"}`),
		map[string]string{"If-Match": strconv.FormatUint(version, 10)})
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
}

func TestFolderMoveIntoSelf(t *testing.T) {
	env := newTestEnv(t)
	env.create(t, "/api/v1/files/notes/a.md", []byte("A"))
	version := liveFolderVersions(t, env)["notes"]

	resp := env.doH(t, http.MethodPost, "/api/v1/folders/notes", []byte(`{"to":"notes/sub"}`),
		map[string]string{"If-Match": strconv.FormatUint(version, 10)})
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412", resp.StatusCode)
	}
}

func TestFolderMoveRequiresPrecondition(t *testing.T) {
	env := newTestEnv(t)
	env.create(t, "/api/v1/files/notes/a.md", []byte("A"))

	resp := env.do(t, http.MethodPost, "/api/v1/folders/notes", []byte(`{"to":"journal"}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428", resp.StatusCode)
	}
}

func TestFolderRecursiveDelete(t *testing.T) {
	env := newTestEnv(t)
	env.create(t, "/api/v1/files/notes/a.md", []byte("A"))
	env.create(t, "/api/v1/files/notes/deep/b.md", []byte("B"))
	env.create(t, "/api/v1/files/keep/other.md", []byte("K"))
	version := liveFolderVersions(t, env)["notes"]

	resp := env.doH(t, http.MethodDelete, "/api/v1/folders/notes?recursive=true", nil,
		map[string]string{"If-Match": strconv.FormatUint(version, 10)})
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("recursive delete status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	live := livePaths(t, env)
	if !live["keep/other.md"] {
		t.Errorf("unrelated file removed: %v", live)
	}
	if live["notes/a.md"] || live["notes/deep/b.md"] {
		t.Errorf("subtree files still live: %v", live)
	}
	folders := liveFolderVersions(t, env)
	if _, ok := folders["keep"]; !ok {
		t.Errorf("unrelated folder removed: %v", folders)
	}
	if _, ok := folders["notes"]; ok {
		t.Errorf("notes folder still live: %v", folders)
	}
	if _, ok := folders["notes/deep"]; ok {
		t.Errorf("notes/deep folder still live: %v", folders)
	}

	// The bytes are gone, so the removed file no longer downloads.
	resp2 := env.do(t, http.MethodGet, "/api/v1/files/notes/a.md", nil)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("download after recursive delete = %d, want 404", resp2.StatusCode)
	}
}

func TestFilePathKindConflict(t *testing.T) {
	env := newTestEnv(t)
	createFolder(t, env, "d")

	// A file cannot take a folder's path.
	resp := env.doH(t, http.MethodPut, "/api/v1/files/d", []byte("x"),
		map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("file over folder status = %d, want 412", resp.StatusCode)
	}

	// And a folder cannot take a file's path.
	env.create(t, "/api/v1/files/g", []byte("y"))
	resp2 := env.doH(t, http.MethodPut, "/api/v1/folders/g", nil,
		map[string]string{"If-None-Match": "*"})
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("folder over file status = %d, want 412", resp2.StatusCode)
	}
}
