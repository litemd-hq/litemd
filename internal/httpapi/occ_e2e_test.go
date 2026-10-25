package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/litemd-hq/litemd/internal/files"
)

type apiError struct {
	Error struct {
		Code        string       `json:"code"`
		Message     string       `json:"message"`
		ServerEntry *files.Entry `json:"server_entry"`
	} `json:"error"`
}

func decodeErr(t *testing.T, resp *http.Response) apiError {
	t.Helper()
	var e apiError
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	return e
}

func TestUploadRequiresPrecondition(t *testing.T) {
	env := newTestEnv(t)

	resp := env.do(t, http.MethodPut, "/api/v1/files/x.md", []byte("body"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428", resp.StatusCode)
	}
	if got := decodeErr(t, resp).Error.Code; got != "precondition_required" {
		t.Errorf("code = %q, want precondition_required", got)
	}
}

func TestCreateOnlyRejectsExisting(t *testing.T) {
	env := newTestEnv(t)
	created := env.create(t, "/api/v1/files/x.md", []byte("first"))

	resp := env.doH(t, http.MethodPut, "/api/v1/files/x.md", []byte("second"),
		map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412", resp.StatusCode)
	}
	body := decodeErr(t, resp)
	if body.Error.ServerEntry == nil || body.Error.ServerEntry.Version != created.Version {
		t.Errorf("412 should carry the current entry, got %+v", body.Error.ServerEntry)
	}
}

func TestVersionMismatchConflicts(t *testing.T) {
	env := newTestEnv(t)
	created := env.create(t, "/api/v1/files/x.md", []byte("first"))

	resp := env.doH(t, http.MethodPut, "/api/v1/files/x.md", []byte("second"),
		map[string]string{"If-Match": "9999"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	body := decodeErr(t, resp)
	if body.Error.ServerEntry == nil {
		t.Fatal("409 must carry the current entry so clients can merge")
	}
	if body.Error.ServerEntry.Version != created.Version {
		t.Errorf("server_entry.version = %d, want %d", body.Error.ServerEntry.Version, created.Version)
	}
}

func TestIfMatchOnMissingPath(t *testing.T) {
	env := newTestEnv(t)
	resp := env.doH(t, http.MethodPut, "/api/v1/files/ghost.md", []byte("x"),
		map[string]string{"If-Match": "1"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412", resp.StatusCode)
	}
}

func TestLastWriteWinsIsGone(t *testing.T) {
	env := newTestEnv(t)
	created := env.create(t, "/api/v1/files/x.md", []byte("v1"))
	updated := env.update(t, "/api/v1/files/x.md", []byte("v2"), created.Version)

	// A stale writer holding v1 must not clobber v2.
	resp := env.doH(t, http.MethodPut, "/api/v1/files/x.md", []byte("v3-stale"),
		map[string]string{"If-Match": strconv.FormatUint(created.Version, 10)})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale write status = %d, want 409", resp.StatusCode)
	}
	if got := decodeErr(t, resp).Error.ServerEntry; got == nil || got.SHA256 != updated.SHA256 {
		t.Errorf("conflict should reflect the newer version (sha %s)", updated.SHA256)
	}
}

func TestDeleteRequiresPrecondition(t *testing.T) {
	env := newTestEnv(t)
	env.create(t, "/api/v1/files/x.md", []byte("body"))

	resp := env.do(t, http.MethodDelete, "/api/v1/files/x.md", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("delete without precondition status = %d, want 428", resp.StatusCode)
	}
	if got := env.do(t, http.MethodGet, "/api/v1/files/x.md", nil); got.StatusCode != http.StatusOK {
		got.Body.Close()
		t.Errorf("file should still exist after rejected delete, got %d", got.StatusCode)
	} else {
		got.Body.Close()
	}
}

func TestStaleDeleteConflicts(t *testing.T) {
	env := newTestEnv(t)
	created := env.create(t, "/api/v1/files/x.md", []byte("v1"))
	env.update(t, "/api/v1/files/x.md", []byte("v2"), created.Version)

	// Delete holding the stale v1 version.
	resp := env.doH(t, http.MethodDelete, "/api/v1/files/x.md", nil,
		map[string]string{"If-Match": strconv.FormatUint(created.Version, 10)})
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale delete status = %d, want 409", resp.StatusCode)
	}
	if got := env.do(t, http.MethodGet, "/api/v1/files/x.md", nil); got.StatusCode != http.StatusOK {
		got.Body.Close()
		t.Errorf("file must survive a stale delete, got %d", got.StatusCode)
	} else {
		got.Body.Close()
	}
}

func TestResurrectAfterDelete(t *testing.T) {
	env := newTestEnv(t)
	created := env.create(t, "/api/v1/files/x.md", []byte("v1"))
	env.del(t, "/api/v1/files/x.md", created.Version)

	// A tombstone is not a live file, so create-only succeeds.
	again := env.create(t, "/api/v1/files/x.md", []byte("v2"))
	if again.Version <= created.Version {
		t.Errorf("resurrected version %d should exceed tombstone version %d", again.Version, created.Version)
	}
}

func TestRejectsAmbiguousOrWildcardPreconditions(t *testing.T) {
	env := newTestEnv(t)
	created := env.create(t, "/api/v1/files/x.md", []byte("body"))
	version := strconv.FormatUint(created.Version, 10)

	cases := map[string]map[string]string{
		"both":      {"If-Match": version, "If-None-Match": "*"},
		"wildcard":  {"If-Match": "*"},
		"malformed": {"If-Match": "not-a-version"},
	}
	for name, hdr := range cases {
		resp := env.doH(t, http.MethodPut, "/api/v1/files/x.md", []byte("new"), hdr)
		resp.Body.Close()
		if resp.StatusCode != http.StatusPreconditionFailed {
			t.Errorf("%s: status = %d, want 412", name, resp.StatusCode)
		}
	}
}
