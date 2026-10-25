package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/litemd-hq/litemd/internal/auth"
	bolt "github.com/litemd-hq/litemd/internal/bolt"
	"github.com/litemd-hq/litemd/internal/config"
	"github.com/litemd-hq/litemd/internal/files"
)

type testEnv struct {
	srv    *httptest.Server
	server *Server
	token  string
	client *http.Client
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWith(t, nil)
}

// newTestEnvWith builds a test server, letting the caller tweak the config
// before it is applied (used to exercise rate limiting).
func newTestEnvWith(t *testing.T, mutate func(*config.Config)) *testEnv {
	t.Helper()
	dir := t.TempDir()

	cfg := &config.Config{
		DataDir:               dir,
		QuotaBytes:            1 << 20,
		MaxUpload:             1 << 20,
		AccessTokenTTL:        time.Minute,
		RefreshTokenTTL:       time.Hour,
		RateLimitBurst:        config.DefaultRateLimitBurst,
		RateLimitRefillPerSec: config.DefaultRateLimitRefillPerSec,
	}
	if mutate != nil {
		mutate(cfg)
	}
	store, err := bolt.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	authSvc, err := auth.NewService(store, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err != nil {
		t.Fatalf("auth service: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	api := New(cfg, store, authSvc, log)
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	env := &testEnv{srv: srv, server: api, client: srv.Client()}
	env.registerAndLogin(t, "alice", "password123")
	return env
}

func (e *testEnv) do(t *testing.T, method, path string, body []byte) *http.Response {
	t.Helper()
	return e.doH(t, method, path, body, nil)
}

// doH issues a request with extra headers, e.g. the OCC preconditions.
func (e *testEnv) doH(t *testing.T, method, path string, body []byte, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if e.token != "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// create uploads a new file, asserting it is created (201).
func (e *testEnv) create(t *testing.T, path string, body []byte) files.Entry {
	t.Helper()
	resp := e.doH(t, http.MethodPut, path, body, map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create %s status = %d, want 201", path, resp.StatusCode)
	}
	return decodeEntry(t, resp)
}

// update replaces an existing file at the given version, asserting 200.
func (e *testEnv) update(t *testing.T, path string, body []byte, version uint64) files.Entry {
	t.Helper()
	resp := e.doH(t, http.MethodPut, path, body, map[string]string{"If-Match": strconv.FormatUint(version, 10)})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update %s status = %d, want 200", path, resp.StatusCode)
	}
	return decodeEntry(t, resp)
}

// del removes a file at the given version, asserting 204.
func (e *testEnv) del(t *testing.T, path string, version uint64) {
	t.Helper()
	resp := e.doH(t, http.MethodDelete, path, nil, map[string]string{"If-Match": strconv.FormatUint(version, 10)})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %s status = %d, want 204", path, resp.StatusCode)
	}
}

func decodeEntry(t *testing.T, resp *http.Response) files.Entry {
	t.Helper()
	var e files.Entry
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decode entry: %v", err)
	}
	return e
}

func (e *testEnv) registerAndLogin(t *testing.T, user, pass string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp := e.do(t, http.MethodPost, "/api/v1/auth/register", body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want 201", resp.StatusCode)
	}

	reqBody, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/api/v1/auth/login", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	var pair struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pair); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	e.token = pair.AccessToken
}

func TestMarkdownUploadExtractsMetadata(t *testing.T) {
	env := newTestEnv(t)

	doc := "---\ntitle: Roadmap\ntags: [planning, q4]\nowner: alice\n---\n# Roadmap\n\n- ship it\n"
	created := env.create(t, "/api/v1/files/notes/roadmap.md", []byte(doc))

	if created.Metadata == nil {
		t.Fatal("upload response missing metadata")
	}
	if created.Metadata.Title != "Roadmap" {
		t.Errorf("title = %q, want %q", created.Metadata.Title, "Roadmap")
	}
	if got := created.Metadata.Tags; len(got) != 2 || got[0] != "planning" || got[1] != "q4" {
		t.Errorf("tags = %v, want [planning q4]", got)
	}
	if created.Metadata.Extra["owner"] != "alice" {
		t.Errorf("extra owner = %q, want %q", created.Metadata.Extra["owner"], "alice")
	}
}

func TestManifestIncludesMetadata(t *testing.T) {
	env := newTestEnv(t)

	env.create(t, "/api/v1/files/a.md", []byte("---\ntitle: Note A\n---\nbody\n"))
	env.create(t, "/api/v1/files/data.bin", []byte{0x00, 0x01, 0x02})

	resp := env.do(t, http.MethodGet, "/api/v1/files", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest status = %d, want 200", resp.StatusCode)
	}
	var manifest struct {
		Files []files.Entry `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}

	byPath := map[string]files.Entry{}
	for _, e := range manifest.Files {
		byPath[e.Path] = e
	}
	mdEntry, ok := byPath["a.md"]
	if !ok {
		t.Fatalf("a.md missing from manifest: %+v", manifest.Files)
	}
	if mdEntry.Metadata == nil || mdEntry.Metadata.Title != "Note A" {
		t.Errorf("a.md metadata = %+v, want title %q", mdEntry.Metadata, "Note A")
	}
	binEntry, ok := byPath["data.bin"]
	if !ok {
		t.Fatal("data.bin missing from manifest")
	}
	if binEntry.Metadata != nil {
		t.Errorf("data.bin should have no metadata, got %+v", binEntry.Metadata)
	}
}

func TestUploadRejectsInvalidMarkdown(t *testing.T) {
	env := newTestEnv(t)

	// 0xE2 0x28 is an invalid continuation sequence: not valid UTF-8.
	resp := env.doH(t, http.MethodPut, "/api/v1/files/bad.md", []byte{'#', ' ', 0xE2, 0x28, 0xA1},
		map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid markdown upload status = %d, want 400", resp.StatusCode)
	}

	// The rejected file must not be indexed.
	mresp := env.do(t, http.MethodGet, "/api/v1/files", nil)
	defer mresp.Body.Close()
	var manifest struct {
		Files []files.Entry `json:"files"`
	}
	if err := json.NewDecoder(mresp.Body).Decode(&manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	for _, e := range manifest.Files {
		if e.Path == "bad.md" {
			t.Errorf("rejected file was indexed: %+v", e)
		}
	}
}

func TestInvalidUploadDoesNotClobberExistingFile(t *testing.T) {
	env := newTestEnv(t)

	good := "---\ntitle: Keep Me\n---\noriginal body\n"
	created := env.create(t, "/api/v1/files/keep.md", []byte(good))

	// Overwrite with invalid UTF-8: must be rejected and leave the original.
	bad := []byte{'#', ' ', 0xE2, 0x28, 0xA1}
	resp := env.doH(t, http.MethodPut, "/api/v1/files/keep.md", bad,
		map[string]string{"If-Match": strconv.FormatUint(created.Version, 10)})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("overwrite with invalid markdown status = %d, want 400", resp.StatusCode)
	}

	got := env.do(t, http.MethodGet, "/api/v1/files/keep.md", nil)
	defer got.Body.Close()
	if got.StatusCode != http.StatusOK {
		t.Fatalf("download after rejected overwrite = %d, want 200", got.StatusCode)
	}
	body, _ := io.ReadAll(got.Body)
	if string(body) != good {
		t.Errorf("original content not preserved: got %q, want %q", body, good)
	}
}

func TestDownloadRoundTrip(t *testing.T) {
	env := newTestEnv(t)

	doc := "---\ntitle: Roundtrip\n---\nhello world\n"
	env.create(t, "/api/v1/files/rt.md", []byte(doc))

	resp := env.do(t, http.MethodGet, "/api/v1/files/rt.md", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != doc {
		t.Errorf("downloaded body = %q, want %q", got, doc)
	}
	if !strings.HasPrefix(resp.Header.Get("ETag"), `"`) {
		t.Errorf("missing ETag header, got %q", resp.Header.Get("ETag"))
	}
}
