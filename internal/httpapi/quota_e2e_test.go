package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/litemd-hq/litemd/internal/config"
)

// TestQuotaRejectsOversizeUpload checks the per-user quota is enforced: the
// remaining allowance also caps the stream, so the write fails without
// clobbering anything.
func TestQuotaRejectsOversizeUpload(t *testing.T) {
	env := newTestEnvWith(t, func(c *config.Config) {
		c.QuotaBytes = 100
	})

	env.create(t, "/api/v1/files/a.bin", make([]byte, 60))

	resp := env.doH(t, http.MethodPut, "/api/v1/files/b.bin", make([]byte, 60),
		map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	switch code := decodeErr(t, resp).Error.Code; code {
	case "too_large", "quota_exceeded":
	default:
		t.Errorf("error code = %q, want a quota/too-large code", code)
	}

	// The rejected file must not appear in the manifest.
	if livePaths(t, env)["b.bin"] {
		t.Error("rejected upload should not be indexed")
	}
}

func TestQuotaFreesSpaceAfterDelete(t *testing.T) {
	env := newTestEnvWith(t, func(c *config.Config) {
		c.QuotaBytes = 100
	})

	a := env.create(t, "/api/v1/files/a.bin", make([]byte, 60))

	if resp := env.doH(t, http.MethodPut, "/api/v1/files/b.bin", make([]byte, 60),
		map[string]string{"If-None-Match": "*"}); resp.StatusCode != http.StatusRequestEntityTooLarge {
		resp.Body.Close()
		t.Fatalf("second upload status = %d, want 413", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// Deleting the first file frees its bytes.
	env.del(t, "/api/v1/files/a.bin", a.Version)

	if resp := env.doH(t, http.MethodPut, "/api/v1/files/b.bin", make([]byte, 60),
		map[string]string{"If-None-Match": "*"}); resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		t.Fatalf("upload after delete status = %d, want 201", resp.StatusCode)
	} else {
		resp.Body.Close()
	}
}

// TestQuotaCountsReplacedFileOnce ensures replacing an entry is charged the
// difference rather than the sum.
func TestQuotaCountsReplacedFileOnce(t *testing.T) {
	env := newTestEnvWith(t, func(c *config.Config) {
		c.QuotaBytes = 100
	})

	e := env.create(t, "/api/v1/files/a.bin", make([]byte, 80))
	// Replacing the 80-byte file with a 90-byte one must fit: 90 <= 100.
	updated := env.update(t, "/api/v1/files/a.bin", make([]byte, 90), e.Version)
	if updated.Size != 90 {
		t.Fatalf("size = %d, want 90", updated.Size)
	}
}

func TestMaxUploadCapIsIndependentOfQuota(t *testing.T) {
	env := newTestEnvWith(t, func(c *config.Config) {
		c.QuotaBytes = 1 << 20
		c.MaxUpload = 10
	})

	resp := env.doH(t, http.MethodPut, "/api/v1/files/big.bin", make([]byte, 11),
		map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if code := decodeErr(t, resp).Error.Code; code != "too_large" {
		t.Errorf("error code = %q, want too_large", code)
	}
}

// TestQuotaErrorsAreJSON guards the wire format clients depend on.
func TestQuotaErrorsAreJSON(t *testing.T) {
	env := newTestEnvWith(t, func(c *config.Config) {
		c.QuotaBytes = 1
	})
	resp := env.doH(t, http.MethodPut, "/api/v1/files/x.bin", []byte("too big"),
		map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
	var env2 struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env2.Error.Message == "" {
		t.Error("error message should be populated")
	}
}
