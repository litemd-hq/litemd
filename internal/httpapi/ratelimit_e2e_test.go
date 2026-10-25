package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/litemd-hq/litemd/internal/config"
)

func TestRateLimitIsConfigurable(t *testing.T) {
	env := newTestEnvWith(t, func(c *config.Config) {
		c.RateLimitBurst = 2
		c.RateLimitRefillPerSec = 0.0001 // effectively no refill during the test
	})

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "wrong-password"})

	// The first two login attempts are allowed through the bucket; the third is
	// throttled. newTestEnv already consumed one token during registration and
	// the login it performs, so the bucket is nearly empty to start with.
	statuses := make([]int, 0, 4)
	for i := 0; i < 4; i++ {
		resp := env.do(t, http.MethodPost, "/api/v1/auth/login", body)
		statuses = append(statuses, resp.StatusCode)
		resp.Body.Close()
	}

	sawLimited := false
	for _, s := range statuses {
		if s == http.StatusTooManyRequests {
			sawLimited = true
		}
	}
	if !sawLimited {
		t.Fatalf("expected at least one 429 with burst=2, got %v", statuses)
	}
}

func TestRateLimitAllowsWithLargeBurst(t *testing.T) {
	env := newTestEnvWith(t, func(c *config.Config) {
		c.RateLimitBurst = 1000
		c.RateLimitRefillPerSec = 100
	})

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "wrong-password"})
	for i := 0; i < 5; i++ {
		resp := env.do(t, http.MethodPost, "/api/v1/auth/login", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401 (not throttled)", i, resp.StatusCode)
		}
	}
}

func TestRateLimitRefills(t *testing.T) {
	env := newTestEnvWith(t, func(c *config.Config) {
		c.RateLimitBurst = 1
		c.RateLimitRefillPerSec = 100 // refills fast enough that we never trip
	})

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "wrong-password"})
	for i := 0; i < 3; i++ {
		resp := env.do(t, http.MethodPost, "/api/v1/auth/login", body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("attempt %d was throttled despite fast refill", i)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
