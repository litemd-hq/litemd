package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func login(t *testing.T, env *testEnv, user, pass string) tokenPair {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp := env.do(t, http.MethodPost, "/api/v1/auth/login", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	var p tokenPair
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	return p
}

func refreshStatus(t *testing.T, env *testEnv, refreshToken string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	resp := env.do(t, http.MethodPost, "/api/v1/auth/refresh", body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestRevokeAllEndsSessionsAcrossDevices(t *testing.T) {
	env := newTestEnv(t) // registers and logs in "alice"

	// A second "device" logs in independently.
	second := login(t, env, "alice", "password123")
	if got := refreshStatus(t, env, second.RefreshToken); got != http.StatusOK {
		t.Fatalf("precondition refresh status = %d, want 200", got)
	}

	resp := env.do(t, http.MethodPost, "/api/v1/auth/revoke-all", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke-all status = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Revoked int `json:"revoked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Revoked < 1 {
		t.Errorf("revoked = %d, want >= 1", out.Revoked)
	}

	if got := refreshStatus(t, env, second.RefreshToken); got != http.StatusUnauthorized {
		t.Errorf("refresh after revoke-all status = %d, want 401", got)
	}
}

func TestRevokeAllRequiresAuth(t *testing.T) {
	env := newTestEnv(t)
	saved := env.token
	env.token = ""

	resp := env.do(t, http.MethodPost, "/api/v1/auth/revoke-all", nil)
	resp.Body.Close()
	env.token = saved

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated revoke-all status = %d, want 401", resp.StatusCode)
	}
}

func TestLoginRefreshFlow(t *testing.T) {
	env := newTestEnv(t)
	p := login(t, env, "alice", "password123")

	body, _ := json.Marshal(map[string]string{"refresh_token": p.RefreshToken})
	resp := env.do(t, http.MethodPost, "/api/v1/auth/refresh", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200", resp.StatusCode)
	}
	var next tokenPair
	if err := json.NewDecoder(resp.Body).Decode(&next); err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	if next.RefreshToken == "" || next.RefreshToken == p.RefreshToken {
		t.Error("refresh token should be newly issued and rotated")
	}

	// Reusing the consumed token must fail closed.
	if got := refreshStatus(t, env, p.RefreshToken); got != http.StatusUnauthorized {
		t.Errorf("reused refresh token status = %d, want 401", got)
	}
}
