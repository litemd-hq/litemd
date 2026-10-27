package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/litemd-hq/litemd/internal/config"
)

// doAs issues a request with an explicit bearer token (empty means none) and a
// JSON content type.
func doAs(t *testing.T, env *testEnv, method, path string, body any, token string) *http.Response {
	t.Helper()
	var buf []byte
	if body != nil {
		var err error
		buf, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	req, err := http.NewRequest(method, env.srv.URL+path, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := env.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

type meBody struct {
	UUID      string `json:"uuid"`
	Username  string `json:"username"`
	IsAdmin   bool   `json:"is_admin"`
	Quota     int64  `json:"quota_bytes"`
	UsedBytes int64  `json:"used_bytes"`
}

func getMe(t *testing.T, env *testEnv, token string) meBody {
	t.Helper()
	resp := doAs(t, env, http.MethodGet, "/api/v1/auth/me", nil, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /me status = %d, want 200", resp.StatusCode)
	}
	var out meBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	return out
}

func TestMeReturnsProfileAndUsage(t *testing.T) {
	env := newTestEnv(t)
	env.create(t, "/api/v1/files/note.md", []byte("# hi"))

	me := getMe(t, env, env.token)
	if me.Username != "alice" || !me.IsAdmin {
		t.Errorf("me = %+v, want alice/admin", me)
	}
	if me.UsedBytes <= 0 {
		t.Errorf("used_bytes = %d, want > 0 after an upload", me.UsedBytes)
	}
}

func TestMeRequiresAuth(t *testing.T) {
	env := newTestEnv(t)
	resp := doAs(t, env, http.MethodGet, "/api/v1/auth/me", nil, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated /me status = %d, want 401", resp.StatusCode)
	}
}

func TestChangePasswordRevokesOldSessions(t *testing.T) {
	env := newTestEnv(t)
	old := env.token

	resp := doAs(t, env, http.MethodPost, "/api/v1/auth/password",
		map[string]string{"current_password": "password123", "new_password": "newpassword456"}, old)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change password status = %d, want 200", resp.StatusCode)
	}
	var pair tokenPair
	if err := json.NewDecoder(resp.Body).Decode(&pair); err != nil {
		t.Fatalf("decode pair: %v", err)
	}

	// The old access token is dead; the returned one works.
	if got := getStatus(t, env, "/api/v1/auth/me", old); got != http.StatusUnauthorized {
		t.Errorf("old token status = %d, want 401", got)
	}
	if got := getStatus(t, env, "/api/v1/auth/me", pair.AccessToken); got != http.StatusOK {
		t.Errorf("fresh token status = %d, want 200", got)
	}
	// The new password works; the old one does not.
	if loginStatus(t, env, "alice", "newpassword456") != http.StatusOK {
		t.Error("new password should log in")
	}
	if loginStatus(t, env, "alice", "password123") != http.StatusUnauthorized {
		t.Error("old password should be rejected")
	}
}

func TestChangePasswordRejectsWrongCurrent(t *testing.T) {
	env := newTestEnv(t)
	resp := doAs(t, env, http.MethodPost, "/api/v1/auth/password",
		map[string]string{"current_password": "wrong", "new_password": "newpassword456"}, env.token)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestChangeUsername(t *testing.T) {
	env := newTestEnv(t)
	// A second account so a name collision can be exercised.
	create := doAs(t, env, http.MethodPost, "/api/v1/users",
		map[string]any{"username": "bob", "password": "password123"}, env.token)
	create.Body.Close()

	bad := doAs(t, env, http.MethodPost, "/api/v1/auth/username",
		map[string]string{"username": "alice2", "password": "nope"}, env.token)
	bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password status = %d, want 401", bad.StatusCode)
	}

	taken := doAs(t, env, http.MethodPost, "/api/v1/auth/username",
		map[string]string{"username": "bob", "password": "password123"}, env.token)
	taken.Body.Close()
	if taken.StatusCode != http.StatusConflict {
		t.Errorf("taken name status = %d, want 409", taken.StatusCode)
	}

	resp := doAs(t, env, http.MethodPost, "/api/v1/auth/username",
		map[string]string{"username": "alice2", "password": "password123"}, env.token)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change username status = %d, want 200", resp.StatusCode)
	}
	// The existing token still works and reports the new name.
	if me := getMe(t, env, env.token); me.Username != "alice2" {
		t.Errorf("me username = %q, want alice2", me.Username)
	}
	if loginStatus(t, env, "alice", "password123") != http.StatusUnauthorized {
		t.Error("the old username should no longer log in")
	}
	if loginStatus(t, env, "alice2", "password123") != http.StatusOK {
		t.Error("the new username should log in")
	}
}

type sessionBody struct {
	ID      string `json:"id"`
	Current bool   `json:"current"`
}

func TestSessionsListAndRevoke(t *testing.T) {
	env := newTestEnv(t)
	second := login(t, env, "alice", "password123")

	resp := doAs(t, env, http.MethodGet, "/api/v1/auth/sessions", nil, env.token)
	var list struct {
		Sessions []sessionBody `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	resp.Body.Close()
	if len(list.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(list.Sessions))
	}
	current := 0
	var other string
	for _, s := range list.Sessions {
		if s.Current {
			current++
		} else {
			other = s.ID
		}
	}
	if current != 1 || other == "" {
		t.Fatalf("expected exactly one current session, got %+v", list.Sessions)
	}

	del := doAs(t, env, http.MethodDelete, "/api/v1/auth/sessions/"+other, nil, env.token)
	del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke session status = %d, want 204", del.StatusCode)
	}
	if got := refreshStatus(t, env, second.RefreshToken); got != http.StatusUnauthorized {
		t.Errorf("revoked session refresh status = %d, want 401", got)
	}
}

type patBody struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

func TestPersonalTokens(t *testing.T) {
	env := newTestEnv(t)

	resp := doAs(t, env, http.MethodPost, "/api/v1/auth/tokens", map[string]string{"name": "laptop"}, env.token)
	var pat patBody
	if err := json.NewDecoder(resp.Body).Decode(&pat); err != nil {
		t.Fatalf("decode pat: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || pat.Token == "" {
		t.Fatalf("create token status = %d, token empty = %v", resp.StatusCode, pat.Token == "")
	}

	// The secret authenticates like a session token.
	if got := getStatus(t, env, "/api/v1/auth/me", pat.Token); got != http.StatusOK {
		t.Errorf("PAT status = %d, want 200", got)
	}

	// Listing never returns the secret.
	list := doAs(t, env, http.MethodGet, "/api/v1/auth/tokens", nil, env.token)
	var tokens struct {
		Tokens []patBody `json:"tokens"`
	}
	if err := json.NewDecoder(list.Body).Decode(&tokens); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	list.Body.Close()
	if len(tokens.Tokens) != 1 || tokens.Tokens[0].Token != "" || tokens.Tokens[0].ID != pat.ID {
		t.Errorf("tokens list = %+v", tokens.Tokens)
	}

	revoke := doAs(t, env, http.MethodDelete, "/api/v1/auth/tokens/"+pat.ID, nil, env.token)
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want 204", revoke.StatusCode)
	}
	if got := getStatus(t, env, "/api/v1/auth/me", pat.Token); got != http.StatusUnauthorized {
		t.Errorf("revoked PAT status = %d, want 401", got)
	}
}

type adminUserBody struct {
	UUID      string `json:"uuid"`
	Username  string `json:"username"`
	IsAdmin   bool   `json:"is_admin"`
	Quota     int64  `json:"quota_bytes"`
	UsedBytes int64  `json:"used_bytes"`
}

func TestAdminUserCRUD(t *testing.T) {
	env := newTestEnv(t)

	// Create a non-admin user.
	create := doAs(t, env, http.MethodPost, "/api/v1/users",
		map[string]any{"username": "bob", "password": "password123", "quota_bytes": 1024}, env.token)
	if create.StatusCode != http.StatusCreated {
		t.Fatalf("create user status = %d, want 201", create.StatusCode)
	}
	var bob adminUserBody
	if err := json.NewDecoder(create.Body).Decode(&bob); err != nil {
		t.Fatalf("decode bob: %v", err)
	}
	create.Body.Close()
	if bob.Username != "bob" || bob.IsAdmin || bob.Quota != 1024 {
		t.Errorf("bob = %+v", bob)
	}

	// List and fetch.
	list := doAs(t, env, http.MethodGet, "/api/v1/users", nil, env.token)
	var users struct {
		Users []adminUserBody `json:"users"`
	}
	if err := json.NewDecoder(list.Body).Decode(&users); err != nil {
		t.Fatalf("decode users: %v", err)
	}
	list.Body.Close()
	if len(users.Users) != 2 {
		t.Errorf("users = %d, want 2", len(users.Users))
	}
	got := doAs(t, env, http.MethodGet, "/api/v1/users/"+bob.UUID, nil, env.token)
	got.Body.Close()
	if got.StatusCode != http.StatusOK {
		t.Errorf("get user status = %d, want 200", got.StatusCode)
	}

	// Update quota.
	patch := doAs(t, env, http.MethodPatch, "/api/v1/users/"+bob.UUID,
		map[string]any{"quota_bytes": 2048}, env.token)
	var patched adminUserBody
	if err := json.NewDecoder(patch.Body).Decode(&patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	patch.Body.Close()
	if patched.Quota != 2048 {
		t.Errorf("quota = %d, want 2048", patched.Quota)
	}

	// Rename.
	ren := doAs(t, env, http.MethodPatch, "/api/v1/users/"+bob.UUID,
		map[string]any{"username": "robert"}, env.token)
	var renamed adminUserBody
	if err := json.NewDecoder(ren.Body).Decode(&renamed); err != nil {
		t.Fatalf("decode rename: %v", err)
	}
	ren.Body.Close()
	if renamed.Username != "robert" {
		t.Errorf("renamed username = %q, want robert", renamed.Username)
	}
	if loginStatus(t, env, "robert", "password123") != http.StatusOK {
		t.Error("a renamed user should log in under the new name")
	}

	// Admin password reset works.
	reset := doAs(t, env, http.MethodPost, "/api/v1/users/"+bob.UUID+"/password",
		map[string]string{"password": "brandnew123"}, env.token)
	reset.Body.Close()
	if reset.StatusCode != http.StatusNoContent {
		t.Fatalf("reset status = %d, want 204", reset.StatusCode)
	}
	if loginStatus(t, env, "robert", "brandnew123") != http.StatusOK {
		t.Error("the renamed user should be able to log in with the reset password")
	}

	// Force sign-out, then delete.
	revoke := doAs(t, env, http.MethodPost, "/api/v1/users/"+bob.UUID+"/revoke", nil, env.token)
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusOK {
		t.Errorf("revoke status = %d, want 200", revoke.StatusCode)
	}
	del := doAs(t, env, http.MethodDelete, "/api/v1/users/"+bob.UUID, nil, env.token)
	del.Body.Close()
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", del.StatusCode)
	}
	missing := doAs(t, env, http.MethodGet, "/api/v1/users/"+bob.UUID, nil, env.token)
	missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Errorf("deleted user status = %d, want 404", missing.StatusCode)
	}
}

func TestAdminGuards(t *testing.T) {
	env := newTestEnv(t)
	alice := getMe(t, env, env.token)

	// Cannot demote the last admin.
	demote := doAs(t, env, http.MethodPatch, "/api/v1/users/"+alice.UUID,
		map[string]any{"is_admin": false}, env.token)
	demote.Body.Close()
	if demote.StatusCode != http.StatusConflict {
		t.Errorf("demote last admin status = %d, want 409", demote.StatusCode)
	}
	// Cannot delete self.
	self := doAs(t, env, http.MethodDelete, "/api/v1/users/"+alice.UUID, nil, env.token)
	self.Body.Close()
	if self.StatusCode != http.StatusBadRequest {
		t.Errorf("delete self status = %d, want 400", self.StatusCode)
	}
}

func TestAdminEndpointsForbiddenForNonAdmin(t *testing.T) {
	env := newTestEnv(t)
	create := doAs(t, env, http.MethodPost, "/api/v1/users",
		map[string]any{"username": "bob", "password": "password123"}, env.token)
	var bob adminUserBody
	if err := json.NewDecoder(create.Body).Decode(&bob); err != nil {
		t.Fatalf("decode bob: %v", err)
	}
	create.Body.Close()

	bobToken := login(t, env, "bob", "password123").AccessToken
	resp := doAs(t, env, http.MethodGet, "/api/v1/users", nil, bobToken)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin list status = %d, want 403", resp.StatusCode)
	}
}

func TestRegistrationPolicyOpen(t *testing.T) {
	env := newTestEnvWith(t, func(c *config.Config) { c.Registration = config.RegistrationOpen })
	// A second user may register without an admin token.
	resp := doAs(t, env, http.MethodPost, "/api/v1/auth/register",
		map[string]string{"username": "bob", "password": "password123"}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("open registration status = %d, want 201", resp.StatusCode)
	}
}

func TestRegistrationPolicyClosed(t *testing.T) {
	// Bootstrap the admin first, then switch the policy to closed.
	env := newTestEnv(t)
	env.server.cfg.Registration = config.RegistrationClosed
	resp := doAs(t, env, http.MethodPost, "/api/v1/auth/register",
		map[string]string{"username": "bob", "password": "password123"}, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("closed registration status = %d, want 403", resp.StatusCode)
	}
}

func loginStatus(t *testing.T, env *testEnv, user, pass string) int {
	t.Helper()
	resp := doAs(t, env, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": user, "password": pass}, "")
	resp.Body.Close()
	return resp.StatusCode
}

func getStatus(t *testing.T, env *testEnv, path, token string) int {
	t.Helper()
	resp := doAs(t, env, http.MethodGet, path, nil, token)
	resp.Body.Close()
	return resp.StatusCode
}
