package auth

import (
	"errors"
	"testing"
	"time"

	bolt "github.com/litemd-hq/litemd/internal/bolt"
)

func newTestService(t *testing.T) (*Service, *bolt.Store) {
	t.Helper()
	store, err := bolt.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	svc, err := NewService(store, time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, store
}

func register(t *testing.T, svc *Service, name, pass string) *bolt.User {
	t.Helper()
	u, err := svc.Register(RegisterOptions{Username: name, Password: pass, Quota: 1024, Open: true})
	if err != nil {
		t.Fatalf("register %q: %v", name, err)
	}
	return u
}

func login(t *testing.T, svc *Service, name, pass string) *TokenPair {
	t.Helper()
	pair, err := svc.Login(name, pass, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("login %q: %v", name, err)
	}
	return pair
}

func TestRegisterLoginAndAuthenticate(t *testing.T) {
	svc, _ := newTestService(t)

	u, err := svc.Register(RegisterOptions{Username: "alice", Password: "password123", Quota: 1024})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !u.IsAdmin {
		t.Error("first user should be admin")
	}

	pair := login(t, svc, "alice", "password123")
	got, family, err := svc.Authenticate(pair.AccessToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.UUID != u.UUID {
		t.Errorf("user = %q, want %q", got.UUID, u.UUID)
	}
	if family == "" {
		t.Error("access token should carry a session family")
	}
	if _, _, err := svc.Authenticate(pair.AccessToken + "x"); err == nil {
		t.Error("tampered access token should not authenticate")
	}
}

func TestLoginFailures(t *testing.T) {
	svc, _ := newTestService(t)
	register(t, svc, "alice", "password123")
	if _, err := svc.Login("alice", "wrong-password", "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.Login("nobody", "password123", "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user err = %v, want ErrInvalidCredentials", err)
	}
}

func TestDuplicateUsername(t *testing.T) {
	svc, _ := newTestService(t)
	register(t, svc, "alice", "password123")
	if _, err := svc.Register(RegisterOptions{Username: "alice", Password: "password456", Open: true}); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("err = %v, want ErrUsernameTaken", err)
	}
}

func TestRegistrationGate(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.Register(RegisterOptions{Username: "alice", Password: "password123"}); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if _, err := svc.Register(RegisterOptions{Username: "bob", Password: "password123"}); !errors.Is(err, ErrRegistrationClosed) {
		t.Errorf("err = %v, want ErrRegistrationClosed", err)
	}
	if _, err := svc.Register(RegisterOptions{Username: "bob", Password: "password123", AdminAuthorized: true}); err != nil {
		t.Errorf("admin register: %v", err)
	}
}

func TestRefreshRotationAndTheftDetection(t *testing.T) {
	svc, _ := newTestService(t)
	register(t, svc, "alice", "password123")
	first := login(t, svc, "alice", "password123")

	second, err := svc.Refresh(first.RefreshToken)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("refresh token should rotate")
	}

	// Re-presenting a consumed token signals theft: revoke the whole session.
	if _, err := svc.Refresh(first.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("reuse err = %v, want ErrTokenRevoked", err)
	}
	// The sibling token from the same session must now be dead too.
	if _, err := svc.Refresh(second.RefreshToken); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("session token err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	svc, _ := newTestService(t)
	register(t, svc, "alice", "password123")
	a := login(t, svc, "alice", "password123")
	b := login(t, svc, "alice", "password123")

	if err := svc.Logout(a.RefreshToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	// The refresh token is gone and the access token dies with the session.
	if _, err := svc.Refresh(a.RefreshToken); err == nil {
		t.Error("logged-out token should not refresh")
	}
	if _, _, err := svc.Authenticate(a.AccessToken); err == nil {
		t.Error("logged-out access token should not authenticate")
	}
	if _, err := svc.Refresh(b.RefreshToken); err != nil {
		t.Errorf("other session should survive: %v", err)
	}
}

func TestRevokeAllEndsEverySession(t *testing.T) {
	svc, _ := newTestService(t)
	u := register(t, svc, "alice", "password123")
	a := login(t, svc, "alice", "password123")
	b := login(t, svc, "alice", "password123")

	n, err := svc.RevokeAll(u.UUID)
	if err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	if n < 2 {
		t.Errorf("revoked = %d, want >= 2", n)
	}
	for _, p := range []*TokenPair{a, b} {
		if _, err := svc.Refresh(p.RefreshToken); err == nil {
			t.Error("refresh should fail after revoke-all")
		}
		if _, _, err := svc.Authenticate(p.AccessToken); err == nil {
			t.Error("access token should fail after revoke-all")
		}
	}
}

func TestRevokeSessionInvalidatesAccessToken(t *testing.T) {
	svc, _ := newTestService(t)
	u := register(t, svc, "alice", "password123")
	pair := login(t, svc, "alice", "password123")

	_, family, err := svc.Authenticate(pair.AccessToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if err := svc.RevokeSession(u.UUID, family); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if _, _, err := svc.Authenticate(pair.AccessToken); err == nil {
		t.Error("access token should be invalid after its session is revoked")
	}
}

func TestChangePasswordRevokesSessions(t *testing.T) {
	svc, _ := newTestService(t)
	u := register(t, svc, "alice", "password123")
	old := login(t, svc, "alice", "password123")

	fresh, err := svc.ChangePassword(u.UUID, "password123", "newpassword456", "agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, _, err := svc.Authenticate(old.AccessToken); err == nil {
		t.Error("old access token should be revoked after a password change")
	}
	if _, err := svc.Login("alice", "password123", "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("old password should no longer work")
	}
	if _, _, err := svc.Authenticate(fresh.AccessToken); err != nil {
		t.Errorf("fresh token should authenticate: %v", err)
	}
	if _, err := svc.Login("alice", "newpassword456", "", ""); err != nil {
		t.Errorf("new password should work: %v", err)
	}
}

func TestChangeUsername(t *testing.T) {
	svc, _ := newTestService(t)
	u := register(t, svc, "alice", "password123")
	register(t, svc, "bob", "password123")

	if _, err := svc.ChangeUsername(u.UUID, "wrong", "alice2"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.ChangeUsername(u.UUID, "password123", "bob"); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("taken name err = %v, want ErrUsernameTaken", err)
	}
	got, err := svc.ChangeUsername(u.UUID, "password123", "alice2")
	if err != nil {
		t.Fatalf("change username: %v", err)
	}
	if got.Username != "alice2" {
		t.Errorf("username = %q, want alice2", got.Username)
	}
	// The account still logs in under the new name, and existing tokens survive.
	if _, err := svc.Login("alice2", "password123", "", ""); err != nil {
		t.Errorf("login with the new name: %v", err)
	}
}

func TestChangePasswordRejectsWrongCurrent(t *testing.T) {
	svc, _ := newTestService(t)
	u := register(t, svc, "alice", "password123")
	if _, err := svc.ChangePassword(u.UUID, "wrong", "newpassword456", "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestPersonalTokenAuthenticates(t *testing.T) {
	svc, _ := newTestService(t)
	u := register(t, svc, "alice", "password123")

	secret, rec, err := svc.CreatePAT(u.UUID, "laptop", 0)
	if err != nil {
		t.Fatalf("create pat: %v", err)
	}
	got, family, err := svc.Authenticate(secret)
	if err != nil {
		t.Fatalf("authenticate pat: %v", err)
	}
	if got.UUID != u.UUID {
		t.Errorf("user = %q, want %q", got.UUID, u.UUID)
	}
	if family != "" {
		t.Error("a personal token has no session family")
	}

	if err := svc.RevokePAT(u.UUID, rec.ID); err != nil {
		t.Fatalf("revoke pat: %v", err)
	}
	if _, _, err := svc.Authenticate(secret); err == nil {
		t.Error("revoked personal token should not authenticate")
	}
}

func TestHashPassword(t *testing.T) {
	h, err := HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "password123") {
		t.Error("correct password rejected")
	}
	if VerifyPassword(h, "wrong") {
		t.Error("wrong password accepted")
	}
	if VerifyPassword("not-a-hash", "password123") {
		t.Error("malformed hash accepted")
	}
	if VerifyPassword("", "") {
		t.Error("empty hash accepted")
	}
}
