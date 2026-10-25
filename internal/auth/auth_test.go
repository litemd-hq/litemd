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

func TestRegisterLoginAndParse(t *testing.T) {
	svc, _ := newTestService(t)

	u, err := svc.Register("alice", "password123", 1024)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !u.IsAdmin {
		t.Error("first user should be admin")
	}

	pair, err := svc.Login("alice", "password123")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	sub, err := svc.ParseAccess(pair.AccessToken)
	if err != nil {
		t.Fatalf("parse access: %v", err)
	}
	if sub != u.UUID {
		t.Errorf("subject = %q, want %q", sub, u.UUID)
	}
	if _, err := svc.ParseAccess(pair.AccessToken + "x"); err == nil {
		t.Error("tampered access token should not parse")
	}
}

func TestLoginFailures(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.Register("alice", "password123", 1024); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login("alice", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.Login("nobody", "password123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user err = %v, want ErrInvalidCredentials", err)
	}
}

func TestDuplicateUsername(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.Register("alice", "password123", 1024); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Register("alice", "password456", 1024); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("err = %v, want ErrUsernameTaken", err)
	}
}

func TestRefreshRotationAndTheftDetection(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.Register("alice", "password123", 1024); err != nil {
		t.Fatal(err)
	}
	first, err := svc.Login("alice", "password123")
	if err != nil {
		t.Fatal(err)
	}

	second, err := svc.Refresh(first.RefreshToken)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("refresh token should rotate")
	}

	// Re-presenting a consumed token signals theft: revoke the whole family.
	if _, err := svc.Refresh(first.RefreshToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("reuse err = %v, want ErrTokenRevoked", err)
	}
	// The sibling token from the same family must now be dead too.
	if _, err := svc.Refresh(second.RefreshToken); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("family token err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLogoutRevokesOneToken(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.Register("alice", "password123", 1024); err != nil {
		t.Fatal(err)
	}
	a, _ := svc.Login("alice", "password123")
	b, _ := svc.Login("alice", "password123")

	if err := svc.Logout(a.RefreshToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := svc.Refresh(a.RefreshToken); err == nil {
		t.Error("logged-out token should not refresh")
	}
	if _, err := svc.Refresh(b.RefreshToken); err != nil {
		t.Errorf("other session should survive: %v", err)
	}
}

func TestRevokeAllEndsEverySession(t *testing.T) {
	svc, _ := newTestService(t)
	u, err := svc.Register("alice", "password123", 1024)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := svc.Login("alice", "password123")
	b, _ := svc.Login("alice", "password123")

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
