package bolt

import (
	"errors"
	"testing"
	"time"

	"github.com/litemd-hq/litemd/internal/files"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func entry(path string, size int64) *files.Entry {
	return &files.Entry{Path: path, Size: size, SHA256: "sha-" + path, ModTime: time.Now().UTC()}
}

func TestPutFileAssignsIncreasingVersions(t *testing.T) {
	s := testStore(t)

	a := entry("a.md", 1)
	if err := s.PutFile("u1", a); err != nil {
		t.Fatalf("put: %v", err)
	}
	if a.Version == 0 {
		t.Error("PutFile should assign a version")
	}

	b := entry("b.md", 1)
	if err := s.PutFile("u1", b); err != nil {
		t.Fatalf("put: %v", err)
	}
	if b.Version <= a.Version {
		t.Errorf("versions must increase: %d then %d", a.Version, b.Version)
	}
}

func TestPutFileCheckedEnforcesQuota(t *testing.T) {
	s := testStore(t)

	if err := s.PutFileChecked("u1", entry("a.bin", 80), 100); err != nil {
		t.Fatalf("first write should fit: %v", err)
	}

	// 80 + 30 exceeds the 100-byte quota.
	err := s.PutFileChecked("u1", entry("b.bin", 30), 100)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err = %v, want ErrQuotaExceeded", err)
	}
	if _, err := s.GetFile("u1", "b.bin"); !errors.Is(err, ErrNotFound) {
		t.Error("a rejected write must not create an entry")
	}

	// Replacing the existing 80-byte file with 90 counts the difference only.
	if err := s.PutFileChecked("u1", entry("a.bin", 90), 100); err != nil {
		t.Errorf("replacement should fit: %v", err)
	}
}

func TestQuotaIsPerUser(t *testing.T) {
	s := testStore(t)
	if err := s.PutFileChecked("u1", entry("a.bin", 80), 100); err != nil {
		t.Fatal(err)
	}
	// A different user has their own allowance.
	if err := s.PutFileChecked("u2", entry("a.bin", 80), 100); err != nil {
		t.Errorf("second user should have a fresh quota: %v", err)
	}
}

func TestQuotaIgnoresTombstones(t *testing.T) {
	s := testStore(t)

	a := entry("a.bin", 100)
	if err := s.PutFileChecked("u1", a, 100); err != nil {
		t.Fatal(err)
	}
	// Delete it: the tombstone carries no size.
	a.Deleted = true
	a.Size = 0
	if err := s.PutFile("u1", a); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFileChecked("u1", entry("b.bin", 100), 100); err != nil {
		t.Errorf("space should be free after delete: %v", err)
	}
}

func TestManifestIncludesTombstonesOrderedByPath(t *testing.T) {
	s := testStore(t)

	for _, p := range []string{"b.md", "a.md", "c.md"} {
		if err := s.PutFile("u1", entry(p, 1)); err != nil {
			t.Fatal(err)
		}
	}
	c := entry("c.md", 1)
	if err := s.PutFile("u1", c); err != nil { // read current version
		t.Fatal(err)
	}
	cur, err := s.GetFile("u1", "c.md")
	if err != nil {
		t.Fatal(err)
	}
	cur.Deleted = true
	cur.Size = 0
	if err := s.PutFile("u1", cur); err != nil {
		t.Fatal(err)
	}

	got, err := s.Manifest("u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("manifest has %d entries, want 3 (tombstones included)", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Path > got[i].Path {
			t.Errorf("manifest not ordered by path: %q before %q", got[i-1].Path, got[i].Path)
		}
	}
	last := got[len(got)-1]
	if last.Path != "c.md" || !last.Deleted {
		t.Errorf("expected a c.md tombstone, got %+v", last)
	}
}

func TestManifestsAreIsolatedPerUser(t *testing.T) {
	s := testStore(t)
	if err := s.PutFile("u1", entry("only-u1.md", 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFile("u2", entry("only-u2.md", 1)); err != nil {
		t.Fatal(err)
	}

	one, _ := s.Manifest("u1")
	if len(one) != 1 || one[0].Path != "only-u1.md" {
		t.Errorf("u1 manifest = %+v", one)
	}
	two, _ := s.Manifest("u2")
	if len(two) != 1 || two[0].Path != "only-u2.md" {
		t.Errorf("u2 manifest = %+v", two)
	}
}

func TestIndexMaintainedAcrossWrites(t *testing.T) {
	s := testStore(t)

	e := entry("note.md", 5)
	e.Metadata = &files.MarkdownMetadata{Tags: []string{"alpha", "beta"}}
	e.Links = []string{"Other"}
	if err := s.PutFile("u1", e); err != nil {
		t.Fatal(err)
	}

	tags, err := s.Tags("u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 {
		t.Fatalf("tags = %+v, want 2", tags)
	}

	back, err := s.Backlinks("u1", files.LinkKey("Other"))
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 || back[0] != "note.md" {
		t.Errorf("backlinks = %v, want [note.md]", back)
	}

	// Replacing the entry drops the stale index rows.
	updated := entry("note.md", 5)
	updated.Metadata = &files.MarkdownMetadata{Tags: []string{"gamma"}}
	if err := s.PutFile("u1", updated); err != nil {
		t.Fatal(err)
	}
	tags, _ = s.Tags("u1")
	if len(tags) != 1 || tags[0].Tag != "gamma" {
		t.Errorf("tags after update = %+v, want just gamma", tags)
	}
	if back, _ := s.Backlinks("u1", files.LinkKey("Other")); len(back) != 0 {
		t.Errorf("stale backlink survived: %v", back)
	}
}

func TestRevokeAllForUserIsScoped(t *testing.T) {
	s := testStore(t)

	for _, rec := range []struct{ hash, user, family string }{
		{"h1", "u1", "f1"},
		{"h2", "u1", "f2"},
		{"h3", "u2", "f3"},
	} {
		if err := s.PutSession(&SessionMeta{
			UserUUID: rec.user, Family: rec.family, CreatedAt: time.Now(), LastSeen: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveRefresh(rec.hash, &RefreshRecord{
			UserUUID: rec.user, Family: rec.family, Expires: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.RevokeAllForUser("u1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("revoked = %d, want 2", n)
	}
	if _, err := s.GetRefresh("h3"); err != nil {
		t.Errorf("another user's token was revoked: %v", err)
	}
	if _, err := s.GetRefresh("h1"); !errors.Is(err, ErrNotFound) {
		t.Error("u1's token should be gone")
	}
	if _, err := s.GetSession("f1"); !errors.Is(err, ErrNotFound) {
		t.Error("u1's session should be gone")
	}
	if _, err := s.GetSession("f3"); err != nil {
		t.Errorf("another user's session was revoked: %v", err)
	}
}

func TestUsernameIsUniqueCaseSensitively(t *testing.T) {
	s := testStore(t)
	u := &User{UUID: "id1", Username: "alice", Argon2: "x", Quota: 1, CreatedAt: time.Now()}
	if err := s.CreateUser(u, true, true); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.CreateUser(&User{UUID: "id2", Username: "alice", Argon2: "y", Quota: 1}, true, true); err == nil {
		t.Error("duplicate username should be rejected")
	}
	n, err := s.CountUsers()
	if err != nil || n != 1 {
		t.Errorf("CountUsers = %d, %v; want 1", n, err)
	}
	got, err := s.UserByUsername("alice")
	if err != nil || got.UUID != "id1" {
		t.Errorf("UserByUsername = %+v, %v", got, err)
	}
}

func TestCreateUserRegistrationGate(t *testing.T) {
	s := testStore(t)

	// The first user is always allowed and always becomes the admin.
	first := &User{UUID: "id1", Username: "alice", Argon2: "x"}
	if err := s.CreateUser(first, false, false); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if !first.IsAdmin {
		t.Error("the first user must become the admin")
	}

	// A later self-registration is refused under the admin policy.
	if err := s.CreateUser(&User{UUID: "id2", Username: "bob", Argon2: "y"}, false, false); !errors.Is(err, ErrRegistrationClosed) {
		t.Errorf("second create err = %v, want ErrRegistrationClosed", err)
	}
	// An admin-authorized create is allowed.
	if err := s.CreateUser(&User{UUID: "id2", Username: "bob", Argon2: "y"}, true, false); err != nil {
		t.Errorf("admin create: %v", err)
	}
	// The open policy allows anyone.
	if err := s.CreateUser(&User{UUID: "id3", Username: "carol", Argon2: "z"}, false, true); err != nil {
		t.Errorf("open create: %v", err)
	}
}

func TestUpdateUserGuardsLastAdmin(t *testing.T) {
	s := testStore(t)
	if err := s.CreateUser(&User{UUID: "id1", Username: "alice"}, true, true); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(&User{UUID: "id2", Username: "bob", IsAdmin: true}, true, true); err != nil {
		t.Fatal(err)
	}
	no := false
	// Demoting one of two admins is fine.
	if _, err := s.UpdateUser("id2", nil, &no); err != nil {
		t.Fatalf("demote one admin: %v", err)
	}
	// Demoting the last admin is refused.
	if _, err := s.UpdateUser("id1", nil, &no); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demote last admin err = %v, want ErrLastAdmin", err)
	}
	// Deleting the last admin is refused too.
	if err := s.DeleteUser("id1"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("delete last admin err = %v, want ErrLastAdmin", err)
	}
}

func TestUpdateUserUsername(t *testing.T) {
	s := testStore(t)
	if err := s.CreateUser(&User{UUID: "id1", Username: "alice"}, true, true); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(&User{UUID: "id2", Username: "bob"}, true, true); err != nil {
		t.Fatal(err)
	}

	u, err := s.UpdateUserUsername("id1", "alice2")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if u.Username != "alice2" {
		t.Errorf("username = %q, want alice2", u.Username)
	}
	// The old name is free and the new one resolves.
	if _, err := s.UserByUsername("alice"); !errors.Is(err, ErrNotFound) {
		t.Error("the old name should be free after a rename")
	}
	if got, err := s.UserByUsername("alice2"); err != nil || got.UUID != "id1" {
		t.Errorf("lookup by new name = %+v, %v", got, err)
	}
	// A name in use is rejected.
	if _, err := s.UpdateUserUsername("id1", "bob"); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("collision err = %v, want ErrUsernameTaken", err)
	}
	// Renaming to the current name is a no-op.
	if _, err := s.UpdateUserUsername("id1", "alice2"); err != nil {
		t.Errorf("same-name rename: %v", err)
	}
	// An unknown user is reported.
	if _, err := s.UpdateUserUsername("nobody", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user err = %v, want ErrNotFound", err)
	}
}

func TestDeleteUserCascades(t *testing.T) {
	s := testStore(t)
	// A second admin exists so deleting alice is not blocked by the last-admin guard.
	if err := s.CreateUser(&User{UUID: "id0", Username: "root", IsAdmin: true}, true, true); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(&User{UUID: "id1", Username: "alice"}, true, true); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFile("id1", entry("note.md", 10)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSession(&SessionMeta{UserUUID: "id1", Family: "fam", CreatedAt: time.Now(), LastSeen: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRefresh("rh", &RefreshRecord{UserUUID: "id1", Family: "fam", Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePAT("ph", &PATRecord{ID: "pat1", UserUUID: "id1", Name: "laptop", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteUser("id1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.UserByUUID("id1"); !errors.Is(err, ErrNotFound) {
		t.Error("user should be gone")
	}
	if _, err := s.UserByUsername("alice"); !errors.Is(err, ErrNotFound) {
		t.Error("username index should be gone")
	}
	if manifest, _ := s.Manifest("id1"); len(manifest) != 0 {
		t.Errorf("files survived delete: %v", manifest)
	}
	if _, err := s.GetSession("fam"); !errors.Is(err, ErrNotFound) {
		t.Error("session survived delete")
	}
	if _, err := s.GetRefresh("rh"); !errors.Is(err, ErrNotFound) {
		t.Error("refresh token survived delete")
	}
	if _, err := s.GetPAT("ph"); !errors.Is(err, ErrNotFound) {
		t.Error("personal token survived delete")
	}
}

func TestPurgeExpiredRemovesDeadRecords(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	past := now.Add(-time.Hour)

	if err := s.SaveAccess("dead-access", &AccessRecord{UserUUID: "u", Family: "f", Expires: past}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRefresh("dead-refresh", &RefreshRecord{UserUUID: "u", Family: "f", Expires: past}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSession(&SessionMeta{UserUUID: "u", Family: "f", CreatedAt: past, LastSeen: past}); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePAT("dead-pat", &PATRecord{ID: "p", UserUUID: "u", Expires: past}); err != nil {
		t.Fatal(err)
	}

	n, err := s.PurgeExpired(now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 {
		t.Errorf("purged = %d, want >= 4", n)
	}
	if _, err := s.GetAccess("dead-access"); !errors.Is(err, ErrNotFound) {
		t.Error("expired access token survived")
	}
	if _, err := s.GetRefresh("dead-refresh"); !errors.Is(err, ErrNotFound) {
		t.Error("expired refresh token survived")
	}
	if _, err := s.GetSession("f"); !errors.Is(err, ErrNotFound) {
		t.Error("stale session survived")
	}
	if _, err := s.GetPAT("dead-pat"); !errors.Is(err, ErrNotFound) {
		t.Error("expired personal token survived")
	}
}
