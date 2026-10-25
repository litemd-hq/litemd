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
}

func TestUsernameIsUniqueCaseSensitively(t *testing.T) {
	s := testStore(t)
	u := &User{UUID: "id1", Username: "alice", Argon2: "x", Quota: 1, CreatedAt: time.Now()}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.CreateUser(&User{UUID: "id2", Username: "alice", Argon2: "y", Quota: 1}); err == nil {
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

func TestJWTSecretIsStable(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.JWTSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 {
		t.Errorf("secret length = %d, want 32", len(first))
	}
	_ = s.Close()

	// Reopening must return the same secret, or every token would be invalidated.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	second, err := s2.JWTSecret()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("JWT secret changed across restarts")
	}
}
