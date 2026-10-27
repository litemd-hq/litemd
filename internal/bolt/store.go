// Package bolt wraps the embedded bbolt database holding users, login sessions
// (access and refresh tokens), personal API tokens, the per-file index and a
// global monotonic version counter.
package bolt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/litemd-hq/litemd/internal/files"
)

var (
	BucketUsers        = []byte("users")        // userUUID -> User (JSON)
	BucketNames        = []byte("usernames")    // username -> userUUID
	BucketRefresh      = []byte("refresh")      // sha256(refresh) -> RefreshRecord (JSON)
	BucketAccess       = []byte("access")       // sha256(access) -> AccessRecord (JSON)
	BucketSessions     = []byte("sessions")     // family -> SessionMeta (JSON)
	BucketUserSessions = []byte("usersessions") // userUUID\x00family -> {1}
	BucketRefreshFam   = []byte("refreshfam")   // family\x00sha256(refresh) -> {1}
	BucketPATs         = []byte("pats")         // sha256(pat) -> PATRecord (JSON)
	BucketPATIndex     = []byte("patindex")     // userUUID\x00patID -> sha256(pat)
	BucketFiles        = []byte("files")        // userUUID\x00path -> files.Entry (JSON)
	BucketTags         = []byte("tags")         // userUUID\x00tag\x00path -> {1}
	BucketBacklinks    = []byte("backlinks")    // userUUID\x00targetKey\x00sourcePath -> {1}
	BucketFolders      = []byte("folders")      // userUUID\x00path -> files.Folder (JSON)
	BucketMeta         = []byte("meta")         // versions, auth schema version

	fileKeySep = []byte{0}
)

var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrQuotaExceeded = errors.New("storage quota exceeded")
	// ErrMoveCollision reports that a folder move would overwrite a live file
	// or folder at one of the destination paths.
	ErrMoveCollision = errors.New("destination path already exists")
	// ErrUsernameTaken reports that a username is already registered.
	ErrUsernameTaken = errors.New("username already taken")
	// ErrRegistrationClosed reports that self-registration was refused because
	// the store already holds a user and no admin authorized the request.
	ErrRegistrationClosed = errors.New("registration is closed")
	// ErrLastAdmin reports an attempt to remove the only administrator.
	ErrLastAdmin = errors.New("cannot remove the last administrator")
)

type Store struct {
	DB *bolt.DB
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dataDir, "litemd.db"), 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{
			BucketUsers, BucketNames, BucketRefresh, BucketAccess, BucketSessions,
			BucketUserSessions, BucketRefreshFam, BucketPATs, BucketPATIndex,
			BucketFiles, BucketTags, BucketBacklinks, BucketFolders, BucketMeta,
		} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return backfillAuthTx(tx)
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db}, nil
}

func (s *Store) Close() error { return s.DB.Close() }

// --- users ---

type User struct {
	UUID      string    `json:"uuid"`
	Username  string    `json:"username"`
	Argon2    string    `json:"argon2"`
	Quota     int64     `json:"quota"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.DB.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(BucketUsers).Stats().KeyN
		return nil
	})
	return n, err
}

// CreateUser stores a user. The first user ever written always becomes an
// admin and is always allowed, which makes the bootstrap decision atomic: the
// user count and the write happen in one transaction, so concurrent first
// registrations cannot both slip through. Once the store holds a user, a
// request is accepted only when admin authorized it or the open policy is on;
// otherwise it fails with ErrRegistrationClosed.
func (s *Store) CreateUser(u *User, adminAuthorized, open bool) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(BucketUsers)
		names := tx.Bucket(BucketNames)
		if names.Get([]byte(u.Username)) != nil {
			return ErrUsernameTaken
		}
		if users.Get([]byte(u.UUID)) != nil {
			return fmt.Errorf("user uuid collision")
		}
		if n := users.Stats().KeyN; n == 0 {
			u.IsAdmin = true
		} else if !adminAuthorized && !open {
			return ErrRegistrationClosed
		}
		raw, err := json.Marshal(u)
		if err != nil {
			return err
		}
		if err := users.Put([]byte(u.UUID), raw); err != nil {
			return err
		}
		return names.Put([]byte(u.Username), []byte(u.UUID))
	})
}

// ListUsers returns every user, ordered by creation time then username.
func (s *Store) ListUsers() ([]User, error) {
	var out []User
	err := s.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(BucketUsers).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				return err
			}
			out = append(out, u)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Username < out[j].Username
	})
	return out, nil
}

// UpdateUser applies a partial update. A nil field is left unchanged. Quota 0
// means unlimited. Demoting the last administrator fails with ErrLastAdmin.
func (s *Store) UpdateUser(userUUID string, quota *int64, isAdmin *bool) (*User, error) {
	var out User
	err := s.DB.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(BucketUsers)
		raw := users.Get([]byte(userUUID))
		if raw == nil {
			return ErrNotFound
		}
		var u User
		if err := json.Unmarshal(raw, &u); err != nil {
			return err
		}
		if isAdmin != nil {
			if u.IsAdmin && !*isAdmin && adminCountTx(tx) <= 1 {
				return ErrLastAdmin
			}
			u.IsAdmin = *isAdmin
		}
		if quota != nil {
			u.Quota = *quota
		}
		raw, err := json.Marshal(&u)
		if err != nil {
			return err
		}
		if err := users.Put([]byte(userUUID), raw); err != nil {
			return err
		}
		out = u
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateUserUsername renames a user, keeping the username index consistent. The
// request fails with ErrUsernameTaken when the new name is in use. Tokens are
// keyed by UUID, so renaming does not invalidate any session.
func (s *Store) UpdateUserUsername(userUUID, newUsername string) (*User, error) {
	var out User
	err := s.DB.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(BucketUsers)
		names := tx.Bucket(BucketNames)
		raw := users.Get([]byte(userUUID))
		if raw == nil {
			return ErrNotFound
		}
		var u User
		if err := json.Unmarshal(raw, &u); err != nil {
			return err
		}
		if u.Username == newUsername {
			out = u
			return nil
		}
		if names.Get([]byte(newUsername)) != nil {
			return ErrUsernameTaken
		}
		if err := names.Delete([]byte(u.Username)); err != nil {
			return err
		}
		if err := names.Put([]byte(newUsername), []byte(userUUID)); err != nil {
			return err
		}
		u.Username = newUsername
		encoded, err := json.Marshal(&u)
		if err != nil {
			return err
		}
		if err := users.Put([]byte(userUUID), encoded); err != nil {
			return err
		}
		out = u
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// SetUserPassword replaces a user's password hash without touching sessions.
func (s *Store) SetUserPassword(userUUID, argon2 string) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(BucketUsers)
		raw := users.Get([]byte(userUUID))
		if raw == nil {
			return ErrNotFound
		}
		var u User
		if err := json.Unmarshal(raw, &u); err != nil {
			return err
		}
		u.Argon2 = argon2
		raw, err := json.Marshal(&u)
		if err != nil {
			return err
		}
		return users.Put([]byte(userUUID), raw)
	})
}

func adminCountTx(tx *bolt.Tx) int {
	n := 0
	c := tx.Bucket(BucketUsers).Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var u User
		if err := json.Unmarshal(v, &u); err != nil {
			continue
		}
		if u.IsAdmin {
			n++
		}
	}
	return n
}

// DeleteUser removes a user and every record they own: credentials, sessions
// and personal tokens, file and folder records, and the derived tag/backlink
// indexes, all in one transaction. The on-disk files are removed by the caller.
// Deleting the last administrator fails with ErrLastAdmin.
func (s *Store) DeleteUser(userUUID string) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(BucketUsers)
		raw := users.Get([]byte(userUUID))
		if raw == nil {
			return ErrNotFound
		}
		var u User
		if err := json.Unmarshal(raw, &u); err != nil {
			return err
		}
		if u.IsAdmin && adminCountTx(tx) <= 1 {
			return ErrLastAdmin
		}
		if err := tx.Bucket(BucketNames).Delete([]byte(u.Username)); err != nil {
			return err
		}
		if err := revokeAllFamiliesTx(tx, userUUID); err != nil {
			return err
		}
		if err := deletePATsTx(tx, userUUID); err != nil {
			return err
		}
		prefix := append([]byte(userUUID), fileKeySep...)
		for _, b := range [][]byte{BucketFiles, BucketFolders, BucketTags, BucketBacklinks} {
			if err := deletePrefixTx(tx, b, prefix); err != nil {
				return err
			}
		}
		return users.Delete([]byte(userUUID))
	})
}

// deletePrefixTx removes every key in bucket beginning with prefix.
func deletePrefixTx(tx *bolt.Tx, bucket, prefix []byte) error {
	b := tx.Bucket(bucket)
	var keys [][]byte
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, _ = c.Next() {
		keys = append(keys, append([]byte(nil), k...))
	}
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UserByUUID(uuid string) (*User, error) {
	return s.user(func(tx *bolt.Tx) []byte {
		return tx.Bucket(BucketUsers).Get([]byte(uuid))
	})
}

func (s *Store) UserByUsername(name string) (*User, error) {
	return s.user(func(tx *bolt.Tx) []byte {
		uuid := tx.Bucket(BucketNames).Get([]byte(name))
		if uuid == nil {
			return nil
		}
		return tx.Bucket(BucketUsers).Get(uuid)
	})
}

func (s *Store) user(get func(*bolt.Tx) []byte) (*User, error) {
	var u *User
	err := s.DB.View(func(tx *bolt.Tx) error {
		raw := get(tx)
		if raw == nil {
			return ErrNotFound
		}
		u = &User{}
		return json.Unmarshal(raw, u)
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// --- sessions, access tokens and refresh tokens ---
//
// A login creates a "session" identified by a random family id. The session
// owns short-lived access tokens (opaque, stored hashed) and a rotating refresh
// token. An access token is honored only while its session row still exists, so
// deleting the session revokes every access token of that session immediately,
// with no expiry window.

type RefreshRecord struct {
	UserUUID string    `json:"user_uuid"`
	Family   string    `json:"family"`
	Expires  time.Time `json:"expires"`
	// Rotated marks a token that has already been exchanged for a newer one.
	// Presenting it again is theft: the whole family gets revoked.
	Rotated bool `json:"rotated,omitempty"`
}

// AccessRecord is one issued access token, keyed by its hash.
type AccessRecord struct {
	UserUUID string    `json:"user_uuid"`
	Family   string    `json:"family"`
	Expires  time.Time `json:"expires"`
}

// SessionMeta is the canonical record for a login session ("family"). It is the
// row a session listing shows and the row whose deletion revokes the session:
// access tokens are only honored while their session row exists.
type SessionMeta struct {
	UserUUID  string    `json:"user_uuid"`
	Family    string    `json:"family"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	UserAgent string    `json:"user_agent,omitempty"`
	IP        string    `json:"ip,omitempty"`
}

// PATRecord is a personal API token. It authenticates as its owner but is never
// refreshed; it lives until revoked or until Expires (zero means no expiry).
type PATRecord struct {
	ID        string    `json:"id"`
	UserUUID  string    `json:"user_uuid"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	Expires   time.Time `json:"expires,omitempty"`
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func sessionIndexKey(userUUID, family string) []byte {
	return append(append([]byte(userUUID), fileKeySep...), []byte(family)...)
}

func refreshFamilyKey(family, tokenHash string) []byte {
	return append(append([]byte(family), fileKeySep...), []byte(tokenHash)...)
}

func patIndexKey(userUUID, id string) []byte {
	return append(append([]byte(userUUID), fileKeySep...), []byte(id)...)
}

func putRefreshTx(tx *bolt.Tx, tokenHash string, rec *RefreshRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := tx.Bucket(BucketRefresh).Put([]byte(tokenHash), raw); err != nil {
		return err
	}
	return tx.Bucket(BucketRefreshFam).Put(refreshFamilyKey(rec.Family, tokenHash), indexMarker)
}

func deleteRefreshTx(tx *bolt.Tx, tokenHash string, rec *RefreshRecord) error {
	if err := tx.Bucket(BucketRefresh).Delete([]byte(tokenHash)); err != nil {
		return err
	}
	return tx.Bucket(BucketRefreshFam).Delete(refreshFamilyKey(rec.Family, tokenHash))
}

func putAccessTx(tx *bolt.Tx, tokenHash string, rec *AccessRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return tx.Bucket(BucketAccess).Put([]byte(tokenHash), raw)
}

func putSessionTx(tx *bolt.Tx, m *SessionMeta) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := tx.Bucket(BucketSessions).Put([]byte(m.Family), raw); err != nil {
		return err
	}
	return tx.Bucket(BucketUserSessions).Put(sessionIndexKey(m.UserUUID, m.Family), indexMarker)
}

func touchSessionTx(tx *bolt.Tx, family string, seen time.Time) error {
	b := tx.Bucket(BucketSessions)
	raw := b.Get([]byte(family))
	if raw == nil {
		return nil
	}
	var m SessionMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	m.LastSeen = seen
	raw, err := json.Marshal(&m)
	if err != nil {
		return err
	}
	return b.Put([]byte(family), raw)
}

// revokeFamilyTx deletes a session: the session row (which invalidates every
// access token of the family) and every refresh token in the family. It returns
// the number of refresh tokens removed.
func revokeFamilyTx(tx *bolt.Tx, userUUID, family string) (int, error) {
	if err := tx.Bucket(BucketSessions).Delete([]byte(family)); err != nil {
		return 0, err
	}
	if userUUID != "" {
		if err := tx.Bucket(BucketUserSessions).Delete(sessionIndexKey(userUUID, family)); err != nil {
			return 0, err
		}
	}
	famB := tx.Bucket(BucketRefreshFam)
	refB := tx.Bucket(BucketRefresh)
	prefix := append([]byte(family), fileKeySep...)
	var hashes [][]byte
	c := famB.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, _ = c.Next() {
		hashes = append(hashes, append([]byte(nil), k[len(prefix):]...))
	}
	for _, h := range hashes {
		if err := refB.Delete(h); err != nil {
			return 0, err
		}
		if err := famB.Delete(refreshFamilyKey(family, string(h))); err != nil {
			return 0, err
		}
	}
	return len(hashes), nil
}

// revokeAllFamiliesTx revokes every session owned by userUUID.
func revokeAllFamiliesTx(tx *bolt.Tx, userUUID string) error {
	prefix := append([]byte(userUUID), fileKeySep...)
	var families []string
	c := tx.Bucket(BucketUserSessions).Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, _ = c.Next() {
		families = append(families, string(k[len(prefix):]))
	}
	for _, f := range families {
		if _, err := revokeFamilyTx(tx, userUUID, f); err != nil {
			return err
		}
	}
	return nil
}

// PutTokens installs a fresh access/refresh pair in one transaction.
func (s *Store) PutTokens(accessHash string, access *AccessRecord, refreshHash string, refresh *RefreshRecord) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		if err := putAccessTx(tx, accessHash, access); err != nil {
			return err
		}
		return putRefreshTx(tx, refreshHash, refresh)
	})
}

// RotateRefresh atomically consumes oldHash and installs the successor refresh
// and access tokens, so a crash cannot leave a consumed token without a
// replacement. The consumed token is kept (marked rotated) for theft detection
// until it expires.
func (s *Store) RotateRefresh(oldHash string, old *RefreshRecord, newHash string, next *RefreshRecord, accessHash string, access *AccessRecord, seen time.Time) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		old.Rotated = true
		if err := putRefreshTx(tx, oldHash, old); err != nil {
			return err
		}
		if err := putRefreshTx(tx, newHash, next); err != nil {
			return err
		}
		if err := putAccessTx(tx, accessHash, access); err != nil {
			return err
		}
		return touchSessionTx(tx, next.Family, seen)
	})
}

// SaveRefresh stores a refresh token by hash.
func (s *Store) SaveRefresh(tokenHash string, rec *RefreshRecord) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		return putRefreshTx(tx, tokenHash, rec)
	})
}

// GetRefresh looks up a refresh token by hash.
func (s *Store) GetRefresh(tokenHash string) (*RefreshRecord, error) {
	var rec *RefreshRecord
	err := s.DB.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketRefresh).Get([]byte(tokenHash))
		if raw == nil {
			return ErrNotFound
		}
		rec = &RefreshRecord{}
		return json.Unmarshal(raw, rec)
	})
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// DeleteRefresh removes a refresh token and its family index entry.
func (s *Store) DeleteRefresh(tokenHash string) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketRefresh).Get([]byte(tokenHash))
		if raw == nil {
			return nil
		}
		var rec RefreshRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		return deleteRefreshTx(tx, tokenHash, &rec)
	})
}

// SaveAccess stores a short-lived access token by hash.
func (s *Store) SaveAccess(tokenHash string, rec *AccessRecord) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		return putAccessTx(tx, tokenHash, rec)
	})
}

// GetAccess looks up an access token by hash.
func (s *Store) GetAccess(tokenHash string) (*AccessRecord, error) {
	var rec *AccessRecord
	err := s.DB.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketAccess).Get([]byte(tokenHash))
		if raw == nil {
			return ErrNotFound
		}
		rec = &AccessRecord{}
		return json.Unmarshal(raw, rec)
	})
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// PutSession stores a session row and its per-user index entry.
func (s *Store) PutSession(m *SessionMeta) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		return putSessionTx(tx, m)
	})
}

// GetSession returns the session row for family, or ErrNotFound when the
// session was revoked (which invalidates its access tokens).
func (s *Store) GetSession(family string) (*SessionMeta, error) {
	var m *SessionMeta
	err := s.DB.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketSessions).Get([]byte(family))
		if raw == nil {
			return ErrNotFound
		}
		m = &SessionMeta{}
		return json.Unmarshal(raw, m)
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// SessionsByUser lists the live sessions of a user, most recently seen first.
func (s *Store) SessionsByUser(userUUID string) ([]SessionMeta, error) {
	var out []SessionMeta
	prefix := append([]byte(userUUID), fileKeySep...)
	err := s.DB.View(func(tx *bolt.Tx) error {
		ses := tx.Bucket(BucketSessions)
		c := tx.Bucket(BucketUserSessions).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, _ = c.Next() {
			raw := ses.Get([]byte(k[len(prefix):]))
			if raw == nil {
				continue
			}
			var m SessionMeta
			if err := json.Unmarshal(raw, &m); err != nil {
				return err
			}
			out = append(out, m)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, nil
}

// RevokeSession deletes one session (and its refresh tokens), revoking its
// access tokens immediately. It reports the number of refresh tokens removed.
func (s *Store) RevokeSession(userUUID, family string) (int, error) {
	revoked := 0
	err := s.DB.Update(func(tx *bolt.Tx) error {
		n, err := revokeFamilyTx(tx, userUUID, family)
		revoked = n
		return err
	})
	return revoked, err
}

// RevokeFamily revokes every token of family. Called when a rotated (already
// used) refresh token is presented again: a strong signal of token theft.
func (s *Store) RevokeFamily(family string) (int, error) {
	revoked := 0
	err := s.DB.Update(func(tx *bolt.Tx) error {
		userUUID := ""
		if raw := tx.Bucket(BucketSessions).Get([]byte(family)); raw != nil {
			var m SessionMeta
			if err := json.Unmarshal(raw, &m); err == nil {
				userUUID = m.UserUUID
			}
		}
		n, err := revokeFamilyTx(tx, userUUID, family)
		revoked = n
		return err
	})
	return revoked, err
}

// RevokeAllForUser revokes every session owned by userUUID, signing the user out
// on all devices. Access tokens die with their session, so there is no expiry
// window. Returns the number of refresh tokens removed.
func (s *Store) RevokeAllForUser(userUUID string) (int, error) {
	revoked := 0
	err := s.DB.Update(func(tx *bolt.Tx) error {
		prefix := append([]byte(userUUID), fileKeySep...)
		var families []string
		c := tx.Bucket(BucketUserSessions).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, _ = c.Next() {
			families = append(families, string(k[len(prefix):]))
		}
		for _, f := range families {
			n, err := revokeFamilyTx(tx, userUUID, f)
			if err != nil {
				return err
			}
			revoked += n
		}
		return nil
	})
	return revoked, err
}

// --- personal API tokens ---

// SavePAT stores a personal API token by hash and indexes it for its owner.
func (s *Store) SavePAT(tokenHash string, rec *PATRecord) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := tx.Bucket(BucketPATs).Put([]byte(tokenHash), raw); err != nil {
			return err
		}
		return tx.Bucket(BucketPATIndex).Put(patIndexKey(rec.UserUUID, rec.ID), []byte(tokenHash))
	})
}

// GetPAT looks up a personal API token by hash.
func (s *Store) GetPAT(tokenHash string) (*PATRecord, error) {
	var rec *PATRecord
	err := s.DB.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketPATs).Get([]byte(tokenHash))
		if raw == nil {
			return ErrNotFound
		}
		rec = &PATRecord{}
		return json.Unmarshal(raw, rec)
	})
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// PATsByUser lists a user's personal tokens, newest first.
func (s *Store) PATsByUser(userUUID string) ([]PATRecord, error) {
	var out []PATRecord
	prefix := append([]byte(userUUID), fileKeySep...)
	err := s.DB.View(func(tx *bolt.Tx) error {
		pats := tx.Bucket(BucketPATs)
		c := tx.Bucket(BucketPATIndex).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, v = c.Next() {
			raw := pats.Get(v)
			if raw == nil {
				continue
			}
			var rec PATRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// DeletePAT revokes the user's personal token with the given id.
func (s *Store) DeletePAT(userUUID, id string) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		idx := tx.Bucket(BucketPATIndex)
		key := patIndexKey(userUUID, id)
		hash := idx.Get(key)
		if hash == nil {
			return ErrNotFound
		}
		if err := tx.Bucket(BucketPATs).Delete(hash); err != nil {
			return err
		}
		return idx.Delete(key)
	})
}

func deletePATsTx(tx *bolt.Tx, userUUID string) error {
	prefix := append([]byte(userUUID), fileKeySep...)
	idx := tx.Bucket(BucketPATIndex)
	var keys, hashes [][]byte
	c := idx.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, v = c.Next() {
		keys = append(keys, append([]byte(nil), k...))
		hashes = append(hashes, append([]byte(nil), v...))
	}
	for i := range keys {
		if err := tx.Bucket(BucketPATs).Delete(hashes[i]); err != nil {
			return err
		}
		if err := idx.Delete(keys[i]); err != nil {
			return err
		}
	}
	return nil
}

// --- housekeeping ---

// PurgeExpired removes expired access tokens, expired refresh tokens, personal
// tokens past their expiry, and session rows with no live refresh token. It is
// safe to run while the server is up (a single write transaction).
func (s *Store) PurgeExpired(now time.Time, refreshTTL time.Duration) (int, error) {
	purged := 0
	err := s.DB.Update(func(tx *bolt.Tx) error {
		purged = 0
		type refreshDead struct {
			hash string
			rec  RefreshRecord
		}
		refB := tx.Bucket(BucketRefresh)
		famB := tx.Bucket(BucketRefreshFam)
		var deadRefresh []refreshDead
		c := refB.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec RefreshRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				continue
			}
			if rec.Expires.Before(now) {
				deadRefresh = append(deadRefresh, refreshDead{string(k), rec})
			}
		}
		for _, d := range deadRefresh {
			if err := refB.Delete([]byte(d.hash)); err != nil {
				return err
			}
			if err := famB.Delete(refreshFamilyKey(d.rec.Family, d.hash)); err != nil {
				return err
			}
			purged++
		}

		accB := tx.Bucket(BucketAccess)
		var deadAccess [][]byte
		ac := accB.Cursor()
		for k, v := ac.First(); k != nil; k, v = ac.Next() {
			var rec AccessRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				continue
			}
			if rec.Expires.Before(now) {
				deadAccess = append(deadAccess, append([]byte(nil), k...))
			}
		}
		for _, k := range deadAccess {
			if err := accB.Delete(k); err != nil {
				return err
			}
			purged++
		}

		sesB := tx.Bucket(BucketSessions)
		usB := tx.Bucket(BucketUserSessions)
		var deadSessions []SessionMeta
		sc := sesB.Cursor()
		for k, v := sc.First(); k != nil; k, v = sc.Next() {
			var m SessionMeta
			if err := json.Unmarshal(v, &m); err != nil {
				continue
			}
			if m.LastSeen.Add(refreshTTL).Before(now) {
				deadSessions = append(deadSessions, m)
			}
		}
		for _, m := range deadSessions {
			if err := sesB.Delete([]byte(m.Family)); err != nil {
				return err
			}
			if err := usB.Delete(sessionIndexKey(m.UserUUID, m.Family)); err != nil {
				return err
			}
			purged++
		}

		type patDead struct {
			hash string
			rec  PATRecord
		}
		patB := tx.Bucket(BucketPATs)
		piB := tx.Bucket(BucketPATIndex)
		var deadPATs []patDead
		pc := patB.Cursor()
		for k, v := pc.First(); k != nil; k, v = pc.Next() {
			var rec PATRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				continue
			}
			if !rec.Expires.IsZero() && rec.Expires.Before(now) {
				deadPATs = append(deadPATs, patDead{string(k), rec})
			}
		}
		for _, d := range deadPATs {
			if err := patB.Delete([]byte(d.hash)); err != nil {
				return err
			}
			if err := piB.Delete(patIndexKey(d.rec.UserUUID, d.rec.ID)); err != nil {
				return err
			}
			purged++
		}
		return nil
	})
	return purged, err
}

// backfillAuthTx upgrades a database written before sessions and access tokens
// existed by building the family and session indexes from the refresh records.
// It is idempotent: it runs once, guarded by a schema marker in the meta bucket.
func backfillAuthTx(tx *bolt.Tx) error {
	meta := tx.Bucket(BucketMeta)
	if meta.Get([]byte("authver")) != nil {
		return nil
	}
	type refreshRow struct {
		hash string
		rec  RefreshRecord
	}
	refB := tx.Bucket(BucketRefresh)
	famB := tx.Bucket(BucketRefreshFam)
	sesB := tx.Bucket(BucketSessions)
	usB := tx.Bucket(BucketUserSessions)
	var rows []refreshRow
	c := refB.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var rec RefreshRecord
		if err := json.Unmarshal(v, &rec); err != nil {
			continue
		}
		rows = append(rows, refreshRow{string(k), rec})
	}
	now := time.Now().UTC()
	for _, e := range rows {
		if err := famB.Put(refreshFamilyKey(e.rec.Family, e.hash), indexMarker); err != nil {
			return err
		}
		if sesB.Get([]byte(e.rec.Family)) == nil {
			m := SessionMeta{UserUUID: e.rec.UserUUID, Family: e.rec.Family, CreatedAt: now, LastSeen: now}
			raw, err := json.Marshal(&m)
			if err != nil {
				return err
			}
			if err := sesB.Put([]byte(m.Family), raw); err != nil {
				return err
			}
		}
		if err := usB.Put(sessionIndexKey(e.rec.UserUUID, e.rec.Family), indexMarker); err != nil {
			return err
		}
	}
	return meta.Put([]byte("authver"), []byte{1})
}

// --- file index ---

func fileKey(userUUID, cleanPath string) []byte {
	return append(append([]byte(userUUID), fileKeySep...), []byte(cleanPath)...)
}

// PutFile stores the index entry for userUUID/path, assigning a fresh global
// version in the same transaction so the manifest can never reference a write
// that failed to land. The tag and backlink indexes are updated in the same
// transaction, so they cannot drift from the manifest.
func (s *Store) PutFile(userUUID string, e *files.Entry) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		return s.putEntry(tx, userUUID, e, 0)
	})
}

// PutFileChecked is PutFile with an atomic quota check: the used-bytes total,
// the quota decision, the version bump and the entry write all happen in one
// transaction, so concurrent uploads cannot both slip past the limit. Use 0 to
// skip the quota check.
func (s *Store) PutFileChecked(userUUID string, e *files.Entry, quota int64) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		return s.putEntry(tx, userUUID, e, quota)
	})
}

func (s *Store) putEntry(tx *bolt.Tx, userUUID string, e *files.Entry, quota int64) error {
	filesB := tx.Bucket(BucketFiles)
	key := fileKey(userUUID, e.Path)

	if quota > 0 && !e.Deleted {
		used, err := usedBytesTx(tx, userUUID, e.Path)
		if err != nil {
			return err
		}
		if used+e.Size > quota {
			return ErrQuotaExceeded
		}
	}

	// Keep the folder tree backed by records: every ancestor of a written file
	// becomes an explicit folder record so folders sync even when empty.
	if err := ensureFoldersTx(tx, userUUID, e.Path); err != nil {
		return err
	}

	// Drop index entries for whatever this path looked like before.
	if err := removeEntryIndex(tx, filesB.Get(key), userUUID); err != nil {
		return err
	}

	version, err := nextVersionTx(tx)
	if err != nil {
		return err
	}
	e.Version = version

	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := filesB.Put(key, raw); err != nil {
		return err
	}
	// Tombstones are indexed by nothing: the file no longer exists.
	if e.Deleted {
		return nil
	}
	return addEntryIndex(tx, userUUID, e)
}

// usedBytesTx sums live entry sizes for a user, skipping one path (the entry
// being replaced, whose old size must not be counted).
func usedBytesTx(tx *bolt.Tx, userUUID, skipPath string) (int64, error) {
	prefix := append([]byte(userUUID), fileKeySep...)
	var total int64
	c := tx.Bucket(BucketFiles).Cursor()
	for k, v := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, v = c.Next() {
		var e files.Entry
		if err := json.Unmarshal(v, &e); err != nil {
			return 0, err
		}
		if e.Deleted || e.Path == skipPath {
			continue
		}
		total += e.Size
	}
	return total, nil
}

// nextVersionTx bumps and returns the global version counter within tx.
func nextVersionTx(tx *bolt.Tx) (uint64, error) {
	b := tx.Bucket(BucketMeta)
	v := uint64(1)
	if raw := b.Get([]byte("version")); raw != nil {
		v = binary.BigEndian.Uint64(raw) + 1
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	if err := b.Put([]byte("version"), buf[:]); err != nil {
		return 0, err
	}
	return v, nil
}

// SetEntryIndex rewrites an entry's persisted form and rebuilds its index
// entries without touching the global version counter. Used by backfill.
func (s *Store) SetEntryIndex(userUUID string, e *files.Entry) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.DB.Update(func(tx *bolt.Tx) error {
		filesB := tx.Bucket(BucketFiles)
		key := fileKey(userUUID, e.Path)
		old := filesB.Get(key)
		if old == nil {
			return nil // vanished since enumeration; nothing to do
		}
		if err := removeEntryIndex(tx, old, userUUID); err != nil {
			return err
		}
		if err := filesB.Put(key, raw); err != nil {
			return err
		}
		if e.Deleted {
			return nil
		}
		return addEntryIndex(tx, userUUID, e)
	})
}

func tagIndexKey(userUUID, tag, cleanPath string) []byte {
	k := append([]byte(userUUID), fileKeySep...)
	k = append(k, []byte(tag)...)
	k = append(k, fileKeySep...)
	return append(k, []byte(cleanPath)...)
}

func backlinkIndexKey(userUUID, targetKey, sourcePath string) []byte {
	k := append([]byte(userUUID), fileKeySep...)
	k = append(k, []byte(targetKey)...)
	k = append(k, fileKeySep...)
	return append(k, []byte(sourcePath)...)
}

var indexMarker = []byte{1}

func addEntryIndex(tx *bolt.Tx, userUUID string, e *files.Entry) error {
	if e.Metadata != nil {
		tags := tx.Bucket(BucketTags)
		for _, tag := range e.Metadata.Tags {
			t := files.NormalizeTag(tag)
			if t == "" {
				continue
			}
			if err := tags.Put(tagIndexKey(userUUID, t, e.Path), indexMarker); err != nil {
				return err
			}
		}
	}
	bl := tx.Bucket(BucketBacklinks)
	for _, link := range e.Links {
		key := files.LinkKey(link)
		if key == "" {
			continue
		}
		if err := bl.Put(backlinkIndexKey(userUUID, key, e.Path), indexMarker); err != nil {
			return err
		}
	}
	return nil
}

func removeEntryIndex(tx *bolt.Tx, raw []byte, userUUID string) error {
	if raw == nil {
		return nil
	}
	var e files.Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil //nolint:nilerr // unreadable old value: nothing to clean
	}
	if e.Metadata != nil {
		tags := tx.Bucket(BucketTags)
		for _, tag := range e.Metadata.Tags {
			t := files.NormalizeTag(tag)
			if t == "" {
				continue
			}
			if err := tags.Delete(tagIndexKey(userUUID, t, e.Path)); err != nil {
				return err
			}
		}
	}
	bl := tx.Bucket(BucketBacklinks)
	for _, link := range e.Links {
		key := files.LinkKey(link)
		if key == "" {
			continue
		}
		if err := bl.Delete(backlinkIndexKey(userUUID, key, e.Path)); err != nil {
			return err
		}
	}
	return nil
}

// TagCount is one row of the per-user tag index.
type TagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

// Tags returns the user's tags with live-file counts, ordered by descending
// count then tag name.
func (s *Store) Tags(userUUID string) ([]TagCount, error) {
	prefix := append([]byte(userUUID), fileKeySep...)
	counts := map[string]int{}
	err := s.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(BucketTags).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, _ = c.Next() {
			rest := k[len(prefix):]
			i := bytes.IndexByte(rest, 0)
			if i < 0 {
				continue
			}
			counts[string(rest[:i])]++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]TagCount, 0, len(counts))
	for tag, n := range counts {
		out = append(out, TagCount{Tag: tag, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Tag < out[j].Tag
	})
	return out, nil
}

// FilesByTag returns the live entries carrying tag for the user.
func (s *Store) FilesByTag(userUUID, tag string) ([]files.Entry, error) {
	t := files.NormalizeTag(tag)
	if t == "" {
		return nil, nil
	}
	prefix := tagIndexKey(userUUID, t, "")
	var out []files.Entry
	err := s.DB.View(func(tx *bolt.Tx) error {
		tags := tx.Bucket(BucketTags)
		filesB := tx.Bucket(BucketFiles)
		c := tags.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, _ = c.Next() {
			p := string(k[len(prefix):])
			raw := filesB.Get(fileKey(userUUID, p))
			if raw == nil {
				continue
			}
			var e files.Entry
			if err := json.Unmarshal(raw, &e); err != nil {
				return err
			}
			if e.Deleted {
				continue
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// Backlinks returns the live source paths that link to targetKey for the user.
func (s *Store) Backlinks(userUUID, targetKey string) ([]string, error) {
	if targetKey == "" {
		return nil, nil
	}
	prefix := backlinkIndexKey(userUUID, targetKey, "")
	var out []string
	err := s.DB.View(func(tx *bolt.Tx) error {
		bl := tx.Bucket(BucketBacklinks)
		filesB := tx.Bucket(BucketFiles)
		c := bl.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, _ = c.Next() {
			src := string(k[len(prefix):])
			raw := filesB.Get(fileKey(userUUID, src))
			if raw == nil {
				continue
			}
			var e files.Entry
			if err := json.Unmarshal(raw, &e); err != nil {
				return err
			}
			if e.Deleted {
				continue
			}
			out = append(out, src)
		}
		return nil
	})
	return out, err
}

// UserFile pairs an entry with its owning user, used by index backfill.
type UserFile struct {
	UserUUID string
	Entry    files.Entry
}

// AllFiles enumerates every entry in the store. It returns a materialized
// slice so callers can safely write while iterating (bbolt read transactions
// must not perform writes).
func (s *Store) AllFiles() ([]UserFile, error) {
	var out []UserFile
	err := s.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(BucketFiles).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			i := bytes.IndexByte(k, 0)
			if i < 0 {
				continue
			}
			var e files.Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, UserFile{UserUUID: string(k[:i]), Entry: e})
		}
		return nil
	})
	return out, err
}

// IndexVersion reports the schema version of the derived indexes.
func (s *Store) IndexVersion() (int, error) {
	var v int
	err := s.DB.View(func(tx *bolt.Tx) error {
		if raw := tx.Bucket(BucketMeta).Get([]byte("idxver")); raw != nil {
			v = int(binary.BigEndian.Uint64(raw))
		}
		return nil
	})
	return v, err
}

// SetIndexVersion records the derived-index schema version.
func (s *Store) SetIndexVersion(v int) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(v))
		return tx.Bucket(BucketMeta).Put([]byte("idxver"), buf[:])
	})
}

func (s *Store) GetFile(userUUID, cleanPath string) (*files.Entry, error) {
	var e *files.Entry
	err := s.DB.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketFiles).Get(fileKey(userUUID, cleanPath))
		if raw == nil {
			return ErrNotFound
		}
		e = &files.Entry{}
		return json.Unmarshal(raw, e)
	})
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (s *Store) Manifest(userUUID string) ([]files.Entry, error) {
	var out []files.Entry
	prefix := append([]byte(userUUID), fileKeySep...)
	err := s.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(BucketFiles).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, v = c.Next() {
			var e files.Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// UsedBytes sums the sizes of all live (non-tombstoned) files of a user.
func (s *Store) UsedBytes(userUUID string) (int64, error) {
	prefix := append([]byte(userUUID), fileKeySep...)
	var total int64
	err := s.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(BucketFiles).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, v = c.Next() {
			var e files.Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if !e.Deleted {
				total += e.Size
			}
		}
		return nil
	})
	return total, err
}

func bytesHasPrefix(b, prefix []byte) bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == string(prefix)
}

// --- folders ---

func folderKey(userUUID, cleanPath string) []byte {
	return append(append([]byte(userUUID), fileKeySep...), []byte(cleanPath)...)
}

// ensureFoldersTx creates (or revives) an explicit folder record for every
// ancestor directory of path, so that every folder in the tree is backed by a
// record and therefore syncs, carries a version, and can be moved.
func ensureFoldersTx(tx *bolt.Tx, userUUID, path string) error {
	dirs := files.AncestorDirs(path)
	if len(dirs) == 0 {
		return nil
	}
	b := tx.Bucket(BucketFolders)
	now := time.Now().UTC()
	for _, dir := range dirs {
		key := folderKey(userUUID, dir)
		if raw := b.Get(key); raw != nil {
			var f files.Folder
			if err := json.Unmarshal(raw, &f); err != nil {
				return err
			}
			if !f.Deleted {
				continue
			}
			v, err := nextVersionTx(tx)
			if err != nil {
				return err
			}
			f.Deleted = false
			f.Version = v
			f.ModTime = now
			enc, err := json.Marshal(&f)
			if err != nil {
				return err
			}
			if err := b.Put(key, enc); err != nil {
				return err
			}
			continue
		}
		v, err := nextVersionTx(tx)
		if err != nil {
			return err
		}
		f := files.Folder{Path: dir, Version: v, ModTime: now}
		enc, err := json.Marshal(&f)
		if err != nil {
			return err
		}
		if err := b.Put(key, enc); err != nil {
			return err
		}
	}
	return nil
}

// PutFolder stores a folder record, assigning a fresh version and ensuring its
// ancestor folders exist.
func (s *Store) PutFolder(userUUID string, f *files.Folder) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		if err := ensureFoldersTx(tx, userUUID, f.Path); err != nil {
			return err
		}
		v, err := nextVersionTx(tx)
		if err != nil {
			return err
		}
		f.Version = v
		enc, err := json.Marshal(f)
		if err != nil {
			return err
		}
		return tx.Bucket(BucketFolders).Put(folderKey(userUUID, f.Path), enc)
	})
}

// EnsureFolderPath creates the ancestor folder records for path if missing. It
// is used by the one-time backfill for databases written before folders existed.
func (s *Store) EnsureFolderPath(userUUID, path string) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		return ensureFoldersTx(tx, userUUID, path)
	})
}

// BackfillFolders creates folder records for the ancestors of every live file.
// It upgrades databases written before folders existed; it is a no-op for an
// already-migrated vault.
func (s *Store) BackfillFolders() error {
	all, err := s.AllFiles()
	if err != nil {
		return err
	}
	for _, uf := range all {
		if uf.Entry.Deleted {
			continue
		}
		if err := s.EnsureFolderPath(uf.UserUUID, uf.Entry.Path); err != nil {
			return err
		}
	}
	return nil
}

// GetFolder returns the folder record at cleanPath, tombstones included.
func (s *Store) GetFolder(userUUID, cleanPath string) (*files.Folder, error) {
	var f *files.Folder
	err := s.DB.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(BucketFolders).Get(folderKey(userUUID, cleanPath))
		if raw == nil {
			return ErrNotFound
		}
		f = &files.Folder{}
		return json.Unmarshal(raw, f)
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Folders returns every folder record for a user, including tombstones.
func (s *Store) Folders(userUUID string) ([]files.Folder, error) {
	var out []files.Folder
	prefix := append([]byte(userUUID), fileKeySep...)
	err := s.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(BucketFolders).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, v = c.Next() {
			var f files.Folder
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			out = append(out, f)
		}
		return nil
	})
	return out, err
}

// moveTarget rewrites a path living at or under from so it lives at or under to.
func moveTarget(path, from, to string) string {
	if path == from {
		return to
	}
	return to + strings.TrimPrefix(path, from)
}

func liveFileAt(tx *bolt.Tx, userUUID, cleanPath string) bool {
	raw := tx.Bucket(BucketFiles).Get(fileKey(userUUID, cleanPath))
	if raw == nil {
		return false
	}
	var e files.Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return false
	}
	return !e.Deleted
}

func liveFolderAt(tx *bolt.Tx, userUUID, cleanPath string) bool {
	raw := tx.Bucket(BucketFolders).Get(folderKey(userUUID, cleanPath))
	if raw == nil {
		return false
	}
	var f files.Folder
	if err := json.Unmarshal(raw, &f); err != nil {
		return false
	}
	return !f.Deleted
}

// MoveFolder atomically moves the folder at from, together with every descendant
// folder record and every file beneath it, to to. It returns the affected
// entries: a tombstone at each old path and a live record at each new path, so
// other devices observe the change as a delete plus a create.
//
// When userRoot is non-empty the real directory on disk is renamed first, so a
// missing or unwritable destination aborts the move before the index changes.
// The caller is responsible for validating from/to and the source precondition.
func (s *Store) MoveFolder(userRoot, userUUID, from, to string) ([]files.Entry, []files.Folder, error) {
	var movedFiles []files.Entry
	var movedFolders []files.Folder
	err := s.DB.Update(func(tx *bolt.Tx) error {
		movedFiles, movedFolders = nil, nil
		filesB := tx.Bucket(BucketFiles)
		foldersB := tx.Bucket(BucketFolders)
		prefix := append([]byte(userUUID), fileKeySep...)

		// Collect affected live records first: bbolt forbids mutating a bucket
		// while iterating it.
		var srcFiles []files.Entry
		c := filesB.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, v = c.Next() {
			var e files.Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.Deleted || !files.IsUnder(e.Path, from) {
				continue
			}
			srcFiles = append(srcFiles, e)
		}
		var srcFolders []files.Folder
		fc := foldersB.Cursor()
		for k, v := fc.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, v = fc.Next() {
			var f files.Folder
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			if f.Deleted || !files.IsUnder(f.Path, from) {
				continue
			}
			srcFolders = append(srcFolders, f)
		}

		// Refuse to clobber anything live at a destination path.
		for _, e := range srcFiles {
			np := moveTarget(e.Path, from, to)
			if liveFileAt(tx, userUUID, np) || liveFolderAt(tx, userUUID, np) {
				return fmt.Errorf("%w: %s", ErrMoveCollision, np)
			}
		}
		for _, f := range srcFolders {
			np := moveTarget(f.Path, from, to)
			if liveFileAt(tx, userUUID, np) || liveFolderAt(tx, userUUID, np) {
				return fmt.Errorf("%w: %s", ErrMoveCollision, np)
			}
		}

		// Move the bytes on disk before touching the index.
		if userRoot != "" {
			oldDir := filepath.Join(userRoot, filepath.FromSlash(from))
			if fi, statErr := os.Stat(oldDir); statErr == nil && fi.IsDir() {
				newDir := filepath.Join(userRoot, filepath.FromSlash(to))
				if err := os.MkdirAll(filepath.Dir(newDir), 0o700); err != nil {
					return err
				}
				if err := os.Rename(oldDir, newDir); err != nil {
					return err
				}
			}
		}

		// The destination's own ancestors must exist as folder records.
		if err := ensureFoldersTx(tx, userUUID, to); err != nil {
			return err
		}

		now := time.Now().UTC()
		for _, e := range srcFiles {
			oldKey := fileKey(userUUID, e.Path)
			if err := removeEntryIndex(tx, filesB.Get(oldKey), userUUID); err != nil {
				return err
			}
			gone := e
			gone.Deleted = true
			gone.Size = 0
			gone.Metadata = nil
			gone.Links = nil
			gone.ModTime = now
			gv, err := nextVersionTx(tx)
			if err != nil {
				return err
			}
			gone.Version = gv
			goneRaw, err := json.Marshal(&gone)
			if err != nil {
				return err
			}
			if err := filesB.Put(oldKey, goneRaw); err != nil {
				return err
			}
			movedFiles = append(movedFiles, gone)

			live := e
			live.Path = moveTarget(e.Path, from, to)
			live.ModTime = now
			lv, err := nextVersionTx(tx)
			if err != nil {
				return err
			}
			live.Version = lv
			liveRaw, err := json.Marshal(&live)
			if err != nil {
				return err
			}
			if err := filesB.Put(fileKey(userUUID, live.Path), liveRaw); err != nil {
				return err
			}
			if err := addEntryIndex(tx, userUUID, &live); err != nil {
				return err
			}
			movedFiles = append(movedFiles, live)
		}

		for _, f := range srcFolders {
			oldKey := folderKey(userUUID, f.Path)
			gone := f
			gone.Deleted = true
			gone.ModTime = now
			gv, err := nextVersionTx(tx)
			if err != nil {
				return err
			}
			gone.Version = gv
			goneRaw, err := json.Marshal(&gone)
			if err != nil {
				return err
			}
			if err := foldersB.Put(oldKey, goneRaw); err != nil {
				return err
			}
			movedFolders = append(movedFolders, gone)

			live := f
			live.Path = moveTarget(f.Path, from, to)
			live.ModTime = now
			lv, err := nextVersionTx(tx)
			if err != nil {
				return err
			}
			live.Version = lv
			liveRaw, err := json.Marshal(&live)
			if err != nil {
				return err
			}
			if err := foldersB.Put(folderKey(userUUID, live.Path), liveRaw); err != nil {
				return err
			}
			movedFolders = append(movedFolders, live)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return movedFiles, movedFolders, nil
}

// DeleteFolderTree tombstones the folder at from and every descendant folder
// and file beneath it in a single transaction, returning the affected records
// (all tombstones). Bytes are removed from disk afterwards, best-effort: an
// orphaned file left by a failed remove is never served (no live entry points
// at it) and does not count against quota.
func (s *Store) DeleteFolderTree(userRoot, userUUID, from string) ([]files.Entry, []files.Folder, error) {
	var deadFiles []files.Entry
	var deadFolders []files.Folder
	err := s.DB.Update(func(tx *bolt.Tx) error {
		deadFiles, deadFolders = nil, nil
		filesB := tx.Bucket(BucketFiles)
		foldersB := tx.Bucket(BucketFolders)
		prefix := append([]byte(userUUID), fileKeySep...)

		// Collect affected live records first: bbolt forbids mutating a bucket
		// while iterating it.
		var srcFiles []files.Entry
		c := filesB.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, v = c.Next() {
			var e files.Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.Deleted || !files.IsUnder(e.Path, from) {
				continue
			}
			srcFiles = append(srcFiles, e)
		}
		var srcFolders []files.Folder
		fc := foldersB.Cursor()
		for k, v := fc.Seek(prefix); k != nil && bytesHasPrefix(k, prefix); k, v = fc.Next() {
			var f files.Folder
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			if f.Deleted || !files.IsUnder(f.Path, from) {
				continue
			}
			srcFolders = append(srcFolders, f)
		}

		now := time.Now().UTC()
		for _, e := range srcFiles {
			key := fileKey(userUUID, e.Path)
			if err := removeEntryIndex(tx, filesB.Get(key), userUUID); err != nil {
				return err
			}
			gone := e
			gone.Deleted = true
			gone.Size = 0
			gone.Metadata = nil
			gone.Links = nil
			gone.ModTime = now
			v, err := nextVersionTx(tx)
			if err != nil {
				return err
			}
			gone.Version = v
			raw, err := json.Marshal(&gone)
			if err != nil {
				return err
			}
			if err := filesB.Put(key, raw); err != nil {
				return err
			}
			deadFiles = append(deadFiles, gone)
		}
		for _, f := range srcFolders {
			key := folderKey(userUUID, f.Path)
			gone := f
			gone.Deleted = true
			gone.ModTime = now
			v, err := nextVersionTx(tx)
			if err != nil {
				return err
			}
			gone.Version = v
			raw, err := json.Marshal(&gone)
			if err != nil {
				return err
			}
			if err := foldersB.Put(key, raw); err != nil {
				return err
			}
			deadFolders = append(deadFolders, gone)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// Remove the subtree's bytes once the index no longer references them.
	if userRoot != "" && len(deadFiles) > 0 {
		dir := filepath.Join(userRoot, filepath.FromSlash(from))
		_ = os.RemoveAll(dir)
	}
	return deadFiles, deadFolders, nil
}
