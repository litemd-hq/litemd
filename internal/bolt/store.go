// Package bolt wraps the embedded bbolt database holding users, refresh
// tokens, the per-file index and a global monotonic version counter.
package bolt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/litemd-hq/litemd/internal/files"
)

var (
	BucketUsers     = []byte("users")     // userUUID -> User (JSON)
	BucketNames     = []byte("usernames") // username -> userUUID
	BucketRefresh   = []byte("refresh")   // sha256(refresh) -> RefreshRecord (JSON)
	BucketFiles     = []byte("files")     // userUUID\x00path -> files.Entry (JSON)
	BucketTags      = []byte("tags")      // userUUID\x00tag\x00path -> {1}
	BucketBacklinks = []byte("backlinks") // userUUID\x00targetKey\x00sourcePath -> {1}
	BucketMeta      = []byte("meta")      // versions, jwt_secret

	fileKeySep = []byte{0}
)

var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrQuotaExceeded = errors.New("storage quota exceeded")
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
		for _, b := range [][]byte{BucketUsers, BucketNames, BucketRefresh, BucketFiles, BucketTags, BucketBacklinks, BucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
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

func (s *Store) CreateUser(u *User) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		names := tx.Bucket(BucketNames)
		if names.Get([]byte(u.Username)) != nil {
			return fmt.Errorf("username already taken")
		}
		if tx.Bucket(BucketUsers).Get([]byte(u.UUID)) != nil {
			return fmt.Errorf("user uuid collision")
		}
		raw, err := json.Marshal(u)
		if err != nil {
			return err
		}
		if err := tx.Bucket(BucketUsers).Put([]byte(u.UUID), raw); err != nil {
			return err
		}
		return names.Put([]byte(u.Username), []byte(u.UUID))
	})
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

// --- refresh tokens ---

type RefreshRecord struct {
	UserUUID string    `json:"user_uuid"`
	Family   string    `json:"family"`
	Expires  time.Time `json:"expires"`
	// Rotated marks a token that has already been exchanged for a newer one.
	// Presenting it again is theft: the whole family gets revoked.
	Rotated bool `json:"rotated,omitempty"`
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) SaveRefresh(tokenHash string, rec *RefreshRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(BucketRefresh).Put([]byte(tokenHash), raw)
	})
}

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

func (s *Store) DeleteRefresh(tokenHash string) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(BucketRefresh).Delete([]byte(tokenHash))
	})
}

// RevokeFamily deletes every refresh token belonging to family. Called when
// a rotated (already-used) refresh token is presented again: a strong signal
// of token theft.
func (s *Store) RevokeFamily(family string) (int, error) {
	revoked := 0
	err := s.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketRefresh)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec RefreshRecord
			if err := json.Unmarshal(v, &rec); err != nil || rec.Family != family {
				continue
			}
			if err := b.Delete(k); err != nil {
				return err
			}
			revoked++
		}
		return nil
	})
	return revoked, err
}

// RevokeAllForUser deletes every refresh token owned by userUUID, i.e. signs
// the user out on all devices. Access tokens already issued stay valid until
// they expire, so keep access-ttl short.
func (s *Store) RevokeAllForUser(userUUID string) (int, error) {
	revoked := 0
	err := s.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketRefresh)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec RefreshRecord
			if err := json.Unmarshal(v, &rec); err != nil || rec.UserUUID != userUUID {
				continue
			}
			if err := b.Delete(k); err != nil {
				return err
			}
			revoked++
		}
		return nil
	})
	return revoked, err
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

// --- secrets ---

// JWTSecret returns the persistent HMAC secret, creating one on first use.
func (s *Store) JWTSecret() ([]byte, error) {
	var secret []byte
	err := s.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketMeta)
		if raw := b.Get([]byte("jwt_secret")); raw != nil {
			secret = append([]byte(nil), raw...)
			return nil
		}
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		return b.Put([]byte("jwt_secret"), secret)
	})
	return secret, err
}
