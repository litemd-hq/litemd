// Package auth implements credentials, opaque session tokens (a short-lived
// access token plus a rotating refresh token) and personal API tokens, all
// backed by the bbolt store.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	bolt "github.com/litemd-hq/litemd/internal/bolt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenRevoked       = errors.New("token revoked")
	ErrUsernameTaken      = errors.New("username already taken")
	ErrRegistrationClosed = errors.New("registration is disabled")
	ErrLastAdmin          = errors.New("cannot remove the last administrator")
	ErrNotFound           = errors.New("not found")
)

// TokenPair is the wire representation handed to clients. Both tokens are
// opaque strings the server stores only as hashes.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// dummyHash is a valid argon2id hash used to burn comparable time when the
// username does not exist, so login timing cannot reveal which accounts exist.
const dummyHash = "$argon2id$v=19$m=65536,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type Service struct {
	store      *bolt.Store
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewService(store *bolt.Store, accessTTL, refreshTTL time.Duration) (*Service, error) {
	return &Service{store: store, accessTTL: accessTTL, refreshTTL: refreshTTL}, nil
}

// NewUUID returns a random v4-style hex identifier for users, sessions and
// personal tokens.
func NewUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b)
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// issueTokens writes a fresh access/refresh pair for an existing session.
func (s *Service) issueTokens(userUUID, family string) (*TokenPair, error) {
	now := time.Now()
	access := randomToken()
	refresh := randomToken()
	if err := s.store.PutTokens(
		bolt.HashToken(access),
		&bolt.AccessRecord{UserUUID: userUUID, Family: family, Expires: now.Add(s.accessTTL)},
		bolt.HashToken(refresh),
		&bolt.RefreshRecord{UserUUID: userUUID, Family: family, Expires: now.Add(s.refreshTTL)},
	); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

// startSession creates a session row and issues its first token pair.
func (s *Service) startSession(userUUID, userAgent, ip string) (*TokenPair, error) {
	family := NewUUID()
	now := time.Now().UTC()
	if err := s.store.PutSession(&bolt.SessionMeta{
		UserUUID:  userUUID,
		Family:    family,
		CreatedAt: now,
		LastSeen:  now,
		UserAgent: userAgent,
		IP:        ip,
	}); err != nil {
		return nil, err
	}
	return s.issueTokens(userUUID, family)
}

// Authenticate resolves a bearer token to its owner. The token is either a
// session access token or a personal API token; both are opaque and stored
// hashed. The returned family identifies the session and is empty for personal
// tokens.
func (s *Service) Authenticate(token string) (*bolt.User, string, error) {
	now := time.Now()
	hash := bolt.HashToken(token)
	if rec, err := s.store.GetAccess(hash); err == nil {
		if rec.Expires.Before(now) {
			return nil, "", ErrTokenExpired
		}
		// An access token is valid only while its session still exists, so a
		// revoked session invalidates every access token it ever issued.
		if _, err := s.store.GetSession(rec.Family); err != nil {
			return nil, "", ErrTokenRevoked
		}
		u, err := s.store.UserByUUID(rec.UserUUID)
		if err != nil {
			return nil, "", ErrInvalidCredentials
		}
		return u, rec.Family, nil
	}
	if rec, err := s.store.GetPAT(hash); err == nil {
		if !rec.Expires.IsZero() && rec.Expires.Before(now) {
			return nil, "", ErrTokenExpired
		}
		u, err := s.store.UserByUUID(rec.UserUUID)
		if err != nil {
			return nil, "", ErrInvalidCredentials
		}
		return u, "", nil
	}
	return nil, "", ErrInvalidCredentials
}

// RegisterOptions parameterizes user creation. AdminAuthorized is true when an
// admin token authorized the request; Open turns off the admin gate for the
// permissive registration policy.
type RegisterOptions struct {
	Username        string
	Password        string
	Quota           int64
	IsAdmin         bool
	AdminAuthorized bool
	Open            bool
}

// Register creates a user. The first user of a fresh database always becomes
// the admin (decided atomically in the store).
func (s *Service) Register(opts RegisterOptions) (*bolt.User, error) {
	hash, err := HashPassword(opts.Password)
	if err != nil {
		return nil, err
	}
	u := &bolt.User{
		UUID:      NewUUID(),
		Username:  opts.Username,
		Argon2:    hash,
		Quota:     opts.Quota,
		IsAdmin:   opts.IsAdmin,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateUser(u, opts.AdminAuthorized, opts.Open); err != nil {
		switch {
		case errors.Is(err, bolt.ErrUsernameTaken):
			return nil, ErrUsernameTaken
		case errors.Is(err, bolt.ErrRegistrationClosed):
			return nil, ErrRegistrationClosed
		default:
			return nil, err
		}
	}
	return u, nil
}

// ListUsers returns every account.
func (s *Service) ListUsers() ([]bolt.User, error) { return s.store.ListUsers() }

// UpdateUser applies a partial admin update (nil fields are unchanged).
func (s *Service) UpdateUser(userUUID string, quota *int64, isAdmin *bool) (*bolt.User, error) {
	u, err := s.store.UpdateUser(userUUID, quota, isAdmin)
	switch {
	case errors.Is(err, bolt.ErrNotFound):
		return nil, ErrNotFound
	case errors.Is(err, bolt.ErrLastAdmin):
		return nil, ErrLastAdmin
	case err != nil:
		return nil, err
	}
	return u, nil
}

// DeleteUser removes an account and all of its records. The caller removes the
// on-disk files.
func (s *Service) DeleteUser(userUUID string) error {
	err := s.store.DeleteUser(userUUID)
	switch {
	case errors.Is(err, bolt.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, bolt.ErrLastAdmin):
		return ErrLastAdmin
	default:
		return err
	}
}

// Login verifies credentials and starts a new session.
func (s *Service) Login(username, password, userAgent, ip string) (*TokenPair, error) {
	u, err := s.store.UserByUsername(username)
	if err != nil {
		_ = VerifyPassword(dummyHash, password)
		return nil, ErrInvalidCredentials
	}
	if !VerifyPassword(u.Argon2, password) {
		return nil, ErrInvalidCredentials
	}
	return s.startSession(u.UUID, userAgent, ip)
}

// Refresh rotates a refresh token: the presented token is consumed and a new
// pair is issued from the same session. Presenting an already-consumed token
// revokes the entire session (theft detection).
func (s *Service) Refresh(refreshToken string) (*TokenPair, error) {
	hash := bolt.HashToken(refreshToken)
	rec, err := s.store.GetRefresh(hash)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if rec.Rotated {
		if _, err := s.store.RevokeFamily(rec.Family); err != nil {
			return nil, err
		}
		return nil, ErrTokenRevoked
	}
	if time.Now().After(rec.Expires) {
		_ = s.store.DeleteRefresh(hash)
		return nil, ErrTokenExpired
	}
	now := time.Now()
	nextAccess := randomToken()
	nextRefresh := randomToken()
	old := *rec
	if err := s.store.RotateRefresh(
		hash,
		&old,
		bolt.HashToken(nextRefresh),
		&bolt.RefreshRecord{UserUUID: rec.UserUUID, Family: rec.Family, Expires: now.Add(s.refreshTTL)},
		bolt.HashToken(nextAccess),
		&bolt.AccessRecord{UserUUID: rec.UserUUID, Family: rec.Family, Expires: now.Add(s.accessTTL)},
		now.UTC(),
	); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  nextAccess,
		RefreshToken: nextRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

// Logout ends the session that owns refreshToken, revoking its access and
// refresh tokens immediately. An unknown token is a no-op.
func (s *Service) Logout(refreshToken string) error {
	rec, err := s.store.GetRefresh(bolt.HashToken(refreshToken))
	if err != nil {
		return nil
	}
	_, err = s.store.RevokeFamily(rec.Family)
	return err
}

// RevokeSession ends one session of a user, revoking its access tokens at once.
func (s *Service) RevokeSession(userUUID, family string) error {
	_, err := s.store.RevokeSession(userUUID, family)
	return err
}

// RevokeAll signs the user out everywhere. Returns how many refresh tokens were
// revoked. Access tokens are revoked implicitly, with no expiry window.
func (s *Service) RevokeAll(userUUID string) (int, error) {
	return s.store.RevokeAllForUser(userUUID)
}

// ListSessions lists the user's live sessions.
func (s *Service) ListSessions(userUUID string) ([]bolt.SessionMeta, error) {
	return s.store.SessionsByUser(userUUID)
}

// ChangePassword verifies the current password, stores the new one, revokes
// every existing session and starts a fresh one for the caller.
func (s *Service) ChangePassword(userUUID, current, next, userAgent, ip string) (*TokenPair, error) {
	u, err := s.store.UserByUUID(userUUID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !VerifyPassword(u.Argon2, current) {
		return nil, ErrInvalidCredentials
	}
	hash, err := HashPassword(next)
	if err != nil {
		return nil, err
	}
	if err := s.store.SetUserPassword(userUUID, hash); err != nil {
		return nil, err
	}
	if _, err := s.store.RevokeAllForUser(userUUID); err != nil {
		return nil, err
	}
	return s.startSession(userUUID, userAgent, ip)
}

// ChangeUsername renames the caller's account after confirming the current
// password. Existing sessions stay valid: tokens are keyed by user UUID.
func (s *Service) ChangeUsername(userUUID, currentPassword, newUsername string) (*bolt.User, error) {
	u, err := s.store.UserByUUID(userUUID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !VerifyPassword(u.Argon2, currentPassword) {
		return nil, ErrInvalidCredentials
	}
	return s.RenameUser(userUUID, newUsername)
}

// RenameUser renames an account without a password check (admin action).
func (s *Service) RenameUser(userUUID, newUsername string) (*bolt.User, error) {
	u, err := s.store.UpdateUserUsername(userUUID, newUsername)
	switch {
	case errors.Is(err, bolt.ErrNotFound):
		return nil, ErrNotFound
	case errors.Is(err, bolt.ErrUsernameTaken):
		return nil, ErrUsernameTaken
	case err != nil:
		return nil, err
	}
	return u, nil
}

// ResetPassword sets a new password for another user (admin action) and revokes
// that user's sessions.
func (s *Service) ResetPassword(userUUID, next string) error {
	hash, err := HashPassword(next)
	if err != nil {
		return err
	}
	if err := s.store.SetUserPassword(userUUID, hash); err != nil {
		if errors.Is(err, bolt.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	_, err = s.store.RevokeAllForUser(userUUID)
	return err
}

// CreatePAT mints a personal API token for a user. The plaintext secret is
// returned once; only its hash is stored. A ttl of zero means no expiry.
func (s *Service) CreatePAT(userUUID, name string, ttl time.Duration) (string, *bolt.PATRecord, error) {
	secret := randomToken()
	now := time.Now().UTC()
	rec := &bolt.PATRecord{
		ID:        NewUUID()[:16],
		UserUUID:  userUUID,
		Name:      name,
		CreatedAt: now,
		LastSeen:  now,
	}
	if ttl > 0 {
		rec.Expires = now.Add(ttl)
	}
	if err := s.store.SavePAT(bolt.HashToken(secret), rec); err != nil {
		return "", nil, err
	}
	return secret, rec, nil
}

// ListPATs returns a user's personal tokens (without secrets).
func (s *Service) ListPATs(userUUID string) ([]bolt.PATRecord, error) {
	return s.store.PATsByUser(userUUID)
}

// RevokePAT deletes a personal token by id.
func (s *Service) RevokePAT(userUUID, id string) error {
	err := s.store.DeletePAT(userUUID, id)
	if errors.Is(err, bolt.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// PurgeExpired removes expired tokens and dead sessions.
func (s *Service) PurgeExpired(now time.Time) (int, error) {
	return s.store.PurgeExpired(now, s.refreshTTL)
}
