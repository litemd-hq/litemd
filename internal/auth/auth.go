// Package auth implements credentials, JWT access tokens and rotating
// refresh tokens backed by the bbolt store.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	bolt "github.com/litemd-hq/litemd/internal/bolt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenRevoked       = errors.New("token revoked")
	ErrUsernameTaken      = errors.New("username already taken")
)

// TokenPair is the wire representation handed to clients.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type Service struct {
	store      *bolt.Store
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewService(store *bolt.Store, accessTTL, refreshTTL time.Duration) (*Service, error) {
	secret, err := store.JWTSecret()
	if err != nil {
		return nil, err
	}
	return &Service{store: store, secret: secret, accessTTL: accessTTL, refreshTTL: refreshTTL}, nil
}

// NewUUID returns a random v4-style hex identifier for users and families.
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

func (s *Service) issueAccess(userUUID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userUUID,
		"jti": randomToken()[:16],
		"iat": now.Unix(),
		"exp": now.Add(s.accessTTL).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}

// ParseAccess validates an access token and returns the subject (user UUID).
func (s *Service) ParseAccess(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return s.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return "", ErrInvalidCredentials
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", ErrInvalidCredentials
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", ErrInvalidCredentials
	}
	return sub, nil
}

func (s *Service) newPair(userUUID, family string) (*TokenPair, error) {
	access, err := s.issueAccess(userUUID)
	if err != nil {
		return nil, err
	}
	refresh := randomToken()
	err = s.store.SaveRefresh(bolt.HashToken(refresh), &bolt.RefreshRecord{
		UserUUID: userUUID,
		Family:   family,
		Expires:  time.Now().Add(s.refreshTTL),
	})
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

// Register creates a user. The first user in a fresh database becomes the
// admin; subsequent registrations require the caller to pass
// requireAdmin=false only after the HTTP layer verified an admin token.
func (s *Service) Register(username, password string, defaultQuota int64) (*bolt.User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	count, err := s.store.CountUsers()
	if err != nil {
		return nil, err
	}
	u := &bolt.User{
		UUID:      NewUUID(),
		Username:  username,
		Argon2:    hash,
		Quota:     defaultQuota,
		IsAdmin:   count == 0,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateUser(u); err != nil {
		return nil, ErrUsernameTaken
	}
	return u, nil
}

// Login verifies credentials and returns a fresh token pair.
func (s *Service) Login(username, password string) (*TokenPair, error) {
	u, err := s.store.UserByUsername(username)
	if err != nil {
		// Burn comparable time so missing users are indistinguishable.
		_ = VerifyPassword("$argon2id$v=19$m=65536,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password)
		return nil, ErrInvalidCredentials
	}
	if !VerifyPassword(u.Argon2, password) {
		return nil, ErrInvalidCredentials
	}
	return s.newPair(u.UUID, NewUUID())
}

// Refresh rotates a refresh token: the presented token is tombstoned and a
// new one from the same family is issued. Presenting an already-rotated
// token revokes the entire family (theft detection).
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
	rec.Rotated = true
	if err := s.store.SaveRefresh(hash, rec); err != nil {
		return nil, err
	}
	return s.newPair(rec.UserUUID, rec.Family)
}

// RevokeFamily invalidates every refresh token of the given token's family.
func (s *Service) RevokeFamily(refreshToken string) error {
	rec, err := s.store.GetRefresh(bolt.HashToken(refreshToken))
	if err != nil {
		return nil // unknown token: nothing to revoke
	}
	_, err = s.store.RevokeFamily(rec.Family)
	return err
}

// Logout deletes a single refresh token.
func (s *Service) Logout(refreshToken string) error {
	return s.store.DeleteRefresh(bolt.HashToken(refreshToken))
}

// RevokeAll signs the user out everywhere by deleting every refresh token they
// own. Returns how many were revoked. Access tokens already issued remain
// valid until they expire.
func (s *Service) RevokeAll(userUUID string) (int, error) {
	return s.store.RevokeAllForUser(userUUID)
}
