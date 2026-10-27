package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/litemd-hq/litemd/internal/auth"
	bolt "github.com/litemd-hq/litemd/internal/bolt"
	"github.com/litemd-hq/litemd/internal/config"
)

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userResponse struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"is_admin"`
	Quota    int64  `json:"quota_bytes"`
}

type meResponse struct {
	UUID      string    `json:"uuid"`
	Username  string    `json:"username"`
	IsAdmin   bool      `json:"is_admin"`
	Quota     int64     `json:"quota_bytes"`
	UsedBytes int64     `json:"used_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type changeUsernameRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	UserAgent string    `json:"user_agent,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Current   bool      `json:"current"`
}

type createPATRequest struct {
	Name string `json:"name"`
	// ExpiresIn is the token lifetime in seconds; 0 means no expiry.
	ExpiresIn int64 `json:"expires_in"`
}

type patResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	LastSeen  time.Time  `json:"last_seen"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Token is the plaintext secret and is returned only when created.
	Token string `json:"token,omitempty"`
}

func patToResponse(rec bolt.PATRecord) patResponse {
	out := patResponse{ID: rec.ID, Name: rec.Name, CreatedAt: rec.CreatedAt, LastSeen: rec.LastSeen}
	if !rec.Expires.IsZero() {
		e := rec.Expires
		out.ExpiresAt = &e
	}
	return out
}

// handleRegister creates a user subject to the registration policy. The first
// user of a fresh database becomes admin and is always allowed. With the admin
// policy (the default) later registrations must carry an admin token; the open
// policy allows anyone; the closed policy refuses HTTP registration entirely.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	username, err := config.NormalizeUsername(req.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_username", err.Error())
		return
	}
	if err := config.ValidatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, "bad_password", err.Error())
		return
	}
	if s.cfg.Registration == config.RegistrationClosed {
		writeError(w, http.StatusForbidden, "registration_closed", "registration is disabled")
		return
	}

	adminUser, _, aerr := s.authenticate(r)
	adminAuthorized := aerr == nil && adminUser != nil && adminUser.IsAdmin
	open := s.cfg.Registration == config.RegistrationOpen

	if !open && !adminAuthorized {
		count, err := s.store.CountUsers()
		if err != nil {
			s.log.Error("count users", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		if count > 0 {
			if aerr != nil {
				writeError(w, http.StatusUnauthorized, "unauthorized", "registration requires an admin token")
			} else {
				writeError(w, http.StatusForbidden, "forbidden", "admin privileges required")
			}
			return
		}
	}

	user, err := s.auth.Register(auth.RegisterOptions{
		Username:        username,
		Password:        req.Password,
		Quota:           s.cfg.QuotaBytes,
		AdminAuthorized: adminAuthorized,
		Open:            open,
	})
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUsernameTaken):
			writeError(w, http.StatusConflict, "username_taken", "username already taken")
		case errors.Is(err, auth.ErrRegistrationClosed):
			writeError(w, http.StatusUnauthorized, "unauthorized", "registration requires an admin token")
		default:
			s.log.Error("register", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		}
		return
	}
	writeJSON(w, http.StatusCreated, userResponse{
		UUID:     user.UUID,
		Username: user.Username,
		IsAdmin:  user.IsAdmin,
		Quota:    user.Quota,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	pair, err := s.auth.Login(req.Username, req.Password, r.UserAgent(), s.clientIP(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	pair, err := s.auth.Refresh(req.RefreshToken)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, pair)
	case errors.Is(err, auth.ErrTokenRevoked):
		writeError(w, http.StatusUnauthorized, "token_revoked", "refresh token reuse detected; session revoked")
	case errors.Is(err, auth.ErrTokenExpired):
		writeError(w, http.StatusUnauthorized, "token_expired", "refresh token expired")
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "unknown refresh token")
	default:
		s.log.Error("refresh", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

// handleLogout ends the session that owns the presented refresh token, revoking
// its access and refresh tokens. Unknown tokens succeed (nothing to do).
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if err := s.auth.Logout(req.RefreshToken); err != nil {
		s.log.Error("logout", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleMe returns the authenticated user's profile, quota and used bytes.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	used, err := s.store.UsedBytes(user.UUID)
	if err != nil {
		s.log.Error("used bytes", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, meResponse{
		UUID:      user.UUID,
		Username:  user.Username,
		IsAdmin:   user.IsAdmin,
		Quota:     user.Quota,
		UsedBytes: used,
		CreatedAt: user.CreatedAt,
	})
}

// handleChangePassword verifies the current password, stores the new one,
// revokes every session and starts a fresh one for the caller.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if err := config.ValidatePassword(req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, "bad_password", err.Error())
		return
	}
	user := userFromRequest(r)
	pair, err := s.auth.ChangePassword(user.UUID, req.CurrentPassword, req.NewPassword, r.UserAgent(), s.clientIP(r))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "current password is incorrect")
			return
		}
		s.log.Error("change password", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

// handleChangeUsername renames the caller's account after confirming the
// current password. Existing sessions stay valid (tokens are keyed by UUID).
func (s *Server) handleChangeUsername(w http.ResponseWriter, r *http.Request) {
	var req changeUsernameRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	username, err := config.NormalizeUsername(req.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_username", err.Error())
		return
	}
	user := userFromRequest(r)
	updated, err := s.auth.ChangeUsername(user.UUID, req.Password, username)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "password is incorrect")
		case errors.Is(err, auth.ErrUsernameTaken):
			writeError(w, http.StatusConflict, "username_taken", "username already taken")
		default:
			s.log.Error("change username", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		}
		return
	}
	writeJSON(w, http.StatusOK, userResponse{
		UUID:     updated.UUID,
		Username: updated.Username,
		IsAdmin:  updated.IsAdmin,
		Quota:    updated.Quota,
	})
}

// handleSessions lists the caller's live sessions.
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	current := sessionFamilyFromRequest(r)
	sessions, err := s.auth.ListSessions(user.UUID)
	if err != nil {
		s.log.Error("list sessions", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	out := make([]sessionResponse, 0, len(sessions))
	for _, m := range sessions {
		out = append(out, sessionResponse{
			ID:        m.Family,
			CreatedAt: m.CreatedAt,
			LastSeen:  m.LastSeen,
			UserAgent: m.UserAgent,
			IP:        m.IP,
			Current:   current != "" && m.Family == current,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// handleRevokeSession ends one of the caller's sessions.
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	if err := s.auth.RevokeSession(user.UUID, r.PathValue("id")); err != nil {
		s.log.Error("revoke session", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeAll signs the authenticated user out of every device.
func (s *Server) handleRevokeAll(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	n, err := s.auth.RevokeAll(user.UUID)
	if err != nil {
		s.log.Error("revoke all", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

// handleCreatePAT mints a personal API token, returning the secret once.
func (s *Server) handleCreatePAT(w http.ResponseWriter, r *http.Request) {
	var req createPATRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 64 {
		writeError(w, http.StatusBadRequest, "bad_request", "name must be 1-64 characters")
		return
	}
	if req.ExpiresIn < 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "expires_in must not be negative")
		return
	}
	user := userFromRequest(r)
	secret, rec, err := s.auth.CreatePAT(user.UUID, name, time.Duration(req.ExpiresIn)*time.Second)
	if err != nil {
		s.log.Error("create pat", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	resp := patToResponse(*rec)
	resp.Token = secret
	writeJSON(w, http.StatusCreated, resp)
}

// handleListPATs lists the caller's personal tokens, never the secrets.
func (s *Server) handleListPATs(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	recs, err := s.auth.ListPATs(user.UUID)
	if err != nil {
		s.log.Error("list pats", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	out := make([]patResponse, 0, len(recs))
	for _, rec := range recs {
		out = append(out, patToResponse(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

// handleRevokePAT deletes a personal token by id.
func (s *Server) handleRevokePAT(w http.ResponseWriter, r *http.Request) {
	user := userFromRequest(r)
	if err := s.auth.RevokePAT(user.UUID, r.PathValue("id")); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown token")
			return
		}
		s.log.Error("revoke pat", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
