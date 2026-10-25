package httpapi

import (
	"errors"
	"net/http"

	"github.com/litemd-hq/litemd/internal/auth"
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

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// handleRegister: the first user of a fresh database becomes admin and may
// register without a token; afterwards an admin bearer token is required.
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

	count, err := s.store.CountUsers()
	if err != nil {
		s.log.Error("count users", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if count > 0 {
		// Delegate to the admin check but run the registration logic here.
		s.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
			s.createUser(w, r, username, req.Password)
		})(w, r)
		return
	}
	s.createUser(w, r, username, req.Password)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, username, password string) {
	user, err := s.auth.Register(username, password, s.cfg.QuotaBytes)
	if err != nil {
		if errors.Is(err, auth.ErrUsernameTaken) {
			writeError(w, http.StatusConflict, "username_taken", "username already taken")
			return
		}
		s.log.Error("register", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
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
	pair, err := s.auth.Login(req.Username, req.Password)
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
		writeError(w, http.StatusUnauthorized, "token_revoked", "refresh token reuse detected; family revoked")
	case errors.Is(err, auth.ErrTokenExpired):
		writeError(w, http.StatusUnauthorized, "token_expired", "refresh token expired")
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "unknown refresh token")
	default:
		s.log.Error("refresh", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if err := s.auth.Logout(req.RefreshToken); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unknown refresh token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeAll signs the authenticated user out of every device by deleting
// all of their refresh tokens. Access tokens remain valid until they expire.
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
