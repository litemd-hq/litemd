package httpapi

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/litemd-hq/litemd/internal/auth"
	bolt "github.com/litemd-hq/litemd/internal/bolt"
	"github.com/litemd-hq/litemd/internal/config"
)

type adminUserResponse struct {
	UUID      string    `json:"uuid"`
	Username  string    `json:"username"`
	IsAdmin   bool      `json:"is_admin"`
	Quota     int64     `json:"quota_bytes"`
	UsedBytes int64     `json:"used_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

type adminCreateRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	QuotaBytes *int64 `json:"quota_bytes"`
	IsAdmin    *bool  `json:"is_admin"`
}

type updateUserRequest struct {
	Username   *string `json:"username"`
	QuotaBytes *int64  `json:"quota_bytes"`
	IsAdmin    *bool   `json:"is_admin"`
}

type resetPasswordRequest struct {
	Password string `json:"password"`
}

func (s *Server) adminUserView(u *bolt.User) adminUserResponse {
	used, err := s.store.UsedBytes(u.UUID)
	if err != nil {
		s.log.Error("used bytes", "uuid", u.UUID, "err", err)
	}
	return adminUserResponse{
		UUID:      u.UUID,
		Username:  u.Username,
		IsAdmin:   u.IsAdmin,
		Quota:     u.Quota,
		UsedBytes: used,
		CreatedAt: u.CreatedAt,
	}
}

// handleListUsers returns every account with its usage.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.auth.ListUsers()
	if err != nil {
		s.log.Error("list users", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	out := make([]adminUserResponse, 0, len(users))
	for i := range users {
		out = append(out, s.adminUserView(&users[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// handleCreateUser creates a user as an admin, bypassing the registration gate.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req adminCreateRequest
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
	quota := s.cfg.QuotaBytes
	if req.QuotaBytes != nil {
		if *req.QuotaBytes < 0 {
			writeError(w, http.StatusBadRequest, "bad_request", "quota_bytes must not be negative")
			return
		}
		quota = *req.QuotaBytes
	}
	isAdmin := req.IsAdmin != nil && *req.IsAdmin
	user, err := s.auth.Register(auth.RegisterOptions{
		Username:        username,
		Password:        req.Password,
		Quota:           quota,
		IsAdmin:         isAdmin,
		AdminAuthorized: true,
		Open:            true,
	})
	if err != nil {
		if errors.Is(err, auth.ErrUsernameTaken) {
			writeError(w, http.StatusConflict, "username_taken", "username already taken")
			return
		}
		s.log.Error("create user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusCreated, s.adminUserView(user))
}

// handleGetUser returns one account.
func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.UserByUUID(r.PathValue("uuid"))
	if storeNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "unknown user")
		return
	}
	if err != nil {
		s.log.Error("get user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, s.adminUserView(u))
}

// handleUpdateUser changes a user's username, quota and/or admin flag.
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req updateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if req.QuotaBytes != nil && *req.QuotaBytes < 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "quota_bytes must not be negative")
		return
	}
	uuid := r.PathValue("uuid")
	if req.Username != nil {
		name, err := config.NormalizeUsername(*req.Username)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_username", err.Error())
			return
		}
		if _, err := s.auth.RenameUser(uuid, name); err != nil {
			switch {
			case errors.Is(err, auth.ErrNotFound):
				writeError(w, http.StatusNotFound, "not_found", "unknown user")
			case errors.Is(err, auth.ErrUsernameTaken):
				writeError(w, http.StatusConflict, "username_taken", "username already taken")
			default:
				s.log.Error("rename user", "err", err)
				writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			}
			return
		}
	}
	u, err := s.auth.UpdateUser(uuid, req.QuotaBytes, req.IsAdmin)
	switch {
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "unknown user")
		return
	case errors.Is(err, auth.ErrLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", "cannot demote the last administrator")
		return
	case err != nil:
		s.log.Error("update user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, s.adminUserView(u))
}

// handleDeleteUser removes an account, its records and its files.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if actor := userFromRequest(r); actor != nil && actor.UUID == uuid {
		writeError(w, http.StatusBadRequest, "invalid_request", "you cannot delete your own account")
		return
	}
	err := s.auth.DeleteUser(uuid)
	switch {
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "unknown user")
		return
	case errors.Is(err, auth.ErrLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", "cannot delete the last administrator")
		return
	case err != nil:
		s.log.Error("delete user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	// The database no longer references the files; drop them best-effort.
	if err := os.RemoveAll(s.cfg.UserRoot(uuid)); err != nil {
		s.log.Error("remove user files", "uuid", uuid, "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminResetPassword sets a new password for another user.
func (s *Server) handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if err := config.ValidatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, "bad_password", err.Error())
		return
	}
	err := s.auth.ResetPassword(r.PathValue("uuid"), req.Password)
	switch {
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "unknown user")
		return
	case err != nil:
		s.log.Error("reset password", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminRevokeUser signs a user out of every device.
func (s *Server) handleAdminRevokeUser(w http.ResponseWriter, r *http.Request) {
	n, err := s.auth.RevokeAll(r.PathValue("uuid"))
	if err != nil {
		s.log.Error("revoke user", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}
