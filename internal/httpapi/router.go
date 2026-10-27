// Package httpapi wires the HTTP handlers, middleware and routing for the
// /api/v1 surface plus /healthz.
package httpapi

import (
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/litemd-hq/litemd/internal/auth"
	bolt "github.com/litemd-hq/litemd/internal/bolt"
	"github.com/litemd-hq/litemd/internal/config"
)

type Server struct {
	cfg     *config.Config
	store   *bolt.Store
	auth    *auth.Service
	log     *slog.Logger
	limiter *limiter
	trusted []netip.Prefix
}

func New(cfg *config.Config, store *bolt.Store, authSvc *auth.Service, log *slog.Logger) *Server {
	burst, refill := cfg.RateLimitBurst, cfg.RateLimitRefillPerSec
	if burst < 1 || refill <= 0 {
		// A non-positive bucket would reject every request; fall back rather
		// than lock everyone out. config.Parse validates the real path.
		log.Warn("invalid rate limit settings, using defaults",
			"burst", burst, "refill_per_sec", refill)
		burst, refill = config.DefaultRateLimitBurst, config.DefaultRateLimitRefillPerSec
	}
	lim := newLimiter(burst, refill)
	lim.start(15 * time.Minute)
	return &Server{
		cfg:     cfg,
		store:   store,
		auth:    authSvc,
		log:     log,
		limiter: lim,
		trusted: parseTrustedProxies(cfg.TrustedProxies, log),
	}
}

// Close stops background goroutines owned by the server.
func (s *Server) Close() { s.limiter.stop() }

// parseTrustedProxies turns IP/CIDR strings into prefixes for X-Forwarded-For
// trust decisions. Unparseable entries are reported and skipped.
func parseTrustedProxies(list []string, log *slog.Logger) []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range list {
		if p, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		log.Warn("ignoring unparseable trusted proxy", "value", raw)
	}
	return out
}

// Handler returns the fully wrapped root handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("POST /api/v1/auth/register", s.handleRegister)
	mux.HandleFunc("POST /api/v1/auth/login", s.rateLimit(s.handleLogin))
	mux.HandleFunc("POST /api/v1/auth/refresh", s.rateLimit(s.handleRefresh))
	mux.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)
	mux.HandleFunc("POST /api/v1/auth/revoke-all", s.requireAuth(s.handleRevokeAll))

	// Account self-service: profile, password, sessions and personal tokens.
	mux.HandleFunc("GET /api/v1/auth/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("POST /api/v1/auth/password", s.requireAuth(s.rateLimit(s.handleChangePassword)))
	mux.HandleFunc("POST /api/v1/auth/username", s.requireAuth(s.rateLimit(s.handleChangeUsername)))
	mux.HandleFunc("GET /api/v1/auth/sessions", s.requireAuth(s.handleSessions))
	mux.HandleFunc("DELETE /api/v1/auth/sessions/{id}", s.requireAuth(s.handleRevokeSession))
	mux.HandleFunc("GET /api/v1/auth/tokens", s.requireAuth(s.handleListPATs))
	mux.HandleFunc("POST /api/v1/auth/tokens", s.requireAuth(s.rateLimit(s.handleCreatePAT)))
	mux.HandleFunc("DELETE /api/v1/auth/tokens/{id}", s.requireAuth(s.handleRevokePAT))

	// Admin user management.
	mux.HandleFunc("GET /api/v1/users", s.requireAdmin(s.handleListUsers))
	mux.HandleFunc("POST /api/v1/users", s.requireAdmin(s.handleCreateUser))
	mux.HandleFunc("GET /api/v1/users/{uuid}", s.requireAdmin(s.handleGetUser))
	mux.HandleFunc("PATCH /api/v1/users/{uuid}", s.requireAdmin(s.handleUpdateUser))
	mux.HandleFunc("DELETE /api/v1/users/{uuid}", s.requireAdmin(s.handleDeleteUser))
	mux.HandleFunc("POST /api/v1/users/{uuid}/password", s.requireAdmin(s.handleAdminResetPassword))
	mux.HandleFunc("POST /api/v1/users/{uuid}/revoke", s.requireAdmin(s.handleAdminRevokeUser))

	mux.HandleFunc("GET /api/v1/files", s.requireAuth(s.handleManifest))
	mux.HandleFunc("GET /api/v1/files/{path...}", s.requireAuth(s.handleDownload))
	mux.HandleFunc("PUT /api/v1/files/{path...}", s.requireAuth(s.handleUpload))
	mux.HandleFunc("DELETE /api/v1/files/{path...}", s.requireAuth(s.handleDelete))

	// Folders are first-class synced records: GET lists them (tombstones
	// included), PUT creates an (empty) folder, DELETE tombstones one, and POST
	// moves/renames a folder and its contents in a single transaction.
	mux.HandleFunc("GET /api/v1/folders", s.requireAuth(s.handleFolders))
	mux.HandleFunc("PUT /api/v1/folders/{path...}", s.requireAuth(s.handleFolderPut))
	mux.HandleFunc("DELETE /api/v1/folders/{path...}", s.requireAuth(s.handleFolderDelete))
	mux.HandleFunc("POST /api/v1/folders/{path...}", s.requireAuth(s.handleFolderMove))

	// Derived indexes: tags, wikilinks and the note graph.
	mux.HandleFunc("GET /api/v1/tags", s.requireAuth(s.handleTags))
	mux.HandleFunc("GET /api/v1/tags/{tag}", s.requireAuth(s.handleTagFiles))
	mux.HandleFunc("GET /api/v1/links/{path...}", s.requireAuth(s.handleLinks))
	mux.HandleFunc("GET /api/v1/backlinks/{path...}", s.requireAuth(s.handleBacklinks))
	mux.HandleFunc("GET /api/v1/unresolved", s.requireAuth(s.handleUnresolved))
	mux.HandleFunc("GET /api/v1/graph", s.requireAuth(s.handleGraph))

	return s.wrap(mux)
}
