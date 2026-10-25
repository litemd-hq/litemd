package httpapi

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	bolt "github.com/litemd-hq/litemd/internal/bolt"
)

type ctxKey int

const userKey ctxKey = iota

// userFromRequest returns the authenticated user set by requireAuth.
func userFromRequest(r *http.Request) *bolt.User {
	u, _ := r.Context().Value(userKey).(*bolt.User)
	return u
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(h, prefix) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		uuid, err := s.auth.ParseAccess(strings.TrimPrefix(h, prefix))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired access token")
			return
		}
		user, err := s.store.UserByUUID(uuid)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired access token")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey, user)))
	}
}

// requireAdmin wraps an unauthenticated route that may optionally carry an
// admin token (used by POST /auth/register once the first user exists).
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(h, prefix) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "registration requires an admin token")
			return
		}
		uuid, err := s.auth.ParseAccess(strings.TrimPrefix(h, prefix))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired access token")
			return
		}
		user, err := s.store.UserByUUID(uuid)
		if err != nil || !user.IsAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "admin privileges required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey, user)))
	}
}

// --- rate limiting (in-memory token bucket, per IP) ---

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	capacity float64
	refill   float64 // tokens per second
	done     chan struct{}
	stopOnce sync.Once
}

func newLimiter(capacity int, refillPerSec float64) *limiter {
	return &limiter{
		buckets:  make(map[string]*bucket),
		capacity: float64(capacity),
		refill:   refillPerSec,
		done:     make(chan struct{}),
	}
}

func (l *limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.capacity, last: now}
		l.buckets[key] = b
	} else {
		b.tokens += now.Sub(b.last).Seconds() * l.refill
		if b.tokens > l.capacity {
			b.tokens = l.capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// start runs the idle-bucket sweeper until stop is called.
func (l *limiter) start(interval time.Duration) {
	go l.sweep(interval)
}

// stop ends the sweeper goroutine; safe to call more than once.
func (l *limiter) stop() {
	l.stopOnce.Do(func() { close(l.done) })
}

// sweep drops idle buckets so the map cannot grow unbounded.
func (l *limiter) sweep(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-t.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-time.Hour)
			for k, b := range l.buckets {
				if b.last.Before(cutoff) {
					delete(l.buckets, k)
				}
			}
			l.mu.Unlock()
		}
	}
}

// clientIP returns the address to rate-limit on. X-Forwarded-For is honored
// only when the immediate peer is a configured trusted proxy, walking the list
// right-to-left to the first untrusted hop.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return host
	}
	if !s.peerTrusted(peer) {
		return peer.String()
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer.String()
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		if !s.peerTrusted(addr) {
			return addr.String()
		}
	}
	return peer.String()
}

func (s *Server) peerTrusted(addr netip.Addr) bool {
	for _, p := range s.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.Allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", "30")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, slow down")
			return
		}
		next(w, r)
	}
}

// --- logging, recovery, security headers ---

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		sw.Header().Set("X-Content-Type-Options", "nosniff")
		if r.TLS != nil {
			sw.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic recovered", "panic", rec, "path", r.URL.Path)
				if sw.status == 0 {
					writeError(sw, http.StatusInternalServerError, "internal", "internal server error")
				}
			}
			s.log.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration", time.Since(start).Round(time.Microsecond),
				"remote", r.RemoteAddr,
			)
		}()
		next.ServeHTTP(sw, r)
	})
}
