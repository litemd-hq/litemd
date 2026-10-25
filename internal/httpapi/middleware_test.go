package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func serverWithProxies(proxies ...string) *Server {
	return &Server{
		limiter: newLimiter(1, 1),
		log:     discardLogger(),
		trusted: parseTrustedProxies(proxies, discardLogger()),
	}
}

func TestParseTrustedProxies(t *testing.T) {
	got := parseTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1", "::1", "not-an-ip", ""}, discardLogger())
	if len(got) != 3 {
		t.Fatalf("parsed %d prefixes, want 3 (invalid entries skipped): %v", len(got), got)
	}
	if !got[0].Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Error("10.0.0.0/8 should contain 10.1.2.3")
	}
	if got[0].Bits() != 8 {
		t.Errorf("prefix bits = %d, want 8", got[0].Bits())
	}
	if !got[1].Contains(netip.MustParseAddr("127.0.0.1")) || got[1].Bits() != 32 {
		t.Errorf("bare IPv4 should become a /32, got %v", got[1])
	}
	if !got[2].Contains(netip.MustParseAddr("::1")) || got[2].Bits() != 128 {
		t.Errorf("bare IPv6 should become a /128, got %v", got[2])
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		proxies    []string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "no proxies trusts the socket address",
			remoteAddr: "203.0.113.7:5555",
			xff:        "1.2.3.4",
			want:       "203.0.113.7",
		},
		{
			name:       "trusted peer uses X-Forwarded-For",
			proxies:    []string{"127.0.0.1/32"},
			remoteAddr: "127.0.0.1:5555",
			xff:        "1.2.3.4",
			want:       "1.2.3.4",
		},
		{
			name:       "walks past trusted hops to the first untrusted",
			proxies:    []string{"127.0.0.1/32", "10.0.0.0/8"},
			remoteAddr: "127.0.0.1:5555",
			xff:        "1.2.3.4, 10.0.0.1",
			want:       "1.2.3.4",
		},
		{
			name:       "untrusted peer cannot spoof via the header",
			proxies:    []string{"10.0.0.0/8"},
			remoteAddr: "203.0.113.7:5555",
			xff:        "1.2.3.4",
			want:       "203.0.113.7",
		},
		{
			name:       "malformed header falls back to the peer",
			proxies:    []string{"127.0.0.1/32"},
			remoteAddr: "127.0.0.1:5555",
			xff:        "garbage",
			want:       "127.0.0.1",
		},
		{
			name:       "ipv6 peer without brackets form",
			remoteAddr: "[2001:db8::1]:5555",
			want:       "2001:db8::1",
		},
		{
			name:       "all hops trusted falls back to the peer",
			proxies:    []string{"127.0.0.1/32", "10.0.0.0/8"},
			remoteAddr: "127.0.0.1:5555",
			xff:        "10.0.0.9",
			want:       "127.0.0.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := serverWithProxies(tc.proxies...)
			r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := s.clientIP(r); got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientIPWithoutPort(t *testing.T) {
	s := serverWithProxies()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r.RemoteAddr = "203.0.113.9" // no port, e.g. a unix socket peer
	if got := s.clientIP(r); got != "203.0.113.9" {
		t.Errorf("clientIP = %q, want 203.0.113.9", got)
	}
}

func TestLimiterStopIsIdempotent(t *testing.T) {
	l := newLimiter(1, 1)
	l.start(10 * time.Millisecond)
	l.stop()
	l.stop() // must not panic on a closed channel
	// The sweeper should have exited; Allow still works afterwards.
	if !l.Allow("x") {
		t.Error("limiter should keep working after stop")
	}
}

func TestLimiterRefills(t *testing.T) {
	l := newLimiter(1, 100) // refills 100 tokens/second
	if !l.Allow("k") {
		t.Fatal("first request should pass")
	}
	if l.Allow("k") {
		t.Fatal("second immediate request should be throttled")
	}
	time.Sleep(30 * time.Millisecond)
	if !l.Allow("k") {
		t.Error("limiter should have refilled")
	}
}

func TestLimiterIsPerKey(t *testing.T) {
	l := newLimiter(1, 0.0001)
	if !l.Allow("a") {
		t.Fatal("a should pass")
	}
	if !l.Allow("b") {
		t.Error("a different key must have its own bucket")
	}
	if l.Allow("a") {
		t.Error("a should now be throttled")
	}
}

func TestServerCloseIsIdempotent(t *testing.T) {
	s := serverWithProxies()
	s.Close()
	s.Close()
}
