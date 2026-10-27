package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// clearEnv unsets every LITEMD_* variable so tests are isolated from the
// ambient environment.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LITEMD_CONFIG", "LITEMD_ADDR", "LITEMD_DATA_DIR", "LITEMD_TLS_CERT",
		"LITEMD_TLS_KEY", "LITEMD_INSECURE", "LITEMD_QUOTA_BYTES",
		"LITEMD_MAX_UPLOAD", "LITEMD_ACCESS_TTL", "LITEMD_REFRESH_TTL",
		"LITEMD_TRUSTED_PROXIES", "LITEMD_RATE_LIMIT_BURST",
		"LITEMD_RATE_LIMIT_REFILL_PER_SEC",
		"LITEMD_LOG_LEVEL", "LITEMD_LOG_FORMAT", "LITEMD_REGISTRATION",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func TestParseDefaults(t *testing.T) {
	clearEnv(t)
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Addr != ":8443" || cfg.DataDir != "./data" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
	if cfg.QuotaBytes != DefaultQuotaBytes || cfg.MaxUpload != DefaultMaxUpload {
		t.Errorf("unexpected size defaults: %+v", cfg)
	}
	if cfg.AccessTokenTTL != DefaultAccessTokenTTL || cfg.RefreshTokenTTL != DefaultRefreshTokenTTL {
		t.Errorf("unexpected ttl defaults: %+v", cfg)
	}
}

func TestParseFromFile(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, `{
		"addr": ":9999",
		"data_dir": "/srv/litemd",
		"contains_unknown": true
	}`)
	// Unknown keys are rejected with a clear error.
	if _, err := Parse([]string{"-config", path}); err == nil {
		t.Fatal("unknown field should be rejected")
	}

	path = writeConfig(t, `{
		"addr": ":9999",
		"data_dir": "/srv/litemd",
		"quota_bytes": 2048,
		"access_ttl": "30m",
		"refresh_ttl": 604800000000000,
		"trusted_proxies": ["10.0.0.0/8"],
		"rate_limit_burst": 50,
		"rate_limit_refill_per_sec": 2.5
	}`)
	cfg, err := Parse([]string{"-config", path})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Addr != ":9999" || cfg.DataDir != "/srv/litemd" {
		t.Errorf("file values not applied: %+v", cfg)
	}
	if cfg.QuotaBytes != 2048 {
		t.Errorf("quota = %d, want 2048", cfg.QuotaBytes)
	}
	if cfg.AccessTokenTTL != 30*time.Minute {
		t.Errorf("access ttl = %v, want 30m", cfg.AccessTokenTTL)
	}
	// Numeric durations are nanoseconds.
	if cfg.RefreshTokenTTL != 168*time.Hour {
		t.Errorf("refresh ttl = %v, want 168h", cfg.RefreshTokenTTL)
	}
	if len(cfg.TrustedProxies) != 1 || cfg.TrustedProxies[0] != "10.0.0.0/8" {
		t.Errorf("trusted proxies = %v", cfg.TrustedProxies)
	}
	if cfg.RateLimitBurst != 50 || cfg.RateLimitRefillPerSec != 2.5 {
		t.Errorf("rate limit = %d/%v, want 50/2.5", cfg.RateLimitBurst, cfg.RateLimitRefillPerSec)
	}
}

func TestRateLimitDefaultsAndOverrides(t *testing.T) {
	clearEnv(t)
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.RateLimitBurst != DefaultRateLimitBurst || cfg.RateLimitRefillPerSec != DefaultRateLimitRefillPerSec {
		t.Errorf("rate limit defaults = %d/%v", cfg.RateLimitBurst, cfg.RateLimitRefillPerSec)
	}

	t.Setenv("LITEMD_RATE_LIMIT_BURST", "7")
	cfg, err = Parse([]string{"-rate-limit-refill-per-sec", "0.5"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.RateLimitBurst != 7 || cfg.RateLimitRefillPerSec != 0.5 {
		t.Errorf("rate limit = %d/%v, want 7/0.5", cfg.RateLimitBurst, cfg.RateLimitRefillPerSec)
	}
}

func TestParseFileViaEnv(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, `{"addr": ":7000"}`)
	t.Setenv("LITEMD_CONFIG", path)

	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Addr != ":7000" {
		t.Errorf("addr = %q, want :7000", cfg.Addr)
	}
}

func TestPrecedenceEnvOverFileAndFlagOverEnv(t *testing.T) {
	clearEnv(t)
	path := writeConfig(t, `{"addr": ":1111", "data_dir": "/from/file"}`)

	// Env beats the file.
	t.Setenv("LITEMD_ADDR", ":2222")
	cfg, err := Parse([]string{"-config", path})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Addr != ":2222" {
		t.Errorf("addr = %q, want env value :2222", cfg.Addr)
	}
	if cfg.DataDir != "/from/file" {
		t.Errorf("data = %q, want file value /from/file", cfg.DataDir)
	}

	// An explicit flag beats env.
	cfg, err = Parse([]string{"-config", path, "-addr", ":3333"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Addr != ":3333" {
		t.Errorf("addr = %q, want flag value :3333", cfg.Addr)
	}
}

func TestParseRejectsBadFile(t *testing.T) {
	clearEnv(t)

	if _, err := Parse([]string{"-config", filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Error("missing config file should error")
	}

	path := writeConfig(t, `{"access_ttl": "not-a-duration"}`)
	if _, err := Parse([]string{"-config", path}); err == nil {
		t.Error("bad duration should error")
	}

	path = writeConfig(t, `{"access_ttl": }`)
	if _, err := Parse([]string{"-config", path}); err == nil {
		t.Error("malformed JSON should error")
	}
}

func TestParseRejectsBadEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("LITEMD_ACCESS_TTL", "nope")
	if _, err := Parse(nil); err == nil {
		t.Error("bad LITEMD_ACCESS_TTL should error")
	}
}

func TestValidateRules(t *testing.T) {
	clearEnv(t)

	cases := [][]string{
		{"-quota-bytes", "0"},
		{"-max-upload", "0"},
		{"-access-ttl", "0s"},
		{"-access-ttl", "2h", "-refresh-ttl", "1h"},
		{"-tls-cert", "/tmp/cert.pem"},
		{"-tls-key", "/tmp/key.pem"},
		{"-insecure", "-tls-cert", "/tmp/cert.pem", "-tls-key", "/tmp/key.pem"},
		{"-rate-limit-burst", "0"},
		{"-rate-limit-refill-per-sec", "0"},
		{"-rate-limit-refill-per-sec", "-1"},
	}
	for _, args := range cases {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%v) should have failed validation", args)
		}
	}
}

func TestLogLevel(t *testing.T) {
	clearEnv(t)
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("default log level = %q, want %q", cfg.LogLevel, DefaultLogLevel)
	}

	// Warnings are accepted and normalized, and the level is case insensitive.
	cfg, err = Parse([]string{"-log-level", "WARNING"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("log level = %q, want warn", cfg.LogLevel)
	}

	// Unknown levels are rejected rather than silently ignored.
	if _, err := Parse([]string{"-log-level", "chatty"}); err == nil {
		t.Error("an unknown log level should be rejected")
	}

	t.Setenv("LITEMD_LOG_LEVEL", "error")
	cfg, err = Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.LogLevel != "error" {
		t.Errorf("log level from env = %q, want error", cfg.LogLevel)
	}
}

func TestLogFormat(t *testing.T) {
	clearEnv(t)
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.LogFormat != DefaultLogFormat {
		t.Errorf("default log format = %q, want %q", cfg.LogFormat, DefaultLogFormat)
	}

	// The format is case insensitive.
	cfg, err = Parse([]string{"-log-format", "JSON"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("log format = %q, want json", cfg.LogFormat)
	}

	// Unknown formats are rejected rather than silently ignored.
	if _, err := Parse([]string{"-log-format", "xml"}); err == nil {
		t.Error("an unknown log format should be rejected")
	}

	t.Setenv("LITEMD_LOG_FORMAT", "json")
	cfg, err = Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("log format from env = %q, want json", cfg.LogFormat)
	}
}

func TestRegistration(t *testing.T) {
	clearEnv(t)
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Registration != DefaultRegistration {
		t.Errorf("default registration = %q, want %q", cfg.Registration, DefaultRegistration)
	}

	// The policy is case insensitive.
	cfg, err = Parse([]string{"-registration", "OPEN"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Registration != RegistrationOpen {
		t.Errorf("registration = %q, want open", cfg.Registration)
	}

	// Unknown policies are rejected rather than silently ignored.
	if _, err := Parse([]string{"-registration", "whatever"}); err == nil {
		t.Error("an unknown registration policy should be rejected")
	}

	t.Setenv("LITEMD_REGISTRATION", "closed")
	cfg, err = Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Registration != RegistrationClosed {
		t.Errorf("registration from env = %q, want closed", cfg.Registration)
	}
}

func TestNormalizeUsername(t *testing.T) {
	if _, err := NormalizeUsername("ab"); err == nil {
		t.Error("too short should fail")
	}
	if _, err := NormalizeUsername("-bad"); err == nil {
		t.Error("leading dash should fail")
	}
	if _, err := NormalizeUsername("has space"); err == nil {
		t.Error("space should fail")
	}
	got, err := NormalizeUsername("  good.name-1  ")
	if err != nil || got != "good.name-1" {
		t.Errorf("got %q, %v", got, err)
	}
}
