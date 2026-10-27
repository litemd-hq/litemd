package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultQuotaBytes      = int64(1 << 30)  // 1 GiB
	DefaultMaxUpload       = int64(64 << 20) // 64 MiB
	DefaultAccessTokenTTL  = 15 * time.Minute
	DefaultRefreshTokenTTL = 7 * 24 * time.Hour

	// DefaultRateLimitBurst is how many auth requests a client may make in a
	// burst before being throttled. DefaultRateLimitRefillPerSec is the
	// sustained refill rate (tokens per second).
	DefaultRateLimitBurst        = 10
	DefaultRateLimitRefillPerSec = 0.1

	// DefaultLogLevel keeps per-request logging on; raise it to reduce writes
	// to slow or wear-sensitive storage such as an SD card.
	DefaultLogLevel = "info"

	// DefaultLogFormat renders logs for humans; switch to "json" for
	// machine-consumed output (journald, log shippers).
	DefaultLogFormat = "text"

	// Registration policy values. RegistrationAdmin preserves the historical
	// behavior: the first user of an empty database may register, and every
	// later registration needs an admin token. RegistrationOpen lets anyone
	// register at any time (the first user still becomes the admin); the first
	// user is always allowed unless the policy is RegistrationClosed, which
	// rejects HTTP registration entirely (manage accounts with `litemd user`).
	RegistrationOpen   = "open"
	RegistrationAdmin  = "admin"
	RegistrationClosed = "closed"

	// DefaultRegistration is the registration policy used when none is set.
	DefaultRegistration = RegistrationAdmin
)

// LogLevels are the accepted values for the log level setting.
var LogLevels = []string{"debug", "info", "warn", "error"}

// LogFormats are the accepted values for the log format setting.
var LogFormats = []string{"text", "json"}

// Registrations are the accepted values for the registration policy setting.
var Registrations = []string{RegistrationOpen, RegistrationAdmin, RegistrationClosed}

const configEnv = "LITEMD_CONFIG"

type Config struct {
	Addr            string
	DataDir         string
	TLSCert         string
	TLSKey          string
	Insecure        bool
	QuotaBytes      int64
	MaxUpload       int64
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// TrustedProxies lists IPs/CIDRs whose X-Forwarded-For header is
	// believed. Empty means the header is ignored entirely.
	TrustedProxies []string

	// RateLimitBurst is the per-client token bucket size for auth endpoints and
	// RateLimitRefillPerSec the sustained refill rate. Raise the burst when many
	// legitimate users share one source address (office NAT, CGNAT).
	RateLimitBurst        int
	RateLimitRefillPerSec float64

	// LogLevel is one of debug, info, warn or error.
	LogLevel string

	// LogFormat is one of text or json.
	LogFormat string

	// Registration is one of open, admin or closed; it controls how new users
	// may be created over HTTP.
	Registration string
}

// duration accepts either a Go duration string ("15m", "168h") or a raw
// nanosecond count in JSON.
type duration time.Duration

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf(`duration must be a string like "15m" or a number of nanoseconds`)
	}
	*d = duration(n)
	return nil
}

// fileConfig mirrors Config with pointer fields so absent keys stay
// distinguishable from zero values.
type fileConfig struct {
	Addr           *string   `json:"addr"`
	DataDir        *string   `json:"data_dir"`
	TLSCert        *string   `json:"tls_cert"`
	TLSKey         *string   `json:"tls_key"`
	Insecure       *bool     `json:"insecure"`
	QuotaBytes     *int64    `json:"quota_bytes"`
	MaxUpload      *int64    `json:"max_upload"`
	AccessTTL      *duration `json:"access_ttl"`
	RefreshTTL     *duration `json:"refresh_ttl"`
	TrustedProxies *[]string `json:"trusted_proxies"`

	RateLimitBurst        *int     `json:"rate_limit_burst"`
	RateLimitRefillPerSec *float64 `json:"rate_limit_refill_per_sec"`
	LogLevel              *string  `json:"log_level"`
	LogFormat             *string  `json:"log_format"`
	Registration          *string  `json:"registration"`
}

// builtin returns the compiled-in defaults, used for every value not supplied
// elsewhere.
func builtin() *Config {
	return &Config{
		Addr:                  ":8443",
		DataDir:               "./data",
		QuotaBytes:            DefaultQuotaBytes,
		MaxUpload:             DefaultMaxUpload,
		AccessTokenTTL:        DefaultAccessTokenTTL,
		RefreshTokenTTL:       DefaultRefreshTokenTTL,
		RateLimitBurst:        DefaultRateLimitBurst,
		RateLimitRefillPerSec: DefaultRateLimitRefillPerSec,
		LogLevel:              DefaultLogLevel,
		LogFormat:             DefaultLogFormat,
		Registration:          DefaultRegistration,
	}
}

// Parse resolves configuration from, in increasing precedence: built-in
// defaults, a JSON config file (-config / LITEMD_CONFIG), LITEMD_* environment
// variables, then explicit command-line flags.
func Parse(args []string) (*Config, error) {
	var fv flagConfig
	fs := newFlagSet(&fv)

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument: %q", fs.Arg(0))
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	cfg := builtin()

	path := os.Getenv(configEnv)
	if set["config"] {
		path = fv.config
	}
	if path != "" {
		if err := applyFile(cfg, path); err != nil {
			return nil, err
		}
	}

	if err := applyEnv(cfg); err != nil {
		return nil, err
	}
	applyFlags(cfg, &fv, set)

	return validate(cfg)
}

// newFlagSet declares every server flag. Keeping it in one place lets the CLI
// print the same list the parser accepts.
func newFlagSet(fv *flagConfig) *flag.FlagSet {
	fs := flag.NewFlagSet("litemd", flag.ContinueOnError)
	fs.StringVar(&fv.config, "config", "", "path to a JSON config file")
	fs.StringVar(&fv.addr, "addr", ":8443", "listen address")
	fs.StringVar(&fv.data, "data", "./data", "data directory (database, TLS certs, user files)")
	fs.StringVar(&fv.tlsCert, "tls-cert", "", "TLS certificate path (default: auto-generate into data dir)")
	fs.StringVar(&fv.tlsKey, "tls-key", "", "TLS private key path (default: auto-generate into data dir)")
	fs.BoolVar(&fv.insecure, "insecure", false, "serve plain HTTP; use only behind a TLS-terminating proxy")
	fs.Int64Var(&fv.quotaBytes, "quota-bytes", DefaultQuotaBytes, "default per-user storage quota in bytes")
	fs.Int64Var(&fv.maxUpload, "max-upload", DefaultMaxUpload, "maximum accepted upload body size in bytes")
	fs.DurationVar(&fv.accessTTL, "access-ttl", DefaultAccessTokenTTL, "access token lifetime")
	fs.DurationVar(&fv.refreshTTL, "refresh-ttl", DefaultRefreshTokenTTL, "refresh token lifetime")
	fs.StringVar(&fv.trustedProxies, "trusted-proxies", "", "comma-separated IPs/CIDRs whose X-Forwarded-For is trusted")
	fs.IntVar(&fv.rateLimitBurst, "rate-limit-burst", DefaultRateLimitBurst, "auth rate limit burst per client")
	fs.Float64Var(&fv.rateLimitRefill, "rate-limit-refill-per-sec", DefaultRateLimitRefillPerSec, "auth rate limit token refill per second")
	fs.StringVar(&fv.logLevel, "log-level", DefaultLogLevel, "log level: debug, info, warn or error")
	fs.StringVar(&fv.logFormat, "log-format", DefaultLogFormat, "log format: text or json")
	fs.StringVar(&fv.registration, "registration", DefaultRegistration, "registration policy: open, admin or closed")
	return fs
}

// ServerUsage writes the server flag list to w.
func ServerUsage(w io.Writer) {
	fs := newFlagSet(&flagConfig{})
	fs.SetOutput(w)
	fs.PrintDefaults()
}

func applyFile(cfg *Config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("config file: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var fc fileConfig
	if err := dec.Decode(&fc); err != nil {
		return fmt.Errorf("config file %s: %w", path, err)
	}

	if fc.Addr != nil {
		cfg.Addr = *fc.Addr
	}
	if fc.DataDir != nil {
		cfg.DataDir = *fc.DataDir
	}
	if fc.TLSCert != nil {
		cfg.TLSCert = *fc.TLSCert
	}
	if fc.TLSKey != nil {
		cfg.TLSKey = *fc.TLSKey
	}
	if fc.Insecure != nil {
		cfg.Insecure = *fc.Insecure
	}
	if fc.QuotaBytes != nil {
		cfg.QuotaBytes = *fc.QuotaBytes
	}
	if fc.MaxUpload != nil {
		cfg.MaxUpload = *fc.MaxUpload
	}
	if fc.AccessTTL != nil {
		cfg.AccessTokenTTL = time.Duration(*fc.AccessTTL)
	}
	if fc.RefreshTTL != nil {
		cfg.RefreshTokenTTL = time.Duration(*fc.RefreshTTL)
	}
	if fc.TrustedProxies != nil {
		cfg.TrustedProxies = *fc.TrustedProxies
	}
	if fc.RateLimitBurst != nil {
		cfg.RateLimitBurst = *fc.RateLimitBurst
	}
	if fc.RateLimitRefillPerSec != nil {
		cfg.RateLimitRefillPerSec = *fc.RateLimitRefillPerSec
	}
	if fc.LogLevel != nil {
		cfg.LogLevel = *fc.LogLevel
	}
	if fc.LogFormat != nil {
		cfg.LogFormat = *fc.LogFormat
	}
	if fc.Registration != nil {
		cfg.Registration = *fc.Registration
	}
	return nil
}

func applyEnv(cfg *Config) error {
	if v, ok := os.LookupEnv("LITEMD_ADDR"); ok {
		cfg.Addr = v
	}
	if v, ok := os.LookupEnv("LITEMD_DATA_DIR"); ok {
		cfg.DataDir = v
	}
	if v, ok := os.LookupEnv("LITEMD_TLS_CERT"); ok {
		cfg.TLSCert = v
	}
	if v, ok := os.LookupEnv("LITEMD_TLS_KEY"); ok {
		cfg.TLSKey = v
	}
	if v, ok := os.LookupEnv("LITEMD_TRUSTED_PROXIES"); ok {
		cfg.TrustedProxies = splitList(v)
	}
	if v, ok := os.LookupEnv("LITEMD_INSECURE"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("LITEMD_INSECURE: %w", err)
		}
		cfg.Insecure = b
	}
	if v, ok := os.LookupEnv("LITEMD_QUOTA_BYTES"); ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("LITEMD_QUOTA_BYTES: %w", err)
		}
		cfg.QuotaBytes = n
	}
	if v, ok := os.LookupEnv("LITEMD_MAX_UPLOAD"); ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("LITEMD_MAX_UPLOAD: %w", err)
		}
		cfg.MaxUpload = n
	}
	if v, ok := os.LookupEnv("LITEMD_ACCESS_TTL"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("LITEMD_ACCESS_TTL: %w", err)
		}
		cfg.AccessTokenTTL = d
	}
	if v, ok := os.LookupEnv("LITEMD_REFRESH_TTL"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("LITEMD_REFRESH_TTL: %w", err)
		}
		cfg.RefreshTokenTTL = d
	}
	if v, ok := os.LookupEnv("LITEMD_RATE_LIMIT_BURST"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("LITEMD_RATE_LIMIT_BURST: %w", err)
		}
		cfg.RateLimitBurst = n
	}
	if v, ok := os.LookupEnv("LITEMD_RATE_LIMIT_REFILL_PER_SEC"); ok {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("LITEMD_RATE_LIMIT_REFILL_PER_SEC: %w", err)
		}
		cfg.RateLimitRefillPerSec = f
	}
	if v, ok := os.LookupEnv("LITEMD_LOG_LEVEL"); ok {
		cfg.LogLevel = v
	}
	if v, ok := os.LookupEnv("LITEMD_LOG_FORMAT"); ok {
		cfg.LogFormat = v
	}
	if v, ok := os.LookupEnv("LITEMD_REGISTRATION"); ok {
		cfg.Registration = v
	}
	return nil
}

type flagConfig struct {
	config          string
	addr            string
	data            string
	tlsCert         string
	tlsKey          string
	insecure        bool
	quotaBytes      int64
	maxUpload       int64
	accessTTL       time.Duration
	refreshTTL      time.Duration
	trustedProxies  string
	rateLimitBurst  int
	rateLimitRefill float64
	logLevel        string
	logFormat       string
	registration    string
}

func applyFlags(cfg *Config, fv *flagConfig, set map[string]bool) {
	if set["addr"] {
		cfg.Addr = fv.addr
	}
	if set["data"] {
		cfg.DataDir = fv.data
	}
	if set["tls-cert"] {
		cfg.TLSCert = fv.tlsCert
	}
	if set["tls-key"] {
		cfg.TLSKey = fv.tlsKey
	}
	if set["insecure"] {
		cfg.Insecure = fv.insecure
	}
	if set["quota-bytes"] {
		cfg.QuotaBytes = fv.quotaBytes
	}
	if set["max-upload"] {
		cfg.MaxUpload = fv.maxUpload
	}
	if set["access-ttl"] {
		cfg.AccessTokenTTL = fv.accessTTL
	}
	if set["refresh-ttl"] {
		cfg.RefreshTokenTTL = fv.refreshTTL
	}
	if set["trusted-proxies"] {
		cfg.TrustedProxies = splitList(fv.trustedProxies)
	}
	if set["rate-limit-burst"] {
		cfg.RateLimitBurst = fv.rateLimitBurst
	}
	if set["rate-limit-refill-per-sec"] {
		cfg.RateLimitRefillPerSec = fv.rateLimitRefill
	}
	if set["log-level"] {
		cfg.LogLevel = fv.logLevel
	}
	if set["log-format"] {
		cfg.LogFormat = fv.logFormat
	}
	if set["registration"] {
		cfg.Registration = fv.registration
	}
}

// Validate checks a fully-resolved configuration for internal consistency. It
// is exported so other entry points (such as `litemd init`) share the exact
// same rules the server enforces.
func Validate(cfg *Config) error {
	_, err := validate(cfg)
	return err
}

func validate(cfg *Config) (*Config, error) {
	if cfg.QuotaBytes <= 0 || cfg.MaxUpload <= 0 {
		return nil, fmt.Errorf("quota-bytes and max-upload must be positive")
	}
	if cfg.AccessTokenTTL <= 0 || cfg.RefreshTokenTTL <= 0 {
		return nil, fmt.Errorf("access-ttl and refresh-ttl must be positive")
	}
	if cfg.RefreshTokenTTL < cfg.AccessTokenTTL {
		return nil, fmt.Errorf("refresh-ttl must be at least access-ttl")
	}
	onlyCert := cfg.TLSCert != "" && cfg.TLSKey == ""
	onlyKey := cfg.TLSKey != "" && cfg.TLSCert == ""
	if onlyCert || onlyKey {
		return nil, fmt.Errorf("tls-cert and tls-key must be provided together")
	}
	if cfg.Insecure && cfg.TLSCert != "" {
		return nil, fmt.Errorf("insecure mode ignores tls-cert and tls-key; drop one or the other")
	}
	if cfg.RateLimitBurst < 1 {
		return nil, fmt.Errorf("rate-limit-burst must be at least 1")
	}
	if cfg.RateLimitRefillPerSec <= 0 {
		return nil, fmt.Errorf("rate-limit-refill-per-sec must be positive")
	}
	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	if cfg.LogLevel == "warning" {
		cfg.LogLevel = "warn"
	}
	if !slices.Contains(LogLevels, cfg.LogLevel) {
		return nil, fmt.Errorf("log-level must be one of %s", strings.Join(LogLevels, ", "))
	}
	cfg.LogFormat = strings.ToLower(strings.TrimSpace(cfg.LogFormat))
	if !slices.Contains(LogFormats, cfg.LogFormat) {
		return nil, fmt.Errorf("log-format must be one of %s", strings.Join(LogFormats, ", "))
	}
	cfg.Registration = strings.ToLower(strings.TrimSpace(cfg.Registration))
	if cfg.Registration == "" {
		cfg.Registration = DefaultRegistration
	}
	if !slices.Contains(Registrations, cfg.Registration) {
		return nil, fmt.Errorf("registration must be one of %s", strings.Join(Registrations, ", "))
	}
	return cfg, nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// UserRoot returns the per-user storage root: <data>/users/<uuid>.
func (c *Config) UserRoot(userUUID string) string {
	return c.DataDir + string(os.PathSeparator) + "users" + string(os.PathSeparator) + userUUID
}

// NormalizeUsername validates and returns a canonical username.
func NormalizeUsername(name string) (string, error) {
	name = strings.TrimSpace(name)
	if len(name) < 3 || len(name) > 32 {
		return "", fmt.Errorf("username must be 3-32 characters")
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return "", fmt.Errorf("username may only contain letters, digits, '_', '.', '-'")
		}
		if i == 0 && (r == '.' || r == '-') {
			return "", fmt.Errorf("username must start with a letter, digit or '_'")
		}
	}
	return name, nil
}

func ValidatePassword(pw string) error {
	if len(pw) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(pw) > 1024 {
		return fmt.Errorf("password too long")
	}
	return nil
}
