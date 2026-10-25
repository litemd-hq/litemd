// Package setup implements `litemd init`: an interactive, dependency-light
// onboarding wizard that writes a configuration file and optionally creates the
// first administrator.
package setup

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/litemd-hq/litemd/internal/auth"
	bolt "github.com/litemd-hq/litemd/internal/bolt"
	"github.com/litemd-hq/litemd/internal/config"
)

const (
	tlsSelfSigned = "self-signed"
	tlsImport     = "import"
	tlsInsecure   = "insecure"
)

type options struct {
	out            string
	dataDir        string
	addr           string
	tlsMode        string
	tlsCert        string
	tlsKey         string
	quota          string
	maxUpload      string
	trustedProxies string
	logLevel       string
	adminUser      string
	adminPass      string
	force          bool
	batch          bool
}

// UI bundles the output stream, styling and input source used by the wizard.
type UI struct {
	in     Prompter
	out    io.Writer
	errOut io.Writer
	style  Style
	// interactive suppresses section headers that would otherwise introduce
	// nothing when running from flags.
	interactive bool
}

// Run executes the init command. in, out and errOut are injected so the whole
// flow can be exercised in tests without a terminal.
func Run(args []string, in Prompter, out, errOut io.Writer) error {
	opts, err := parseFlags(args, out)
	if err != nil {
		return err
	}

	u := &UI{in: in, out: out, errOut: errOut, style: detectStyle(out, os.Getenv)}
	interactive := in.IsTTY() && !opts.batch
	u.interactive = interactive

	u.Heading("litemd setup")
	if interactive {
		u.Hint("Answer the prompts, or press Enter to accept the default.")
	} else {
		u.Hint("Non-interactive: using flags and defaults.")
	}

	asked := func(label, def string, validate func(string) (string, error)) (string, error) {
		if !interactive {
			v, err := validate(def)
			if err != nil {
				return "", fmt.Errorf("%s: %w", label, err)
			}
			return v, nil
		}
		return u.Ask(label, def, validate)
	}

	// --- basic settings -----------------------------------------------------

	if interactive {
		u.Step("Basics")
	}

	dataDir, err := asked("Data directory", opts.dataDir, validateNonEmpty)
	if err != nil {
		return err
	}
	addr, err := asked("Listen address", opts.addr, validateAddr)
	if err != nil {
		return err
	}

	quotaStr, err := asked("Quota per user", opts.quota, sizeValidator)
	if err != nil {
		return err
	}
	quotaBytes, err := parseSize(quotaStr)
	if err != nil {
		return err
	}
	uploadStr, err := asked("Max upload size", opts.maxUpload, sizeValidator)
	if err != nil {
		return err
	}
	maxUpload, err := parseSize(uploadStr)
	if err != nil {
		return err
	}

	// --- TLS ----------------------------------------------------------------

	if interactive {
		u.Step("TLS")
	}
	if interactive {
		u.Hint("Use self-signed on a trusted network or behind a TLS-terminating proxy.")
	}
	tlsMode := opts.tlsMode
	if interactive {
		tlsMode, err = u.AskChoice("Mode", []string{tlsSelfSigned, tlsImport, tlsInsecure}, opts.tlsMode)
		if err != nil {
			return err
		}
	}
	var tlsCert, tlsKey string
	switch tlsMode {
	case tlsImport:
		tlsCert, err = asked("Certificate path", opts.tlsCert, validateNonEmpty)
		if err != nil {
			return err
		}
		tlsKey, err = asked("Private key path", opts.tlsKey, validateNonEmpty)
		if err != nil {
			return err
		}
	case tlsInsecure:
		u.Warn("Plain HTTP: only safe behind a TLS-terminating proxy on loopback.")
	case tlsSelfSigned:
		if interactive {
			u.Hint("A certificate will be generated into the data directory on first boot.")
		}
	default:
		return fmt.Errorf("unknown tls mode %q", tlsMode)
	}

	if interactive {
		u.Step("Proxies")
	}
	proxies, err := asked("Trusted proxies (comma-separated, blank for none)", opts.trustedProxies, alwaysOK)
	if err != nil {
		return err
	}

	// --- logging ---

	if interactive {
		u.Step("Logging")
		u.Hint("Each request logs a line; warn or error keeps writes down on an")
		u.Hint("SD card or other wear-sensitive storage.")
	}
	logLevel, err := asked("Log level", opts.logLevel, logLevelValidator)
	if err != nil {
		return err
	}

	// --- administrator ------------------------------------------------------

	adminUser := opts.adminUser
	adminPass := opts.adminPass
	if adminUser == "" && interactive {
		u.Step("Administrator")
		u.Hint("The first account is created now; later accounts need an admin token.")
		create, err := u.AskBool("Create an administrator now", true)
		if err != nil {
			return err
		}
		if create {
			adminUser, err = u.Ask("Username", "", func(s string) (string, error) {
				return config.NormalizeUsername(s)
			})
			if err != nil {
				return err
			}
			adminPass, err = u.AskSecret("Password", config.ValidatePassword)
			if err != nil {
				return err
			}
		}
	}
	if adminUser != "" {
		if _, err := config.NormalizeUsername(adminUser); err != nil {
			return err
		}
		if err := config.ValidatePassword(adminPass); err != nil {
			return fmt.Errorf("admin password: %w", err)
		}
	}

	// --- assemble and validate ---------------------------------------------

	cfg := &config.Config{
		Addr:                  addr,
		DataDir:               dataDir,
		TLSCert:               tlsCert,
		TLSKey:                tlsKey,
		Insecure:              tlsMode == tlsInsecure,
		QuotaBytes:            quotaBytes,
		MaxUpload:             maxUpload,
		AccessTokenTTL:        config.DefaultAccessTokenTTL,
		RefreshTokenTTL:       config.DefaultRefreshTokenTTL,
		RateLimitBurst:        config.DefaultRateLimitBurst,
		RateLimitRefillPerSec: config.DefaultRateLimitRefillPerSec,
		LogLevel:              logLevel,
	}
	cfg.TrustedProxies = splitProxies(proxies)
	if err := config.Validate(cfg); err != nil {
		return err
	}

	// --- summary ------------------------------------------------------------

	adminLine := "not created"
	if adminUser != "" {
		adminLine = adminUser
	}
	u.Box("Configuration to write", [][2]string{
		{"config file", opts.out},
		{"data directory", cfg.DataDir},
		{"listen address", cfg.Addr},
		{"tls", describeTLS(tlsMode)},
		{"quota per user", formatSize(cfg.QuotaBytes)},
		{"max upload", formatSize(cfg.MaxUpload)},
		{"trusted proxies", orNone(strings.Join(cfg.TrustedProxies, ", "))},
		{"log level", cfg.LogLevel},
		{"administrator", adminLine},
	})

	if interactive {
		ok, err := u.AskBool("Write this configuration", true)
		if err != nil {
			return err
		}
		if !ok {
			u.Hint("Nothing written.")
			return nil
		}
	}

	// --- write --------------------------------------------------------------

	fileBytes, err := renderConfig(cfg)
	if err != nil {
		return err
	}
	if err := writeConfigFile(opts.out, fileBytes, opts.force); err != nil {
		return err
	}
	u.Success(fmt.Sprintf("wrote %s", opts.out))

	if adminUser != "" {
		if err := createAdmin(cfg, adminUser, adminPass); err != nil {
			u.Error(fmt.Sprintf("could not create the administrator: %v", err))
			u.Hint("The configuration file was still written.")
			u.Hint("Stop the server if it is running, then re-run init or register manually:")
			u.Hint(`  curl -X POST <base-url>/api/v1/auth/register -H 'content-type: application/json' \`)
			u.Hint(fmt.Sprintf(`       -d '{"username":%q,"password":"..."}'`, adminUser))
			return err
		}
		u.Success(fmt.Sprintf("created administrator %q", adminUser))
	}

	u.Step("Next steps")
	u.Line("%s litemd -config %s", u.style.Cyan(u.style.Arrow()), opts.out)
	if tlsMode == tlsInsecure {
		u.Line("Point clients at http://<host>%s", cfg.Addr)
	} else {
		u.Line("Point clients at https://<host>%s", cfg.Addr)
	}
	u.Line("Back up the data directory (%s); it holds the database and all files.", cfg.DataDir)
	u.Line("")
	return nil
}

func parseFlags(args []string, out io.Writer) (*options, error) {
	fs := flag.NewFlagSet("litemd init", flag.ContinueOnError)
	fs.SetOutput(out)
	o := &options{}
	fs.StringVar(&o.out, "out", "config.json", "path of the configuration file to write")
	fs.StringVar(&o.dataDir, "data", "./data", "data directory")
	fs.StringVar(&o.addr, "addr", ":8443", "listen address")
	fs.StringVar(&o.tlsMode, "tls", tlsSelfSigned, "TLS mode: self-signed, import or insecure")
	fs.StringVar(&o.tlsCert, "tls-cert", "", "certificate path (with -tls import)")
	fs.StringVar(&o.tlsKey, "tls-key", "", "private key path (with -tls import)")
	fs.StringVar(&o.quota, "quota", "1GiB", "per-user quota, e.g. 1GiB or 500MiB")
	fs.StringVar(&o.maxUpload, "max-upload", "64MiB", "maximum upload size, e.g. 64MiB")
	fs.StringVar(&o.trustedProxies, "trusted-proxies", "", "comma-separated IPs/CIDRs behind which X-Forwarded-For is trusted")
	fs.StringVar(&o.logLevel, "log-level", config.DefaultLogLevel, "log level: debug, info, warn or error")
	fs.StringVar(&o.adminUser, "admin-username", "", "create this administrator (skips the prompt)")
	fs.StringVar(&o.adminPass, "admin-password", "", "administrator password (use with -admin-username)")
	fs.BoolVar(&o.force, "force", false, "overwrite an existing configuration file")
	fs.BoolVar(&o.batch, "batch", false, "never prompt; use flags and defaults")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument: %q", fs.Arg(0))
	}
	switch o.tlsMode {
	case tlsSelfSigned, tlsImport, tlsInsecure:
	default:
		return nil, fmt.Errorf("invalid -tls %q: want self-signed, import or insecure", o.tlsMode)
	}
	if o.tlsMode == tlsImport && (o.tlsCert == "" || o.tlsKey == "") {
		return nil, errors.New("-tls import requires -tls-cert and -tls-key")
	}
	return o, nil
}

// renderConfig produces the JSON written to disk. Keys with meaningful
// non-default values are emitted; the rest are left to the server defaults.
func renderConfig(cfg *config.Config) ([]byte, error) {
	type out struct {
		Addr                  string   `json:"addr"`
		DataDir               string   `json:"data_dir"`
		TLSCert               string   `json:"tls_cert,omitempty"`
		TLSKey                string   `json:"tls_key,omitempty"`
		Insecure              bool     `json:"insecure,omitempty"`
		QuotaBytes            int64    `json:"quota_bytes"`
		MaxUpload             int64    `json:"max_upload"`
		AccessTTL             string   `json:"access_ttl"`
		RefreshTTL            string   `json:"refresh_ttl"`
		TrustedProxies        []string `json:"trusted_proxies,omitempty"`
		RateLimitBurst        int      `json:"rate_limit_burst"`
		RateLimitRefillPerSec float64  `json:"rate_limit_refill_per_sec"`
		LogLevel              string   `json:"log_level"`
	}
	b, err := json.MarshalIndent(out{
		Addr:                  cfg.Addr,
		DataDir:               cfg.DataDir,
		TLSCert:               cfg.TLSCert,
		TLSKey:                cfg.TLSKey,
		Insecure:              cfg.Insecure,
		QuotaBytes:            cfg.QuotaBytes,
		MaxUpload:             cfg.MaxUpload,
		AccessTTL:             formatDuration(cfg.AccessTokenTTL),
		RefreshTTL:            formatDuration(cfg.RefreshTokenTTL),
		TrustedProxies:        cfg.TrustedProxies,
		RateLimitBurst:        cfg.RateLimitBurst,
		RateLimitRefillPerSec: cfg.RateLimitRefillPerSec,
		LogLevel:              cfg.LogLevel,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func writeConfigFile(path string, data []byte, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (pass -force to overwrite)", path)
		}
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o600)
}

// createAdmin opens the data directory's database and registers the first user.
// It refuses to touch an instance that already has accounts.
func createAdmin(cfg *config.Config, username, password string) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	store, err := bolt.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	n, err := store.CountUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("the data directory already has %d user(s)", n)
	}
	svc, err := auth.NewService(store, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err != nil {
		return err
	}
	if _, err := svc.Register(username, password, cfg.QuotaBytes); err != nil {
		return err
	}
	return nil
}

// --- small validators and formatters ---------------------------------------

func validateNonEmpty(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", errors.New("a value is required")
	}
	return strings.TrimSpace(s), nil
}

func validateAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("a listen address is required")
	}
	if !strings.Contains(s, ":") {
		return "", errors.New(`use host:port form, e.g. ":8443" or "127.0.0.1:8443"`)
	}
	return s, nil
}

func logLevelValidator(s string) (string, error) {
	lvl := strings.ToLower(strings.TrimSpace(s))
	if lvl == "warning" {
		lvl = "warn"
	}
	for _, allowed := range config.LogLevels {
		if lvl == allowed {
			return lvl, nil
		}
	}
	return "", fmt.Errorf("choose one of: %s", strings.Join(config.LogLevels, ", "))
}

func sizeValidator(s string) (string, error) {
	if _, err := parseSize(s); err != nil {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func alwaysOK(s string) (string, error) { return strings.TrimSpace(s), nil }

func splitProxies(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func describeTLS(mode string) string {
	switch mode {
	case tlsImport:
		return "imported certificate"
	case tlsInsecure:
		return "plain HTTP (behind a proxy)"
	default:
		return "self-signed (generated on first boot)"
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
