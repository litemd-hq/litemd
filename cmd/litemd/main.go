// Command litemd is a lightweight, single-binary file sync server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/litemd-hq/litemd/internal/auth"
	bolt "github.com/litemd-hq/litemd/internal/bolt"
	"github.com/litemd-hq/litemd/internal/config"
	"github.com/litemd-hq/litemd/internal/files"
	"github.com/litemd-hq/litemd/internal/httpapi"
	"github.com/litemd-hq/litemd/internal/setup"
	"github.com/litemd-hq/litemd/internal/tlsutil"
)

// version is the release version reported by `litemd -version` and in the
// startup log.
//
// Two things set it, in order of precedence:
//
//   - a release build, where goreleaser stamps the git tag:
//     -ldflags "-X main.version={{ .Version }}"  (tag v0.1.0 -> "0.1.0")
//   - this constant, which is what a plain `go build ./cmd/litemd` reports.
//
// Bump this when you cut a release so local builds do not lag the tag; see
// "Releases and CI" in README.md.
var version = "0.1.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			err := setup.Run(os.Args[2:], setup.NewFilePrompter(os.Stdin), os.Stdout, os.Stderr)
			if err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return
				}
				fmt.Fprintln(os.Stderr, "init failed:", err)
				os.Exit(1)
			}
			return
		case "help", "-h", "--help":
			usage(os.Stdout)
			return
		case "-version", "--version", "version":
			fmt.Println("litemd", version)
			return
		}
	}

	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "litemd %s - lightweight file sync server\n\n", version)
	fmt.Fprint(w, "Usage:\n")
	fmt.Fprint(w, "  litemd [flags]        start the server\n")
	fmt.Fprint(w, "  litemd init [flags]   write a config file and create the first admin\n")
	fmt.Fprint(w, "  litemd help           show this message\n")
	fmt.Fprint(w, "  litemd -version       print the version\n")
	fmt.Fprint(w, "\nServer flags:\n\n")
	config.ServerUsage(w)
	fmt.Fprint(w, "\nInit flags: run `litemd init -h`\n")
}

// slogLevel maps a validated config log level to a slog level.
func slogLevel(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func run() error {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slogLevel(cfg.LogLevel)}))
	log.Info("starting", "version", version, "addr", cfg.Addr)

	store, err := bolt.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	authSvc, err := auth.NewService(store, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err != nil {
		return err
	}

	usersDir := filepath.Join(cfg.DataDir, "users")
	if err := os.MkdirAll(usersDir, 0o700); err != nil {
		return err
	}

	// Startup janitor: remove stale atomic-write temp files, then keep
	// sweeping hourly.
	files.CleanupTemps(usersDir, time.Hour)
	janitorStop := make(chan struct{})
	go func() {
		for {
			select {
			case <-time.After(time.Hour):
				files.CleanupTemps(usersDir, time.Hour)
			case <-janitorStop:
				return
			}
		}
	}()
	defer close(janitorStop)

	api := httpapi.New(cfg, store, authSvc, log)
	defer api.Close()

	// One-time backfill of the tag/backlink indexes for pre-existing data.
	if err := api.Reindex(); err != nil {
		log.Error("index backfill failed", "err", err)
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // large uploads
		WriteTimeout:      5 * time.Minute, // large downloads
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
	}

	errCh := make(chan error, 1)
	go func() {
		if cfg.Insecure {
			log.Warn("serving plain HTTP (insecure mode)", "addr", cfg.Addr)
			errCh <- srv.ListenAndServe()
		} else {
			cert, err := tlsutil.EnsureCert(cfg.DataDir, cfg.TLSCert, cfg.TLSKey)
			if err != nil {
				errCh <- err
				return
			}
			srv.TLSConfig = tlsutil.Config()
			srv.TLSConfig.Certificates = []tls.Certificate{cert}
			log.Info("serving HTTPS", "addr", cfg.Addr)
			errCh <- srv.ListenAndServeTLS("", "")
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case sig := <-stop:
		log.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			return err
		}
	}
	return nil
}
