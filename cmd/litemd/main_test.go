package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// testBinary is built once for the whole package; the tests below exercise the
// real executable rather than the in-process handlers.
var testBinary string

func TestMain(m *testing.M) {
	// Parse before touching testing.Short; the testing package requires it.
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}

	dir, err := os.MkdirTemp("", "litemd-bin-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	testBinary = filepath.Join(dir, "litemd")
	build := exec.Command("go", "build", "-o", testBinary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "go build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func requireBinary(t *testing.T) string {
	t.Helper()
	if testBinary == "" {
		t.Skip("binary not built in -short mode")
	}
	return testBinary
}

func TestVersionFlag(t *testing.T) {
	bin := requireBinary(t)
	out, err := exec.Command(bin, "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("-version: %v\n%s", err, out)
	}
	if !strings.HasPrefix(string(out), "litemd ") {
		t.Errorf("output = %q, want it to start with %q", out, "litemd ")
	}
}

func TestHelpListsCommands(t *testing.T) {
	bin := requireBinary(t)
	out, err := exec.Command(bin, "help").CombinedOutput()
	if err != nil {
		t.Fatalf("help: %v\n%s", err, out)
	}
	for _, want := range []string{"litemd init", "litemd -version", "-trusted-proxies"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("help output missing %q:\n%s", want, out)
		}
	}
}

// TestInitSubcommandWritesConfig runs the wizard through the real binary's
// argument dispatch (the unit tests cover the wizard itself).
func TestInitSubcommandWritesConfig(t *testing.T) {
	bin := requireBinary(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "config.json")
	port := freePort(t)

	cmd := exec.Command(bin, "init", "-batch", "-out", out,
		"-data", filepath.Join(dir, "data"),
		"-tls", "insecure",
		"-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"-admin-username", "alice", "-admin-password", "password123")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init failed: %v\n%s", err, b)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	if cfg["admin_username"] != nil {
		t.Error("admin credentials must not be written into the config file")
	}
	if cfg["insecure"] != true {
		t.Errorf("insecure = %v, want true", cfg["insecure"])
	}

	// The server must start from the generated file and serve on the port it
	// was configured with.
	assertServerServes(t, bin, []string{"-config", out}, port)
}

// TestServerEndToEnd boots the binary and talks to it over real HTTP.
func TestServerEndToEnd(t *testing.T) {
	bin := requireBinary(t)
	dir := t.TempDir()
	port := freePort(t)
	assertServerServes(t, bin, []string{
		"-insecure",
		"-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"-data", filepath.Join(dir, "data"),
	}, port)
}

// assertServerServes starts the binary with the given arguments, waits for
// /healthz on port, checks an unauthenticated endpoint is protected, then
// asserts a clean shutdown on interrupt.
func assertServerServes(t *testing.T, bin string, args []string, port int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("signal-based shutdown check is unix only")
	}

	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 2 * time.Second}

	// Wait for readiness.
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == "ok" {
				lastErr = nil
				break
			}
			lastErr = fmt.Errorf("healthz status %d, body %q", resp.StatusCode, body)
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("server never became ready: %v\nstderr:\n%s", lastErr, stderr.String())
	}

	// Protected routes must reject an anonymous caller.
	resp, err := client.Get(base + "/api/v1/files")
	if err != nil {
		t.Fatalf("unauthenticated request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/files without a token = %d, want 401", resp.StatusCode)
	}

	// Graceful shutdown.
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected a clean exit, got %v\nstderr:\n%s", err, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("server did not exit after interrupt\nstderr:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "shutting down") {
		t.Errorf("expected a shutdown log line, got:\n%s", stderr.String())
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
