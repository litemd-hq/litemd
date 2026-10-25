package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureCertGeneratesAndReuses(t *testing.T) {
	dir := t.TempDir()

	cert, err := EnsureCert(dir, "", "")
	if err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate returned")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != "litemd" {
		t.Errorf("CN = %q, want litemd", leaf.Subject.CommonName)
	}
	if time.Until(leaf.NotAfter) < 300*24*time.Hour {
		t.Errorf("certificate expires too soon: %v", leaf.NotAfter)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("certificate should be valid for localhost: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("certificate should be valid for 127.0.0.1: %v", err)
	}

	// Cert is world-readable, key is private.
	for path, want := range map[string]os.FileMode{
		filepath.Join(dir, "tls.crt"): 0o644,
		filepath.Join(dir, "tls.key"): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
		}
	}

	// A second call reuses the stored certificate rather than regenerating.
	again, err := EnsureCert(dir, "", "")
	if err != nil {
		t.Fatalf("second EnsureCert: %v", err)
	}
	if string(again.Certificate[0]) != string(cert.Certificate[0]) {
		t.Error("certificate was regenerated instead of reused")
	}
}

func TestEnsureCertLoadsProvidedKeyPair(t *testing.T) {
	genDir := t.TempDir()
	if _, err := EnsureCert(genDir, "", ""); err != nil {
		t.Fatal(err)
	}

	other := t.TempDir()
	cert, err := EnsureCert(other, filepath.Join(genDir, "tls.crt"), filepath.Join(genDir, "tls.key"))
	if err != nil {
		t.Fatalf("EnsureCert with paths: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate loaded")
	}
	if _, err := os.Stat(filepath.Join(other, "tls.crt")); !os.IsNotExist(err) {
		t.Error("a provided keypair should not be copied into the data directory")
	}
}

func TestEnsureCertRejectsHalfAKeyPair(t *testing.T) {
	dir := t.TempDir()
	if _, err := EnsureCert(dir, "/tmp/only-cert.pem", ""); err == nil {
		t.Error("cert without key should be rejected")
	}
	if _, err := EnsureCert(dir, "", "/tmp/only-key.pem"); err == nil {
		t.Error("key without cert should be rejected")
	}
}

func TestEnsureCertRejectsBadProvidedPair(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "nope.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureCert(dir, bad, bad); err == nil {
		t.Error("malformed keypair should be rejected")
	}
}

// serveTLS starts a TLS listener that greets each connection. Every dial in
// these tests is bounded by a timeout so a mistake cannot hang the suite.
func serveTLS(t *testing.T, cfg *tls.Config) (addr string, stop func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write([]byte("hello"))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func dialTLS(t *testing.T, addr string, cfg *tls.Config) (net.Conn, error) {
	t.Helper()
	return tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, cfg)
}

func TestRealHandshake(t *testing.T) {
	dir := t.TempDir()
	cert, err := EnsureCert(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}

	serverCfg := Config()
	serverCfg.Certificates = []tls.Certificate{cert}
	addr, stop := serveTLS(t, serverCfg)
	defer stop()

	pool := x509.NewCertPool()
	pool.AddCert(mustParse(t, cert.Certificate[0]))

	good, err := dialTLS(t, addr, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("verified dial failed: %v", err)
	}
	_ = good.SetDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(good)
	good.Close()
	if err != nil || string(got) != "hello" {
		t.Fatalf("read = %q, %v", got, err)
	}

	// Without trusting it, verification must fail: there is no path from a
	// self-signed certificate to a trusted root.
	if _, err := dialTLS(t, addr, &tls.Config{
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}); err == nil {
		t.Error("dial without a trusted root should fail verification")
	}
}

func TestTLS12FloorRefusesOlderClients(t *testing.T) {
	dir := t.TempDir()
	cert, err := EnsureCert(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config()
	cfg.Certificates = []tls.Certificate{cert}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Error("a cipher suite allowlist is expected")
	}

	addr, stop := serveTLS(t, cfg)
	defer stop()

	pool := x509.NewCertPool()
	pool.AddCert(mustParse(t, cert.Certificate[0]))

	if _, err := dialTLS(t, addr, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS11,
	}); err == nil {
		t.Error("a TLS 1.1 client should be refused")
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return c
}
