package setup

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litemd-hq/litemd/internal/config"
)

// scriptPrompter replays canned answers, standing in for a terminal.
type scriptPrompter struct {
	lines []string
	i     int
	tty   bool
}

func (p *scriptPrompter) next() (string, error) {
	if p.i >= len(p.lines) {
		return "", io.EOF
	}
	v := p.lines[p.i]
	p.i++
	return v, nil
}

func (p *scriptPrompter) ReadLine() (string, error)   { return p.next() }
func (p *scriptPrompter) ReadSecret() (string, error) { return p.next() }
func (p *scriptPrompter) IsTTY() bool                 { return p.tty }

func run(t *testing.T, args []string, answers ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	err := Run(args, &scriptPrompter{lines: answers, tty: len(answers) > 0}, &buf, &buf)
	return buf.String(), err
}

func decodeWritten(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("written config is not valid JSON: %v\n%s", err, b)
	}
	return m
}

func TestBatchInitWritesConfigFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.json")
	data := filepath.Join(dir, "data")

	outText, err := run(t, []string{
		"-batch", "-out", out, "-data", data,
		"-addr", "127.0.0.1:9000",
		"-quota", "2GiB", "-max-upload", "128MiB",
		"-trusted-proxies", "127.0.0.1/32, ::1/128",
	})
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, outText)
	}

	m := decodeWritten(t, out)
	if m["addr"] != "127.0.0.1:9000" {
		t.Errorf("addr = %v", m["addr"])
	}
	if m["data_dir"] != data {
		t.Errorf("data_dir = %v", m["data_dir"])
	}
	if m["quota_bytes"] != float64(2*(1<<30)) {
		t.Errorf("quota_bytes = %v, want %d", m["quota_bytes"], 2*(1<<30))
	}
	if m["max_upload"] != float64(128*(1<<20)) {
		t.Errorf("max_upload = %v", m["max_upload"])
	}
	if m["access_ttl"] != "15m" || m["refresh_ttl"] != "168h" {
		t.Errorf("ttls = %v / %v", m["access_ttl"], m["refresh_ttl"])
	}
	proxies, _ := m["trusted_proxies"].([]any)
	if len(proxies) != 2 {
		t.Errorf("trusted_proxies = %v", m["trusted_proxies"])
	}

	// Written 0600, and it must round-trip through the real config parser.
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config file mode = %o, want 600", perm)
	}
	if _, err := config.Parse([]string{"-config", out}); err != nil {
		t.Errorf("written config rejected by the server parser: %v", err)
	}
}

func TestBatchInitCreatesAdministrator(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.json")
	data := filepath.Join(dir, "data")

	outText, err := run(t, []string{
		"-batch", "-out", out, "-data", data,
		"-admin-username", "alice", "-admin-password", "password123",
	})
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, outText)
	}
	if !strings.Contains(outText, "created administrator") {
		t.Errorf("expected success message, got:\n%s", outText)
	}
	if _, err := os.Stat(filepath.Join(data, "litemd.db")); err != nil {
		t.Errorf("database should have been created: %v", err)
	}

	// A second run must refuse to add another user to a populated instance.
	_, err = run(t, []string{
		"-batch", "-out", filepath.Join(dir, "second.json"), "-data", data,
		"-admin-username", "bob", "-admin-password", "password456",
	})
	if err == nil {
		t.Error("expected refusal when the data directory already has users")
	}
}

func TestRefusesToOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.json")
	if err := os.WriteFile(out, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := run(t, []string{"-batch", "-out", out, "-data", filepath.Join(dir, "d")}); err == nil {
		t.Error("expected an error when the config file already exists")
	}
	if _, err := run(t, []string{"-batch", "-out", out, "-data", filepath.Join(dir, "d"), "-force"}); err != nil {
		t.Errorf("-force should overwrite: %v", err)
	}
}

func TestInteractiveWizard(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.json")
	data := filepath.Join(dir, "data")

	// Answers, in order: data dir, addr, quota, max upload, tls mode,
	// trusted proxies, create-admin?, username, password x2, write? yes.
	outText, err := run(t, []string{"-out", out},
		data,
		":9443",
		"500MiB",
		"32MiB",
		"self-signed",
		"",     // trusted proxies
		"warn", // log level
		"y",
		"alice",
		"password123",
		"password123",
		"y",
	)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, outText)
	}

	m := decodeWritten(t, out)
	if m["addr"] != ":9443" {
		t.Errorf("addr = %v", m["addr"])
	}
	if m["quota_bytes"] != float64(500*(1<<20)) {
		t.Errorf("quota_bytes = %v", m["quota_bytes"])
	}
	if !strings.Contains(outText, "created administrator") {
		t.Errorf("expected admin creation:\n%s", outText)
	}
	if m["log_level"] != "warn" {
		t.Errorf("log_level = %v, want warn", m["log_level"])
	}
}

func TestInteractiveValidationReprompts(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.json")

	// Bad address then good; bad size then good; then accept defaults for the
	// rest and decline admin creation.
	outText, err := run(t, []string{"-out", out},
		filepath.Join(dir, "data"),
		"not-an-address",
		"127.0.0.1:8443",
		"10 potatoes",
		"1GiB",
		"64MiB",
		"self-signed",
		"",     // trusted proxies
		"info", // log level
		"n",
		"y",
	)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, outText)
	}
	if !strings.Contains(outText, "use host:port form") {
		t.Errorf("expected an address error:\n%s", outText)
	}
	if !strings.Contains(outText, "unknown size unit") {
		t.Errorf("expected a size error:\n%s", outText)
	}
	m := decodeWritten(t, out)
	if m["addr"] != "127.0.0.1:8443" {
		t.Errorf("addr = %v", m["addr"])
	}
}

func TestInteractiveInsecureTLS(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.json")

	outText, err := run(t, []string{"-out", out},
		filepath.Join(dir, "data"),
		":8443",
		"1GiB",
		"64MiB",
		"insecure",
		"",     // trusted proxies
		"info", // log level
		"n",
		"y",
	)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, outText)
	}
	m := decodeWritten(t, out)
	if m["insecure"] != true {
		t.Errorf("insecure = %v, want true", m["insecure"])
	}
	if _, ok := m["tls_cert"]; ok {
		t.Error("tls_cert should be omitted in insecure mode")
	}
}

func TestInteractiveDeclineWritesNothing(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.json")

	outText, err := run(t, []string{"-out", out},
		filepath.Join(dir, "data"),
		":8443",
		"1GiB",
		"64MiB",
		"self-signed",
		"",     // trusted proxies
		"info", // log level
		"n",    // no administrator
		"n",    // do not write
	)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, outText)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("no config file should have been written")
	}
	if !strings.Contains(outText, "Nothing written") {
		t.Errorf("expected a decline message:\n%s", outText)
	}
}

func TestTLSImportRequiresPaths(t *testing.T) {
	if _, err := run(t, []string{"-batch", "-tls", "import"}); err == nil {
		t.Error("import mode without -tls-cert/-tls-key should fail")
	}
}

func TestInvalidTLSMode(t *testing.T) {
	if _, err := run(t, []string{"-batch", "-tls", "banana"}); err == nil {
		t.Error("unknown tls mode should fail")
	}
}

func TestNonInteractiveRequiresValidValues(t *testing.T) {
	if _, err := run(t, []string{"-batch", "-quota", "nope"}); err == nil {
		t.Error("invalid quota in batch mode should fail")
	}
}

func TestParseSize(t *testing.T) {
	ok := map[string]int64{
		"1":        1,
		"1b":       1,
		"1KiB":     1 << 10,
		"64MiB":    64 << 20,
		"2GiB":     2 << 30,
		"1.5MiB":   1 << 20 * 3 / 2,
		"1MB":      1000 * 1000,
		" 512 KiB": 512 << 10,
	}
	for in, want := range ok {
		got, err := parseSize(in)
		if err != nil {
			t.Errorf("parseSize(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseSize(%q) = %d, want %d", in, got, want)
		}
	}
	for _, in := range []string{"", "abc", "12 parsecs", "0", "-5MiB"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) should have failed", in)
		}
	}
}

func TestFormatSize(t *testing.T) {
	cases := map[int64]string{
		1 << 30:     "1 GiB",
		64 << 20:    "64 MiB",
		1536:        "1536 B",
		1024:        "1 KiB",
		3 * 1 << 30: "3 GiB",
		1000:        "1000 B",
	}
	for in, want := range cases {
		if got := formatSize(in); got != want {
			t.Errorf("formatSize(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestStyleDetection(t *testing.T) {
	// A pipe is not a terminal, so no color escapes.
	var buf bytes.Buffer
	s := detectStyle(&buf, func(string) string { return "" })
	if s.Color {
		t.Error("non-terminal output should not be coloured")
	}
	if !s.Unicode {
		t.Error("unset locale should be treated as UTF-8")
	}

	// Respect NO_COLOR and a C locale.
	s = detectStyle(&buf, func(k string) string {
		switch k {
		case "NO_COLOR":
			return "1"
		case "LANG":
			return "C"
		default:
			return ""
		}
	})
	if s.Color {
		t.Error("NO_COLOR should disable colour")
	}
	if s.Unicode {
		t.Error("C locale should disable unicode glyphs")
	}
}

func TestOutputHasNoEscapesWhenPiped(t *testing.T) {
	dir := t.TempDir()
	outText, err := run(t, []string{
		"-batch", "-out", filepath.Join(dir, "config.json"),
		"-data", filepath.Join(dir, "data"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(outText, "\x1b[") {
		t.Errorf("piped output must not contain ANSI escapes:\n%q", outText)
	}
}
