package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestTextFormatIsReadable(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "text", slog.LevelDebug, false)
	log.Info("starting", "version", "0.1.0", "addr", ":8443")

	got := buf.String()
	for _, want := range []string{"INFO", "starting", "version=0.1.0", "addr=:8443"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b[") {
		t.Errorf("plain output must not contain ANSI escapes:\n%q", got)
	}
}

func TestTextFormatColor(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "text", slog.LevelDebug, true)
	log.Warn("careful", "path", "/notes/a.md")

	got := buf.String()
	if !strings.Contains(got, "\x1b[") {
		t.Errorf("coloured output should contain ANSI escapes:\n%q", got)
	}
	if !strings.Contains(got, "WARN") || !strings.Contains(got, "careful") {
		t.Errorf("output missing fields:\n%s", got)
	}
}

func TestTextFormatQuotesValues(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "text", slog.LevelDebug, false)
	log.Info("msg", "reason", "two words", "empty", "")

	got := buf.String()
	if !strings.Contains(got, `reason="two words"`) {
		t.Errorf("value with a space should be quoted:\n%s", got)
	}
	if !strings.Contains(got, `empty=""`) {
		t.Errorf("empty value should be quoted:\n%s", got)
	}
}

func TestJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "json", slog.LevelDebug, false)
	log.Info("starting", "version", "0.1.0")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("json output is not valid JSON: %v\n%s", err, buf.String())
	}
	if rec["msg"] != "starting" || rec["version"] != "0.1.0" {
		t.Errorf("unexpected record: %v", rec)
	}
	if rec["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", rec["level"])
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "text", slog.LevelWarn, false)
	log.Info("hidden")
	log.Warn("shown")

	got := buf.String()
	if strings.Contains(got, "hidden") {
		t.Errorf("info should be filtered at warn level:\n%s", got)
	}
	if !strings.Contains(got, "shown") {
		t.Errorf("warn should be emitted:\n%s", got)
	}
}

func TestWithAttrsAndGroup(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "text", slog.LevelDebug, false).With("a", "1").WithGroup("g")
	log.Info("m", "b", "2")

	got := buf.String()
	if !strings.Contains(got, "a=1") {
		t.Errorf("bound attr missing:\n%s", got)
	}
	if !strings.Contains(got, "g.b=2") {
		t.Errorf("grouped attr should be dotted:\n%s", got)
	}
}

func TestConcurrentUse(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "text", slog.LevelDebug, false)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		g := log.With("i", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Info("request", "path", "/x")
		}()
	}
	wg.Wait()

	if n := strings.Count(buf.String(), "request"); n != 50 {
		t.Errorf("logged %d lines, want 50", n)
	}
}
