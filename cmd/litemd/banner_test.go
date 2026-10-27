package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintBannerPlain(t *testing.T) {
	var buf bytes.Buffer
	printBanner(&buf, false, "0.1.0")

	got := buf.String()
	for _, want := range []string{"__  __", "|_|_|", "litemd 0.1.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("banner missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b[") {
		t.Errorf("plain banner must not contain ANSI escapes:\n%q", got)
	}
}

func TestPrintBannerColor(t *testing.T) {
	var buf bytes.Buffer
	printBanner(&buf, true, "0.1.0")

	if !strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("coloured banner should contain ANSI escapes:\n%q", buf.String())
	}
}
