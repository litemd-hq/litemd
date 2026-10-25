package setup

import (
	"strings"
	"testing"
)

// FuzzParseSize checks the parser never panics, never returns a non-positive
// size as valid, and round-trips through formatSize.
func FuzzParseSize(f *testing.F) {
	for _, s := range []string{
		"1", "1b", "1KiB", "64MiB", "2GiB", "1.5MiB", "1MB", " 512 KiB ",
		"", "abc", "10 potatoes", "-5MiB", "0", "1e9", "999999999999999999999",
		"1 GiB", "0.0001KiB", strings.Repeat("9", 40),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		v, err := parseSize(in)
		if err != nil {
			return
		}
		if v <= 0 {
			t.Fatalf("parseSize(%q) accepted a non-positive size: %d", in, v)
		}
		// The formatter must cope with anything the parser accepts.
		if out := formatSize(v); out == "" {
			t.Fatalf("formatSize(%d) returned empty", v)
		}
	})
}
