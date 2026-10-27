// Package tty holds terminal-capability detection shared by the setup wizard,
// the logger and the launch banner: whether the output is a terminal and
// whether colour and UTF-8 glyphs are safe to use.
package tty

import (
	"io"
	"os"
	"strings"
)

// IsTerminal reports whether w is an interactive character device. Writers
// that are not *os.File (buffers, pipes wrapped by callers) are not terminals.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// ColorEnabled reports whether ANSI colour should be emitted to w. Colour is
// off for non-terminals and when NO_COLOR is set or TERM is "dumb".
func ColorEnabled(w io.Writer, getenv func(string) string) bool {
	return IsTerminal(w) && getenv("NO_COLOR") == "" && getenv("TERM") != "dumb"
}

// UTF8 reports whether the environment suggests a UTF-8 terminal. An unset
// locale is treated as UTF-8 (the usual modern default).
func UTF8(getenv func(string) string) bool {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		v := getenv(key)
		if v == "" {
			continue
		}
		lower := strings.ToLower(v)
		if lower == "c" || lower == "posix" {
			return false
		}
		return strings.Contains(lower, "utf-8") || strings.Contains(lower, "utf8")
	}
	return true
}
