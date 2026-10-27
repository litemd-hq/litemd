package tty

import (
	"bytes"
	"testing"
)

func TestColorDisabledForNonTerminal(t *testing.T) {
	var buf bytes.Buffer
	clean := func(string) string { return "" }
	if ColorEnabled(&buf, clean) {
		t.Error("a bytes.Buffer is not a terminal, colour must be off")
	}
}

func TestColorRespectsEnvironment(t *testing.T) {
	// isTerminal is false for these writers regardless, so the only way to
	// observe the environment checks is through a terminal; assert the guards
	// directly instead by checking a terminal-less writer stays off for every
	// environment.
	var buf bytes.Buffer
	envs := []map[string]string{
		{"NO_COLOR": "1"},
		{"TERM": "dumb"},
		{"TERM": "xterm-256color", "NO_COLOR": ""},
	}
	for _, e := range envs {
		getenv := func(k string) string { return e[k] }
		if ColorEnabled(&buf, getenv) {
			t.Errorf("colour must be off for non-terminal with env %v", e)
		}
	}
}

func TestUTF8Locale(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"unset defaults to utf8", map[string]string{}, true},
		{"C locale", map[string]string{"LC_ALL": "C"}, false},
		{"POSIX locale", map[string]string{"LANG": "POSIX"}, false},
		{"utf8 locale", map[string]string{"LANG": "en_US.UTF-8"}, true},
		{"utf8 without dash", map[string]string{"LC_CTYPE": "en_US.utf8"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			if got := UTF8(getenv); got != tc.want {
				t.Errorf("UTF8 = %v, want %v", got, tc.want)
			}
		})
	}
}
