package files

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

var ErrInvalidPath = errors.New("invalid path")

// windowsReserved are DOS device names that cannot be used as file or
// directory segments, in any case and with or without an extension.
var windowsReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// CleanRelPath validates an untrusted client-supplied relative path and
// returns its canonical slash-separated form. It rejects traversal ('..'),
// absolute paths, Windows drive letters and backslashes, reserved device
// names, and characters that are invalid on any of the three supported OSes.
func CleanRelPath(rel string) (string, error) {
	if strings.ContainsRune(rel, '\\') {
		return "", fmt.Errorf("%w: backslash in path", ErrInvalidPath)
	}
	if strings.HasPrefix(rel, "/") {
		return "", fmt.Errorf("%w: absolute path", ErrInvalidPath)
	}
	rel = strings.TrimPrefix(rel, "./")
	if rel == "" {
		return "", fmt.Errorf("%w: empty path", ErrInvalidPath)
	}
	if len(rel) > 1024 {
		return "", fmt.Errorf("%w: path too long", ErrInvalidPath)
	}

	segs := strings.Split(rel, "/")
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		switch seg {
		case "":
			continue // collapse duplicate slashes
		case ".", "..":
			return "", fmt.Errorf("%w: traversal segment %q", ErrInvalidPath, seg)
		}
		if err := validateSegment(seg); err != nil {
			return "", err
		}
		out = append(out, seg)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("%w: empty path", ErrInvalidPath)
	}
	if len(out) > MaxPathDepth {
		return "", fmt.Errorf("%w: path too deep", ErrInvalidPath)
	}
	clean := path.Join(out...)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("%w: traversal escape", ErrInvalidPath)
	}
	return clean, nil
}

func validateSegment(seg string) error {
	if !utf8.ValidString(seg) {
		return fmt.Errorf("%w: invalid UTF-8", ErrInvalidPath)
	}
	if n := utf8.RuneCountInString(seg); n < 1 || n > 255 {
		return fmt.Errorf("%w: segment length out of range", ErrInvalidPath)
	}
	// Windows: no trailing dots or spaces.
	if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
		return fmt.Errorf("%w: segment ends with '.' or space", ErrInvalidPath)
	}
	base := seg
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if windowsReserved[strings.ToUpper(base)] {
		return fmt.Errorf("%w: reserved device name %q", ErrInvalidPath, seg)
	}
	for _, r := range seg {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: control character in segment", ErrInvalidPath)
		}
		switch r {
		case '<', '>', ':', '"', '|', '?', '*':
			return fmt.Errorf("%w: character %q not allowed (Windows-incompatible)", ErrInvalidPath, r)
		}
	}
	return nil
}

// Resolve maps a validated relative path to an absolute filesystem path
// under root and verifies the result cannot escape root.
func Resolve(root, cleanRel string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	target := filepath.Join(absRoot, filepath.FromSlash(cleanRel))
	if !within(absRoot, target) {
		return "", fmt.Errorf("%w: resolved path escapes user root", ErrInvalidPath)
	}
	return target, nil
}

func within(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// CheckSymlinks walks the deepest existing ancestor of target and rejects
// the path if any symlinked component resolves outside root.
func CheckSymlinks(root, target string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	// Resolve the root itself first: the base directory may live under a
	// symlink (e.g. /var -> /private/var on macOS, or a temp dir), which
	// would otherwise make every resolved child look like an escape.
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // root does not exist yet; nothing to check
		}
		return err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absRoot, absTarget)
	if err != nil {
		return fmt.Errorf("%w: not under user root", ErrInvalidPath)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	cur := resolvedRoot
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		resolved, err := filepath.EvalSymlinks(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // nothing deeper can be a symlink
			}
			return err
		}
		if !within(resolvedRoot, resolved) {
			return fmt.Errorf("%w: symlink escapes user root", ErrInvalidPath)
		}
	}
	return nil
}
