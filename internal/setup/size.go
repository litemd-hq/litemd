package setup

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseSize turns a human size such as "1GiB", "64MiB" or a bare byte count
// into bytes. Binary (KiB/MiB/GiB) and decimal (KB/MB/GB) suffixes are both
// accepted, with no suffix meaning bytes.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("size is required")
	}

	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	numStr := s[:i]
	unit := strings.ToLower(strings.TrimSpace(s[i:]))
	if numStr == "" {
		return 0, fmt.Errorf("size %q must start with a number", s)
	}

	var mult int64
	switch unit {
	case "", "b":
		mult = 1
	case "k", "kb":
		mult = 1000
	case "ki", "kib", "kibibyte", "kibibytes":
		mult = 1 << 10
	case "m", "mb":
		mult = 1000 * 1000
	case "mi", "mib", "mebibyte", "mebibytes":
		mult = 1 << 20
	case "g", "gb":
		mult = 1000 * 1000 * 1000
	case "gi", "gib", "gibibyte", "gibibytes":
		mult = 1 << 30
	case "t", "tb":
		mult = 1000 * 1000 * 1000 * 1000
	case "ti", "tib":
		mult = 1 << 40
	default:
		return 0, fmt.Errorf("unknown size unit %q", unit)
	}

	f, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	v := int64(f * float64(mult))
	if v <= 0 {
		return 0, fmt.Errorf("size must be greater than zero")
	}
	return v, nil
}

// formatSize renders bytes using binary units when they divide evenly, falling
// back to a raw byte count.
func formatSize(n int64) string {
	type unit struct {
		size int64
		name string
	}
	for _, u := range []unit{{1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}} {
		if n >= u.size && n%u.size == 0 {
			return fmt.Sprintf("%d %s", n/u.size, u.name)
		}
	}
	return fmt.Sprintf("%d B", n)
}

// formatDuration renders a duration in its shortest familiar form ("15m",
// "168h") rather than Go's default "15m0s".
func formatDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	case d%time.Second == 0:
		return fmt.Sprintf("%ds", d/time.Second)
	default:
		return d.String()
	}
}
