// Package logging builds the server's slog logger. The default "text" format is
// meant for humans watching a terminal; "json" keeps the structured output that
// log shippers expect.
package logging

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// New builds a logger writing to w at the given level. format is "json" or
// "text"; any other value is treated as text. Text output is coloured only when
// color is true.
func New(w io.Writer, format string, level slog.Level, color bool) *slog.Logger {
	if format == "json" {
		return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
	}
	return slog.New(newTextHandler(w, level, color))
}

// textHandler renders human-readable lines: "HH:MM:SS  LEVEL  message key=value".
// It is safe for concurrent use, as required by slog handlers and by the HTTP
// server, which logs from many goroutines.
type textHandler struct {
	mu     *sync.Mutex
	w      io.Writer
	level  slog.Level
	color  bool
	attrs  []slog.Attr
	groups []string
}

func newTextHandler(w io.Writer, level slog.Level, color bool) *textHandler {
	return &textHandler{mu: &sync.Mutex{}, w: w, level: level, color: color}
}

func (h *textHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *textHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	writeStamp(&b, r.Time, h.color)
	b.WriteString("  ")
	writeLevel(&b, r.Level, h.color)
	b.WriteString("  ")
	b.WriteString(r.Message)

	for _, a := range h.attrs {
		writeAttr(&b, h.groups, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, h.groups, a)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *textHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	nh := *h
	nh.attrs = make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	nh.attrs = append(nh.attrs, h.attrs...)
	nh.attrs = append(nh.attrs, attrs...)
	return &nh
}

func (h *textHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := *h
	nh.groups = make([]string, len(h.groups), len(h.groups)+1)
	copy(nh.groups, h.groups)
	nh.groups = append(nh.groups, name)
	return &nh
}

func writeStamp(b *strings.Builder, t time.Time, color bool) {
	stamp := t.Format("15:04:05")
	if color {
		b.WriteString("\x1b[2m")
		b.WriteString(stamp)
		b.WriteString("\x1b[0m")
		return
	}
	b.WriteString(stamp)
}

func writeLevel(b *strings.Builder, l slog.Level, color bool) {
	label := levelLabel(l)
	if color {
		b.WriteString("\x1b[")
		b.WriteString(levelCode(l))
		b.WriteString("m")
		b.WriteString(label)
		b.WriteString("\x1b[0m")
		return
	}
	b.WriteString(label)
}

func levelLabel(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "DEBUG"
	case l < slog.LevelWarn:
		return "INFO "
	case l < slog.LevelError:
		return "WARN "
	default:
		return "ERROR"
	}
}

func levelCode(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "36"
	case l < slog.LevelWarn:
		return "32"
	case l < slog.LevelError:
		return "33"
	default:
		return "31"
	}
}

func writeAttr(b *strings.Builder, groups []string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		g := a.Value.Group()
		if len(g) == 0 {
			return
		}
		next := groups
		if a.Key != "" {
			next = make([]string, len(groups), len(groups)+1)
			copy(next, groups)
			next = append(next, a.Key)
		}
		for _, ga := range g {
			writeAttr(b, next, ga)
		}
		return
	}
	b.WriteByte(' ')
	if len(groups) > 0 {
		b.WriteString(strings.Join(groups, "."))
		b.WriteByte('.')
	}
	b.WriteString(a.Key)
	b.WriteByte('=')
	b.WriteString(formatValue(a.Value))
}

func formatValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		return quoteIfNeeded(v.String())
	case slog.KindTime:
		return v.Time().Format(time.RFC3339)
	default:
		return v.String()
	}
}

// quoteIfNeeded keeps simple values bare for readability but quotes anything
// containing whitespace or a quote so the line stays parseable.
func quoteIfNeeded(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\n\"") {
		return strconv.Quote(s)
	}
	return s
}
