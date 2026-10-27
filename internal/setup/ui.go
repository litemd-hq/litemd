package setup

import (
	"fmt"
	"io"
	"strings"

	"github.com/litemd-hq/litemd/internal/tty"
)

// Style renders terminal output. Both knobs default to "off" so that piped or
// non-UTF-8 output stays plain and machine-readable.
type Style struct {
	Color   bool
	Unicode bool
}

// detectStyle decides how to render based on the output stream, NO_COLOR and
// the locale. No dependency on a terminal library is needed for this.
func detectStyle(out io.Writer, getenv func(string) string) Style {
	return Style{
		Color:   tty.ColorEnabled(out, getenv),
		Unicode: tty.UTF8(getenv),
	}
}

func (s Style) wrap(code, text string) string {
	if !s.Color || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s Style) Bold(t string) string   { return s.wrap("1", t) }
func (s Style) Dim(t string) string    { return s.wrap("2", t) }
func (s Style) Cyan(t string) string   { return s.wrap("36", t) }
func (s Style) Green(t string) string  { return s.wrap("32", t) }
func (s Style) Yellow(t string) string { return s.wrap("33", t) }
func (s Style) Red(t string) string    { return s.wrap("31", t) }

// glyph returns a UTF-8 symbol when the terminal can show it, else an ASCII
// stand-in.
func (s Style) glyph(unicode, ascii string) string {
	if s.Unicode {
		return unicode
	}
	return ascii
}

func (s Style) Rule(width int) string {
	if width < 1 {
		width = 1
	}
	return strings.Repeat(s.glyph("\u2500", "-"), width)
}

func (s Style) Tick() string   { return s.glyph("\u2713", "[ok]") }
func (s Style) Cross() string  { return s.glyph("\u2717", "[x]") }
func (s Style) Bullet() string { return s.glyph("\u2022", "*") }
func (s Style) Arrow() string  { return s.glyph("\u2192", "->") }

// indent is the standard left margin for wizard output.
const indent = "  "

// Heading prints a titled section.
func (u *UI) Heading(title string) {
	fmt.Fprintf(u.out, "\n%s %s\n\n", u.style.Cyan(u.style.glyph("\u2588", "#")), u.style.Bold(title))
}

func (u *UI) Step(title string) {
	fmt.Fprintf(u.out, "\n%s\n", u.style.Bold(title))
}

func (u *UI) Hint(title string) {
	fmt.Fprintf(u.out, "%s%s\n", indent, u.style.Dim(title))
}

func (u *UI) Success(msg string) {
	fmt.Fprintf(u.out, "%s%s %s\n", indent, u.style.Green(u.style.Tick()), msg)
}

func (u *UI) Warn(msg string) {
	fmt.Fprintf(u.out, "%s%s %s\n", indent, u.style.Yellow("!"), msg)
}

func (u *UI) Error(msg string) {
	fmt.Fprintf(u.out, "%s%s %s\n", indent, u.style.Red(u.style.Cross()), u.style.Red(msg))
}

func (u *UI) Line(format string, args ...any) {
	fmt.Fprintf(u.out, "%s%s\n", indent, fmt.Sprintf(format, args...))
}

// Box prints an aligned key/value summary between two rules. Rows with an
// empty key render as a continued value line.
func (u *UI) Box(title string, rows [][2]string) {
	width := 0
	for _, r := range rows {
		if n := len(r[0]); n > width {
			width = n
		}
	}
	if w := len(title) + 4; w > width+8 {
		width = w - 8
	}

	fmt.Fprintf(u.out, "\n%s%s\n", indent, u.style.Dim(u.style.Rule(width+len(indent)+2)))
	fmt.Fprintf(u.out, "%s%s\n", indent, u.style.Bold(title))
	for _, r := range rows {
		if r[0] == "" {
			fmt.Fprintf(u.out, "%s%s%s\n", indent, strings.Repeat(" ", width+2), r[1])
			continue
		}
		fmt.Fprintf(u.out, "%s%s  %s\n", indent, u.style.Dim(fmt.Sprintf("%-*s", width, r[0])), r[1])
	}
	fmt.Fprintf(u.out, "%s%s\n", indent, u.style.Dim(u.style.Rule(width+len(indent)+2)))
}
