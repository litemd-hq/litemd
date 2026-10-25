package setup

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Prompter supplies answers to the wizard so it can be driven either by a real
// terminal or by a script in tests.
type Prompter interface {
	ReadLine() (string, error)
	// ReadSecret reads a line without echoing it when the input is a terminal.
	ReadSecret() (string, error)
	IsTTY() bool
}

type filePrompter struct{ f *os.File }

// NewFilePrompter wraps an *os.File (normally os.Stdin).
func NewFilePrompter(f *os.File) Prompter { return &filePrompter{f: f} }

func (p *filePrompter) IsTTY() bool { return term.IsTerminal(int(p.f.Fd())) }

// ReadLine reads a single line one byte at a time. Reading without buffering
// matters: a buffered reader would happily swallow the password that follows a
// username prompt.
func (p *filePrompter) ReadLine() (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := p.f.Read(buf)
		if n > 0 {
			switch buf[0] {
			case '\n':
				return sb.String(), nil
			case '\r':
				// ignore CR so CRLF input behaves like LF
			default:
				sb.WriteByte(buf[0])
			}
		}
		if err != nil {
			if err == io.EOF && sb.Len() > 0 {
				return sb.String(), nil
			}
			return sb.String(), err
		}
	}
}

func (p *filePrompter) ReadSecret() (string, error) {
	if !p.IsTTY() {
		return p.ReadLine()
	}
	b, err := term.ReadPassword(int(p.f.Fd()))
	return string(b), err
}

// Ask prompts for a line, offering def when the user just presses Enter. The
// validator may normalise the value; a returned error re-prompts.
func (u *UI) Ask(label, def string, validate func(string) (string, error)) (string, error) {
	if validate == nil {
		validate = func(s string) (string, error) { return s, nil }
	}
	for {
		fmt.Fprintf(u.out, "%s%s ", indent, u.style.Bold(label+":"))
		if def != "" {
			fmt.Fprintf(u.out, "%s ", u.style.Dim("["+def+"]"))
		}
		line, err := u.in.ReadLine()
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			line = def
		}
		v, err := validate(line)
		if err != nil {
			u.Error(err.Error())
			continue
		}
		return v, nil
	}
}

// AskBool asks a yes/no question; Enter selects def.
func (u *UI) AskBool(label string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for {
		fmt.Fprintf(u.out, "%s%s %s ", indent, u.style.Bold(label+":"), u.style.Dim(hint))
		line, err := u.in.ReadLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			u.Error("please answer y or n")
		}
	}
}

// AskChoice asks the user to pick one of options; Enter selects def.
func (u *UI) AskChoice(label string, options []string, def string) (string, error) {
	u.Hint(fmt.Sprintf("%s (%s)", label, strings.Join(options, " / ")))
	for {
		fmt.Fprintf(u.out, "%s%s ", indent, u.style.Bold(label+":"))
		if def != "" {
			fmt.Fprintf(u.out, "%s ", u.style.Dim("["+def+"]"))
		}
		line, err := u.in.ReadLine()
		if err != nil {
			return "", err
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			line = def
		}
		for _, o := range options {
			if line == o {
				return o, nil
			}
		}
		u.Error(fmt.Sprintf("choose one of: %s", strings.Join(options, ", ")))
	}
}

// AskSecret prompts twice for a new secret and never echoes it on a terminal.
func (u *UI) AskSecret(label string, validate func(string) error) (string, error) {
	for {
		first, err := u.readSecretOnce(label)
		if err != nil {
			return "", err
		}
		if err := validate(first); err != nil {
			u.Error(err.Error())
			continue
		}
		again, err := u.readSecretOnce("Confirm " + label)
		if err != nil {
			return "", err
		}
		if first != again {
			u.Error("values did not match, try again")
			continue
		}
		return first, nil
	}
}

func (u *UI) readSecretOnce(label string) (string, error) {
	fmt.Fprintf(u.out, "%s%s ", indent, u.style.Bold(label+":"))
	v, err := u.in.ReadSecret()
	if u.in.IsTTY() {
		// Echo was suppressed, so the user's Enter was not shown.
		fmt.Fprintln(u.out)
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(v), nil
}
