package model

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"
)

// Error is a refused write: Code and Params are what the page translates
// (messages.json of the window, srv.<code>); Message is the English text.
// Status is an HTTP-like status.
type Error struct {
	Status  int
	Message string
	Reload  bool
	Confirm bool
	Code    string
	Params  map[string]any
}

func (e *Error) Error() string { return e.Message }

func Err(status int, message, code string) *Error {
	return &Error{Status: status, Message: message, Code: code, Params: map[string]any{}}
}

// Alphabets for Generate. "symbols" stays safe in a shell and in an env file.
var Alphabets = map[string]string{
	"alnum":     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"symbols":   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.,:=@%+^~/",
	"hex":       "0123456789abcdef",
	"base64url": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
}

const (
	GenMin     = 8
	GenMax     = 256
	GenDefault = 32
)

// Generate is a random value of length characters from the named alphabet.
func Generate(length int, alphabet string) (string, error) {
	if length < GenMin || length > GenMax {
		e := Err(400, fmt.Sprintf("a length from %d to %d", GenMin, GenMax), "gen_length")
		e.Params = map[string]any{"min": GenMin, "max": GenMax}
		return "", e
	}
	chars, ok := Alphabets[alphabet]
	if !ok {
		return "", Err(400, "an alphabet: alnum, symbols, hex or base64url", "gen_alphabet")
	}
	var b strings.Builder
	n := big.NewInt(int64(len(chars)))
	for i := 0; i < length; i++ {
		x, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", err
		}
		b.WriteByte(chars[x.Int64()])
	}
	return b.String(), nil
}

// hasLineBreak: any character a line splitter may treat as a line end (Python
// str.splitlines, Unicode line and paragraph separators, NUL), or text that is
// not valid UTF-8 at all.
func hasLineBreak(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		switch r {
		case '\n', '\r', '\v', '\f', 0, 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			return true
		}
	}
	return false
}

// OneLine refuses text that is not one line up to limit characters (no
// character that any parser may read as a line end).
func OneLine(text, what string, limit int) (string, error) {
	if hasLineBreak(text) || len([]rune(text)) > limit {
		e := Err(400, fmt.Sprintf("%s is one line of text, up to %d characters", what, limit), "one_line")
		e.Params = map[string]any{"limit": limit}
		return "", e
	}
	return text, nil
}

// HiddenRune reports characters that are invisible or change how a line is read
// (controls other than newline and tab, DEL, BOM, zero-width, bidi marks).
func HiddenRune(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
		return true
	case r == 0xfeff || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2060 && r <= 0x2064) || r == 0x2028 || r == 0x2029:
		return true
	}
	return false
}

// DescriptionText validates a description: up to 4000 characters, lines
// separated by "\n" only, no hidden or control characters, and no line that
// parses as a machine line (a reserved key, in any case, followed by "=").
// Refused, never rewritten, so ParseNotes(notes) returns exactly the machine
// fields that were written and HintOf returns exactly the accepted text.
// Returns it trimmed.
func DescriptionText(text string) (string, error) {
	if len([]rune(text)) > 4000 {
		return "", Err(400, "a description is text up to 4000 characters", "description_long")
	}
	if !utf8.ValidString(text) {
		return "", Err(400, "a description is plain text: no control, invisible or line-separator characters except a new line", "description_chars")
	}
	for _, r := range text {
		if HiddenRune(r) {
			return "", Err(400, "a description is plain text: no control, invisible or line-separator characters except a new line", "description_chars")
		}
	}
	for _, line := range strings.Split(text, "\n") {
		k, _, ok := strings.Cut(line, "=")
		if ok && MachineKeyFold(strings.TrimSpace(k)) {
			return "", Err(400, "a description line cannot start with a reserved word followed by =", "description_reserved")
		}
	}
	return strings.TrimSpace(text), nil
}

// LabelsList validates labels (nil is none).
func LabelsList(labels []string) ([]string, error) {
	out, err := CheckLabels(labels)
	if err != nil {
		return nil, Err(400, err.Error(), "")
	}
	return out, nil
}

// ValidName: a section, item, site or system name (a-z 0-9 _ -, 1-32 chars).
func ValidName(name string) bool { return NameRE.MatchString(name) }

// SafeDescription turns free text that came from a file (a comment of an env
// file, say) into a description the notes can carry: lines that parse as a
// machine line, and any hidden or control character, are dropped. changed
// reports whether anything was dropped. (An import must not fail over a comment,
// but it must never let a comment become a machine field.)
func SafeDescription(text string) (clean string, changed bool) {
	var keep []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		bad := !utf8.ValidString(line)
		for _, r := range line {
			bad = bad || HiddenRune(r)
		}
		if k, _, ok := strings.Cut(line, "="); ok && MachineKeyFold(strings.TrimSpace(k)) {
			bad = true
		}
		if bad {
			changed = true
			continue
		}
		keep = append(keep, line)
	}
	clean = strings.Join(keep, "\n")
	if len([]rune(clean)) > 4000 {
		clean, changed = string([]rune(clean)[:4000]), true
	}
	return strings.TrimSpace(clean), changed
}
