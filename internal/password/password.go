// Package password is the one policy for a new vault master password, shared by the command line (init-vault) and the window (New vault), and the
// generator of passphrases. It has no say over how an existing vault opens: nothing here runs on unlock.
//
// The policy: at least 12 characters AND a strength estimate (zxcvbn, see NOTICE) of at least 1e12 guesses. The estimate refuses dictionary words
// (also with digits, case changes and l33t), keyboard walks, repeats, sequences, dates and the common patterns built from them, however long the
// password is. An empty password stays possible only where a key file stands behind it; that rule is the caller's, not decided here.
package password

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/trustelem/zxcvbn"
	"github.com/trustelem/zxcvbn/match"
)

const (
	// MinLength is the least number of characters (runes) of a new master password.
	MinLength = 12
	// MinGuessesLog10 is the least estimate, as a power of ten: 1e12 guesses. Characters no pattern explains count 10 each in the zxcvbn estimate, so
	// 12 random characters reach exactly 1e12 (the shortest password that can pass), and a pattern with a few changes stays far below the line. The line
	// is set by the vault key derivation: Argon2d with 64 MiB makes one guess cost about a millisecond of a GPU, so one GPU makes about 1e3 guesses a
	// second and 1e12 guesses take about 30 years on it. A lower line (1e10, about four months) was found too weak; a higher one would refuse
	// good 12-character random passwords. A phrase of common words does not get past it with separators: the estimate is the lower of the password as typed and with its separators
	// (space - _ . , ; : / + and tab) removed.
	MinGuessesLog10 = 12
	// MaxLength is the most characters of a new master password. zxcvbn takes time about cubic in the length, so a longer one is refused at once
	// (nothing is estimated), and only the first EstimateLength characters are estimated, as the original zxcvbn does.
	MaxLength = 256
	// EstimateLength is how many characters the estimate looks at.
	EstimateLength = 100
	// Words is the length of a generated passphrase.
	Words = 6
	// MaxLevel is the top of the meter: the level of a password the policy accepts.
	MaxLevel = 4
)

// Codes of a refusal (the window translates them: srv.<code> in messages.json).
const (
	CodeTooShort = "password_too_short"
	CodeWeak     = "password_weak"
	CodeTooLong  = "password_too_long"
)

// Reasons of a weak password: what the estimate found in it.
const (
	ReasonDictionary = "dictionary"
	ReasonKeyboard   = "keyboard"
	ReasonRepeat     = "repeat"
	ReasonSequence   = "sequence"
	ReasonDate       = "date"
	ReasonCommon     = "common" // nothing single to name: simply too easy to guess
)

//go:embed eff_large_wordlist.txt
var wordlistRaw string // the EFF large wordlist, unchanged (CC BY 3.0, see NOTICE): "11111<TAB>abacus" per line

var wordlist = parseWordlist(wordlistRaw)

func parseWordlist(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			out = append(out, f[1])
		}
	}
	return out
}

// Refusal is a password the policy does not accept. Its text says why and points to the generator; it never holds the password.
type Refusal struct {
	Code   string // CodeTooShort or CodeWeak
	Reason string // for CodeWeak: a Reason* constant
	Min    int    // MinLength
	Max    int    // MaxLength
}

func (r *Refusal) Error() string {
	const hint = " Use a generated passphrase instead (init-vault --generate, or Generate in the window)."
	switch r.Code {
	case CodeTooShort:
		return fmt.Sprintf("the password is too short: use at least %d characters.%s", r.Min, hint)
	case CodeTooLong:
		return fmt.Sprintf("the password is too long: use at most %d characters.", r.Max)
	}
	return "the password is too easy to guess (" + reasonText[r.Reason] + ")." + hint
}

var reasonText = map[string]string{
	ReasonDictionary: "it is built from dictionary words or common passwords",
	ReasonKeyboard:   "it follows a keyboard pattern",
	ReasonRepeat:     "it is made of repeats",
	ReasonSequence:   "it is a sequence of characters in order",
	ReasonDate:       "it contains a date or a year",
	ReasonCommon:     "it is a common pattern with a few changes",
}

// Strength is the estimate of one password, for the meter of the window and for Check.
type Strength struct {
	Level  int     // 0 empty, 1 very weak, 2 weak, 3 almost there, MaxLevel accepted
	OK     bool    // the policy accepts it
	Length int     // characters
	Log10  float64 // log10 of the estimated guesses
	Code   string  // "" when OK
	Reason string  // for CodeWeak
}

// Estimate judges a password. It keeps nothing, but the estimate library takes a Go string, which is a copy of the characters that cannot be wiped:
// the copy is as short as it can be (the first EstimateLength characters) and lives for the call only.
func Estimate(pw []byte) Strength {
	s := Strength{Length: utf8.RuneCount(pw)}
	if s.Length == 0 {
		s.Code = CodeTooShort
		return s
	}
	if s.Length > MaxLength {
		s.Code, s.Level = CodeTooLong, 1
		return s
	}
	res := weakest(pw)
	s.Log10 = math.Log10(math.Max(res.Guesses, 1))
	switch {
	case res.Guesses >= math.Pow(10, MinGuessesLog10): // not through Log10: a round 1e12 must not fall to 11.999...
		s.Level = MaxLevel
	case s.Log10 >= 10:
		s.Level = 3
	case s.Log10 >= 6:
		s.Level = 2
	default:
		s.Level = 1
	}
	if s.Level < MaxLevel {
		s.Reason = reasonOf(res.Sequence)
	}
	switch {
	case s.Length < MinLength:
		s.Code, s.Level = CodeTooShort, min(s.Level, MaxLevel-1)
	case s.Level < MaxLevel:
		s.Code = CodeWeak
	default:
		s.OK = true
	}
	return s
}

// separators are the characters people put between words to make a phrase look random: zxcvbn counts each as one unexplained character (10
// guesses), so "sunshine monkey dragon" would be judged far above "sunshinemonkeydragon".
const separators = " \t-_.,;:/+"

// weakest is the estimate of the password as typed and of the password with its separators removed, whichever is lower: a separator buys nothing.
// Each looks at the first EstimateLength characters. The estimate library takes a Go string; the copies live for the call only.
func weakest(pw []byte) zxcvbn.Result {
	raw := zxcvbn.PasswordStrength(firstRunes(pw, EstimateLength), nil)
	plain := bytes.Map(func(r rune) rune {
		if strings.ContainsRune(separators, r) {
			return -1
		}
		return r
	}, pw)
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	if len(plain) == len(pw) {
		return raw // nothing to remove
	}
	if len(plain) == 0 {
		return raw
	}
	if bare := zxcvbn.PasswordStrength(firstRunes(plain, EstimateLength), nil); bare.Guesses < raw.Guesses {
		return bare
	}
	return raw
}

// firstRunes is the first n characters of b as a string.
func firstRunes(b []byte, n int) string {
	for i := range string(b) { // a range over a string does not copy it
		if n == 0 {
			return string(b[:i])
		}
		n--
	}
	return string(b)
}

// reasonOf names the pattern that covers most of the password.
func reasonOf(seq []*match.Match) string {
	cover := map[string]int{}
	for _, m := range seq {
		r := ""
		switch m.Pattern {
		case "dictionary":
			r = ReasonDictionary
		case "spatial":
			r = ReasonKeyboard
		case "repeat":
			r = ReasonRepeat
		case "sequence":
			r = ReasonSequence
		case "date", "regex":
			r = ReasonDate
		}
		if r != "" {
			cover[r] += m.J - m.I + 1
		}
	}
	best, most := ReasonCommon, 0
	for _, r := range []string{ReasonDictionary, ReasonKeyboard, ReasonRepeat, ReasonSequence, ReasonDate} { // fixed order: a tie is not random
		if cover[r] > most {
			best, most = r, cover[r]
		}
	}
	return best
}

// Check is nil when the policy accepts pw, else a *Refusal.
func Check(pw []byte) error {
	s := Estimate(pw)
	if s.OK {
		return nil
	}
	return &Refusal{Code: s.Code, Reason: s.Reason, Min: MinLength, Max: MaxLength}
}

// Generate makes a passphrase of n random words of the EFF large list joined with "-". Every word is drawn from r (crypto/rand in Passphrase) by
// rejection sampling, so no word is likelier than another. A reader that fails is an error: never a shorter passphrase.
func Generate(r io.Reader, n int) (string, error) {
	if n < 1 {
		return "", errors.New("a passphrase needs at least one word")
	}
	const span = 1 << 16
	limit := span - span%len(wordlist) // values from here up would favour the low indexes
	words := make([]string, 0, n)
	var buf [2]byte
	for len(words) < n {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return "", fmt.Errorf("the random source failed: %w", err)
		}
		v := int(buf[0])<<8 | int(buf[1])
		if v >= limit {
			continue
		}
		words = append(words, wordlist[v%len(wordlist)])
	}
	return strings.Join(words, "-"), nil
}

// Passphrase is a generated passphrase of Words words from crypto/rand that the policy accepts (a draw the estimate would refuse, which
// needs six unusually common words, is drawn again).
func Passphrase() (string, error) { return PassphraseFrom(rand.Reader) }

// PassphraseFrom is Passphrase with another source of randomness (tests).
func PassphraseFrom(r io.Reader) (string, error) {
	for i := 0; i < 100; i++ {
		p, err := Generate(r, Words)
		if err != nil {
			return "", err
		}
		if Check([]byte(p)) == nil {
			return p, nil
		}
	}
	return "", errors.New("no acceptable passphrase after 100 draws")
}
