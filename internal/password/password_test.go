package password

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// The policy's table. The passwords here are made-up examples, none of them protects anything.
func TestCheckTable(t *testing.T) {
	cases := []struct {
		name   string
		pw     string
		reason string // "" accepted; else the Code of the refusal
	}{
		{"empty", "", CodeTooShort},
		{"short random", "k7Qm2xVb9R", CodeTooShort},
		{"qwerty with digits and a symbol", "Qwerty123!", CodeTooShort},
		{"long keyboard walk", "Qwerty123456!asdf", CodeWeak},
		{"long keyboard row", "qwertyuiopasdfgh", CodeWeak},
		{"long repeat", "abcabcabcabcabcabc", CodeWeak},
		{"long single dictionary word with a digit", "Password12345678", CodeWeak},
		{"long date", "19900517199005", CodeWeak},
		{"long dictionary phrase", "iloveyouiloveyoutoo", CodeWeak},
		{"dictionary word, digits and symbol, long", "Dragon2024!Dragon2024!", CodeWeak},
		{"twelve random characters", "k7Qm2xVb9RtZ", ""},
		{"twelve random lower case", "qzkxvbnmwjfd", ""},
		{"six words", "wolf-prism-ladder-oven-brisk-quartz", ""},
		{"long random", "T9#vLq2!xRb7@mZp4", ""},
		{"non ASCII random", "щука-Ωmega-7Kq!zXp", ""},
	}
	for _, c := range cases {
		err := Check([]byte(c.pw))
		if c.reason == "" {
			if err != nil {
				t.Errorf("%s: refused: %v", c.name, err)
			}
			continue
		}
		var r *Refusal
		if !errors.As(err, &r) {
			t.Errorf("%s: want a refusal %q, got %v", c.name, c.reason, err)
			continue
		}
		if r.Code != c.reason {
			t.Errorf("%s: code %q, want %q", c.name, r.Code, c.reason)
		}
	}
}

func TestLengthCountsCharactersNotBytes(t *testing.T) {
	// 11 characters, 22 bytes
	err := Check([]byte("щукаΩюжфцйх"))
	var r *Refusal
	if !errors.As(err, &r) || r.Code != CodeTooShort {
		t.Fatalf("want too_short, got %v", err)
	}
}

func TestRefusalTellsWhyAndSuggestsTheGenerator(t *testing.T) {
	for pw, want := range map[string]string{
		"abc":                   "at least 12",
		"zxcvbnm,./asdfghjkl;'": "keyboard",
		"qwertyuiopasdfgh":      "dictionary",
		"abcabcabcabcabcabc":    "repeat",
		"iloveyouiloveyoutoo":   "repeat",
		"19900517199005":        "date",
	} {
		err := Check([]byte(pw))
		if err == nil {
			t.Fatalf("%q accepted", pw)
		}
		msg := err.Error()
		if !strings.Contains(msg, want) {
			t.Errorf("%q: message %q lacks %q", pw, msg, want)
		}
		if !strings.Contains(msg, "--generate") {
			t.Errorf("%q: message %q does not suggest the generator", pw, msg)
		}
		if strings.Contains(msg, pw) {
			t.Errorf("a refusal repeated the password")
		}
	}
}

func TestEstimateForTheMeter(t *testing.T) {
	if s := Estimate(nil); s.Level != 0 || s.OK {
		t.Fatalf("empty: %+v", s)
	}
	weak, strong := Estimate([]byte("password")), Estimate([]byte("T9#vLq2!xRb7@mZp4"))
	if weak.OK || weak.Level >= strong.Level || !strong.OK || strong.Level != MaxLevel {
		t.Fatalf("weak %+v strong %+v", weak, strong)
	}
	if weak.Reason == "" || strong.Reason != "" {
		t.Fatalf("reasons: %q %q", weak.Reason, strong.Reason)
	}
	// the meter and Check never disagree
	for _, pw := range []string{"", "a", "Qwerty123!", "Qwerty123456!asdf", "k7Qm2xVb9RtZ", "correct-horse-battery-staple-x"} {
		if (Check([]byte(pw)) == nil) != Estimate([]byte(pw)).OK {
			t.Errorf("Check and Estimate disagree about %q", pw)
		}
	}
}

func TestWordlist(t *testing.T) {
	if len(wordlist) != 7776 {
		t.Fatalf("the EFF large list has 7776 words, got %d", len(wordlist))
	}
	seen := map[string]bool{}
	for _, w := range wordlist {
		if w == "" || strings.ContainsAny(w, " \t\r\n") || seen[w] {
			t.Fatalf("bad or repeated word %q", w)
		}
		seen[w] = true
	}
}

// counter yields 0,1,2,... as bytes so the generator's choice is predictable.
type fixedReader struct{ b []byte }

func (f *fixedReader) Read(p []byte) (int, error) {
	if len(f.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, f.b)
	f.b = f.b[n:]
	return n, nil
}

func TestGenerateUsesTheReaderAndTheList(t *testing.T) {
	// two bytes per word, big endian: index 0, 1, 7775, then 7776 (rejected: not below the largest multiple... still below 62208),
	in := []byte{0, 0, 0, 1, 0x1e, 0x5f, 0, 2, 0, 3, 0, 4}
	got, err := Generate(&fixedReader{in}, 6)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{wordlist[0], wordlist[1], wordlist[7775], wordlist[2], wordlist[3], wordlist[4]}, "-")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestGenerateRejectsBiasedValues(t *testing.T) {
	// 62208 = 8*7776 is the first value that would make the low indexes likelier: it must be skipped
	in := []byte{0xf3, 0x00, 0, 5}
	got, err := Generate(&fixedReader{in}, 1)
	if err != nil || got != wordlist[5] {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestGenerateReaderFailureIsAnError(t *testing.T) {
	if _, err := Generate(&fixedReader{[]byte{0, 1, 0}}, 2); err == nil {
		t.Fatal("a reader that ends early must fail, not return a short passphrase")
	}
	if _, err := Generate(bytes.NewReader(nil), 0); err == nil {
		t.Fatal("zero words")
	}
}

func TestPassphraseShapeAndRandomness(t *testing.T) {
	a, err := Passphrase()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Passphrase()
	if a == b {
		t.Fatal("two passphrases are equal")
	}
	parts := strings.Split(a, "-")
	if len(parts) < Words {
		t.Fatalf("%q has fewer than %d parts", a, Words)
	}
}

// A generated passphrase passes the policy by construction: checked over many draws.
func TestEveryGeneratedPassphrasePassesThePolicy(t *testing.T) {
	n := 1000
	if testing.Short() {
		n = 200
	}
	for i := 0; i < n; i++ {
		p, err := Passphrase()
		if err != nil {
			t.Fatal(err)
		}
		if err := Check([]byte(p)); err != nil {
			t.Fatalf("a generated passphrase was refused: %v", err)
		}
	}
}

func TestVeryLongInputIsRefusedFastAndTheEstimateLooksAtTheFirstCharactersOnly(t *testing.T) {
	huge := []byte(strings.Repeat("aB3$xQ9!", 1250)) // 10000 characters
	start := time.Now()
	err := Check(huge)
	took := time.Since(start)
	var r *Refusal
	if !errors.As(err, &r) || r.Code != CodeTooLong || r.Max != MaxLength {
		t.Fatalf("want too_long, got %v", err)
	}
	if !strings.Contains(err.Error(), "at most 256") {
		t.Fatalf("message %q", err)
	}
	if took > time.Second {
		t.Fatalf("a 10000 character input took %v", took)
	}
	if s := Estimate(huge); s.OK || s.Code != CodeTooLong {
		t.Fatalf("%+v", s)
	}
	// the edge: 256 characters of the policy's liking pass, 257 do not, and the time stays small
	ok := []byte(strings.Repeat("k7Qm2xVb9RtZ", 22)[:MaxLength])
	start = time.Now()
	e1, e2 := Check(ok), Check(append(ok, 'x'))
	if e2 == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("257: %v, took %v", e2, time.Since(start))
	}
	_ = e1 // a repeat of 12 characters is weak: only the boundary of the length code is under test here
	var r2 *Refusal
	if !errors.As(e2, &r2) || r2.Code != CodeTooLong {
		t.Fatalf("%v", e2)
	}
	if errors.As(e1, &r2) && r2.Code == CodeTooLong {
		t.Fatal("256 characters are not too long")
	}
}

func TestFirstRunes(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{{"", 3, ""}, {"abc", 3, "abc"}, {"abcd", 3, "abc"}, {"щукаΩ", 3, "щук"}, {"ab", 0, ""}} {
		if got := firstRunes([]byte(c.in), c.n); got != c.want {
			t.Errorf("%q %d: %q", c.in, c.n, got)
		}
	}
}
