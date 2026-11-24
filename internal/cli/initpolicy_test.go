package cli

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/password"
	"github.com/cybericebox/icevault/pkg/vault"
)

// pattern is a fixed, endless source of bytes: the same draws every run.
type pattern struct{ n int }

func (p *pattern) Read(b []byte) (int, error) {
	for i := range b {
		p.n++
		b[i] = byte(p.n*37 + p.n/7)
	}
	return len(b), nil
}

var _ io.Reader = (*pattern)(nil)

func vaultOpens(t *testing.T, h *harness, pw string) bool {
	t.Helper()
	v, err := vault.Open(h.env["ICEVAULT_VAULT"], vault.Credentials{Password: []byte(pw)})
	if err == nil {
		v.Close()
	}
	return err == nil
}

func nothingMade(t *testing.T, h *harness) {
	t.Helper()
	p := h.env["ICEVAULT_VAULT"]
	for _, f := range []string{p, p + ".info.json"} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s was written", f)
		}
	}
	if readInfo(p) != nil {
		t.Error("an info file was written")
	}
}

func TestInitVaultRefusesWeakPasswordsBeforeAnythingIsWritten(t *testing.T) {
	cases := []struct{ name, pw, msg string }{
		{"short", "k7Qm2xVb9R", "at least 12"},
		{"qwerty", "Qwerty123!", "at least 12"},
		{"long keyboard walk", "Qwerty123456!asdf", "too easy to guess"},
		{"long dictionary phrase", "iloveyouiloveyoutoo", "too easy to guess"},
		{"repeat", "abcabcabcabcabcabc", "repeats"},
		{"too long", strings.Repeat("k7Qm2xVb9RtZ", 25), "at most 256"},
	}
	for _, c := range cases {
		h := newHarness(t)
		h.pw = []string{c.pw, c.pw}
		rc := h.run("init-vault", "--decryption-time", "100")
		got := h.errb.String()
		if rc != 1 || !strings.Contains(got, c.msg) || (c.name != "too long" && !strings.Contains(got, "--generate")) || !strings.Contains(got, "nothing was made") {
			t.Errorf("%s: rc=%d %q", c.name, rc, got)
		}
		if strings.Contains(got+h.out.String(), c.pw) {
			t.Errorf("%s: the password is in the output", c.name)
		}
		nothingMade(t, h)
	}
}

func TestInitVaultAcceptsAStrongPassword(t *testing.T) {
	h := newHarness(t)
	h.pw = []string{"k7Qm2xVb9RtZ", "k7Qm2xVb9RtZ"}
	if rc := h.run("init-vault", "--decryption-time", "100"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if !vaultOpens(t, h, "k7Qm2xVb9RtZ") {
		t.Fatal("the vault does not open with its password")
	}
}

func TestInitVaultKeyFileOnlyStaysAllowed(t *testing.T) {
	h := newHarness(t)
	kf := h.dir + "/k.keyx"
	if rc := h.run("keyfile", "new", kf); rc != 0 {
		t.Fatalf("keyfile rc=%d %s", rc, h.errb.String())
	}
	h.env["ICEVAULT_KEYFILE"] = kf
	h.pw = []string{"", ""}
	if rc := h.run("init-vault", "--decryption-time", "100"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	// a key file does not excuse a weak password that is typed
	h2 := newHarness(t)
	h2.env["ICEVAULT_KEYFILE"] = kf
	h2.pw = []string{"Qwerty123!", "Qwerty123!"}
	if rc := h2.run("init-vault", "--decryption-time", "100"); rc != 1 {
		t.Fatalf("a weak password with a key file: rc=%d", rc)
	}
	nothingMade(t, h2)
}

func TestInitVaultGenerate(t *testing.T) {
	want, err := password.PassphraseFrom(&pattern{})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.rand = &pattern{}
	h.pw = []string{want} // typed back
	if rc := h.run("init-vault", "--generate", "--decryption-time", "100"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if h.asked != 1 {
		t.Fatalf("asked %d times: the generated one is typed back once", h.asked)
	}
	if n := strings.Count(h.errb.String(), want); n != 1 {
		t.Fatalf("the passphrase is shown %d times on the terminal stream, want once", n)
	}
	if strings.Contains(h.out.String(), want) {
		t.Fatal("the passphrase went to the output stream, which may be redirected to a file")
	}
	if !vaultOpens(t, h, want) {
		t.Fatal("the vault does not open with the generated passphrase")
	}
	if len(strings.Split(want, "-")) < password.Words {
		t.Fatalf("%d words", len(strings.Split(want, "-")))
	}
}

func TestInitVaultGenerateMismatchMakesNothing(t *testing.T) {
	h := newHarness(t)
	h.rand = &pattern{}
	h.pw = []string{"one", "two", "three"}
	rc := h.run("init-vault", "--generate", "--decryption-time", "100")
	if rc != 1 || !strings.Contains(h.errb.String(), "not typed back correctly") {
		t.Fatalf("rc=%d %q", rc, h.errb.String())
	}
	nothingMade(t, h)
}

func TestInitVaultGenerateNeedsATerminal(t *testing.T) {
	h := newHarness(t)
	h.rand = &pattern{}
	h.pw = nil
	rc := h.run("init-vault", "--generate")
	if rc != 1 || !strings.Contains(h.errb.String(), NeedsOwner) {
		t.Fatalf("rc=%d %q", rc, h.errb.String())
	}
	nothingMade(t, h)
}
