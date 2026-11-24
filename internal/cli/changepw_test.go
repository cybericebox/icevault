package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/password"
	"github.com/cybericebox/icevault/pkg/vault"
)

const newPw = "Zq4#nW8@pRb3yHk7" // a throwaway that passes the policy

func readFileT(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// opensWith says whether the file at path opens with the password (and the key file of the environment, when one is set).
func opensWith(t *testing.T, path, pass, keyFile string) bool {
	t.Helper()
	v, err := vault.Open(path, vault.Credentials{Password: []byte(pass), KeyFile: keyFile})
	if err == nil {
		v.Close()
	}
	return err == nil
}

func TestChangePasswordReEncryptsInPlace(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	h.seed(vault.Entry{Group: "g", Title: "t", Password: []byte("value-1")})
	p := h.env["ICEVAULT_VAULT"]
	h.pw = []string{pw, newPw, newPw}
	h.asked = 0
	if rc := h.run("change-password"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if _, err := os.Stat(p + ".prev"); err == nil {
		t.Fatal("the previous copy still opens with the old password and was left")
	}
	if opensWith(t, p, pw, "") {
		t.Fatal("the old password still opens the vault")
	}
	v, err := vault.Open(p, vault.Credentials{Password: []byte(newPw)})
	if err != nil {
		t.Fatal(err)
	}
	e, err := v.Get("g/t")
	if err != nil || string(e.Password) != "value-1" {
		t.Fatalf("the content changed: %v", err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if h.asked != 3 {
		t.Fatalf("asked %d times: the current one, the new one, again", h.asked)
	}
	for _, s := range []string{h.out.String(), h.errb.String()} {
		if strings.Contains(s, pw) || strings.Contains(s, newPw) {
			t.Fatal("a password is in the output")
		}
	}
	// the date is in the info file, and no secret is
	inf := readInfo(p)
	if d, _ := inf["password_changed"].(string); d == "" {
		t.Fatalf("no password_changed in the info file: %v", inf)
	}
	if b := readFileT(t, infoPath(p)); bytes.Contains(b, []byte(newPw)) || bytes.Contains(b, []byte(pw)) {
		t.Fatal("a password is in the info file")
	}
}

func TestChangePasswordRefusesBeforeAnythingIsWritten(t *testing.T) {
	cases := []struct {
		name string
		pw   []string
		msg  string
	}{
		{"weak new password", []string{pw, "Qwerty123!", "Qwerty123!"}, "at least 12"},
		{"a dictionary phrase", []string{pw, "iloveyouiloveyoutoo", "iloveyouiloveyoutoo"}, "too easy to guess"},
		{"mismatch", []string{pw, newPw, newPw + "x"}, "do not match"},
		{"the same password", []string{pw, pw, pw}, "same as the current"},
		{"wrong current password", []string{"not-the-password", newPw, newPw}, "wrong password"},
	}
	for _, c := range cases {
		h := newHarness(t)
		h.initVault()
		p := h.env["ICEVAULT_VAULT"]
		before := readFileT(t, p)
		prevBefore, _ := os.ReadFile(p + ".prev")
		h.pw = c.pw
		rc := h.run("change-password")
		if rc != 1 || !strings.Contains(h.errb.String(), c.msg) {
			t.Errorf("%s: rc=%d %q", c.name, rc, h.errb.String())
		}
		if !bytes.Equal(readFileT(t, p), before) {
			t.Errorf("%s: the vault file changed", c.name)
		}
		if prev, _ := os.ReadFile(p + ".prev"); !bytes.Equal(prev, prevBefore) {
			t.Errorf("%s: a save happened (the previous copy moved)", c.name)
		}
		if !opensWith(t, p, pw, "") {
			t.Errorf("%s: the old password no longer opens the vault", c.name)
		}
		if inf := readInfo(p); inf["password_changed"] != nil {
			t.Errorf("%s: the info file records a change", c.name)
		}
		for _, s := range []string{h.out.String(), h.errb.String()} {
			for _, secret := range c.pw {
				if secret != "" && strings.Contains(s, secret) {
					t.Errorf("%s: a password is in the output", c.name)
				}
			}
		}
	}
}

// A wrong current password stops the command before the new one is asked for.
func TestChangePasswordWrongCurrentAsksNothingElse(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	h.pw = []string{"not-the-password", newPw, newPw}
	h.asked = 0
	if rc := h.run("change-password"); rc != 1 || h.asked != 1 {
		t.Fatalf("rc=%d asked=%d", rc, h.asked)
	}
}

func TestChangePasswordRefusalsComeBeforeThePrompt(t *testing.T) {
	h := newHarness(t) // no vault file
	h.asked = 0
	if rc := h.run("change-password"); rc != 1 || !strings.Contains(h.errb.String(), "no vault at") || h.asked != 0 {
		t.Fatalf("rc=%d asked=%d %s", rc, h.asked, h.errb.String())
	}
	h.initVault()
	h.env["ICEVAULT_KEYFILE"] = filepath.Join(h.dir, "missing.key")
	h.asked = 0
	if rc := h.run("change-password"); rc != 1 || !strings.Contains(h.errb.String(), "does not exist") || h.asked != 0 {
		t.Fatalf("rc=%d asked=%d %s", rc, h.asked, h.errb.String())
	}
	delete(h.env, "ICEVAULT_KEYFILE")
	h.asked = 0
	if rc := h.run("change-password", "--nope"); rc != 2 || h.asked != 0 {
		t.Fatalf("rc=%d asked=%d", rc, h.asked)
	}
}

func TestChangePasswordNeedsATerminal(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	h.pw = nil
	if rc := h.run("change-password"); rc != 1 || !strings.Contains(h.errb.String(), NeedsOwner) {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
}

func TestChangePasswordGenerate(t *testing.T) {
	want, err := password.PassphraseFrom(&pattern{})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.initVault()
	p := h.env["ICEVAULT_VAULT"]
	h.rand = &pattern{}
	h.pw = []string{pw, want} // the current one, then the generated one typed back
	h.asked = 0
	if rc := h.run("change-password", "--generate"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if h.asked != 2 {
		t.Fatalf("asked %d times", h.asked)
	}
	if n := strings.Count(h.errb.String(), want); n != 1 {
		t.Fatalf("the passphrase is shown %d times on the terminal stream, want once", n)
	}
	if strings.Contains(h.out.String(), want) {
		t.Fatal("the passphrase went to the output stream")
	}
	if !opensWith(t, p, want, "") || opensWith(t, p, pw, "") {
		t.Fatal("the generated passphrase is not the password now")
	}
}

func TestChangePasswordGenerateNotTypedBackChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	p := h.env["ICEVAULT_VAULT"]
	before := readFileT(t, p)
	h.rand = &pattern{}
	h.pw = []string{pw, "one", "two", "three"}
	if rc := h.run("change-password", "--generate"); rc != 1 || !strings.Contains(h.errb.String(), "not typed back correctly") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if !bytes.Equal(readFileT(t, p), before) || !opensWith(t, p, pw, "") {
		t.Fatal("the vault changed")
	}
}

// The key file stays the same, and the new password needs it as the old one did.
func TestChangePasswordKeepsTheKeyFile(t *testing.T) {
	h := newHarness(t)
	kf := filepath.Join(h.dir, "k.key")
	if rc := h.run("keyfile", "new", kf); rc != 0 {
		t.Fatal(h.errb.String())
	}
	h.env["ICEVAULT_KEYFILE"] = kf
	h.initVault()
	p := h.env["ICEVAULT_VAULT"]
	h.pw = []string{pw, newPw, newPw}
	if rc := h.run("change-password"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if !opensWith(t, p, newPw, kf) || opensWith(t, p, newPw, "") || opensWith(t, p, pw, kf) {
		t.Fatal("the key file or the password is not as it should be")
	}
}

// The password behind Touch ID is never taken as the current password, and after a change it no longer opens the vault: the binding is removed.
func TestChangePasswordRemovesTheTouchIDBinding(t *testing.T) {
	h, f := tidHarness(t)
	if rc := h.run("touchid", "enable"); rc != 0 {
		t.Fatal(h.errb.String())
	}
	f.calls = nil
	f.decrypt = []byte(pw) // would open the vault: it must not be asked
	h.pw = []string{pw, newPw, newPw}
	h.asked = 0
	if rc := h.run("change-password"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	for _, c := range f.calls {
		if strings.Contains(c, "--decrypt") {
			t.Fatal("the Touch ID password was used for the current password")
		}
	}
	if h.asked != 3 {
		t.Fatalf("asked %d times", h.asked)
	}
	if !strings.Contains(h.out.String(), "Touch ID is off; `touchid enable` stores the new password") {
		t.Fatalf("no Touch ID line: %q", h.out.String())
	}
	ents, _ := os.ReadDir(h.env["ICEVAULT_TOUCHID_DIR"])
	if len(ents) != 0 {
		t.Fatalf("%d Touch ID files are left", len(ents))
	}
	if rc := h.run("touchid", "status"); !strings.Contains(h.out.String(), "Touch ID unlock: off") || rc != 0 {
		t.Fatal(h.out.String())
	}
}

// When the save fails nothing else happens: the file, the Touch ID binding and the info file stay as they were.
func TestChangePasswordFailedSaveLeavesEverythingAsItWas(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a read-only folder does not stop root")
	}
	h, _ := tidHarness(t)
	if rc := h.run("touchid", "enable"); rc != 0 {
		t.Fatal(h.errb.String())
	}
	p := h.env["ICEVAULT_VAULT"]
	before := readFileT(t, p)
	infoBefore := readFileT(t, infoPath(p))
	dir := filepath.Dir(p)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	h.pw = []string{pw, newPw, newPw}
	rc := h.run("change-password")
	_ = os.Chmod(dir, 0o700)
	if rc != 1 || !strings.Contains(h.errb.String(), "was not changed") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if !bytes.Equal(readFileT(t, p), before) || !opensWith(t, p, pw, "") {
		t.Fatal("the vault changed")
	}
	if !bytes.Equal(readFileT(t, infoPath(p)), infoBefore) {
		t.Fatal("the info file changed")
	}
	if ents, _ := os.ReadDir(h.env["ICEVAULT_TOUCHID_DIR"]); len(ents) != 2 {
		t.Fatalf("the Touch ID binding was touched: %d files", len(ents))
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("a temp file is left: %s", e.Name())
		}
	}
}

// Copies made before the change open with the OLD password: they are listed, never deleted, and --refresh-copies writes the new file to the standing ones.
func TestChangePasswordListsTheOldCopies(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	p := h.env["ICEVAULT_VAULT"]
	standing, once := filepath.Join(h.dir, "standing"), filepath.Join(h.dir, "once")
	for _, d := range []string{standing, once} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if rc := h.run("copies", "add", standing); rc != 0 {
		t.Fatal(h.errb.String())
	}
	if rc := h.run("copy", "--to", once); rc != 0 {
		t.Fatal(h.errb.String())
	}
	oldStanding, oldOnce := readFileT(t, filepath.Join(standing, "v.kdbx")), readFileT(t, filepath.Join(once, "v.kdbx"))

	h.pw = []string{pw, newPw, newPw}
	if rc := h.run("change-password"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	out := h.out.String() + h.errb.String()
	for _, want := range []string{filepath.Join(standing, "v.kdbx"), filepath.Join(once, "v.kdbx"), "OLD password", "--refresh-copies"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	if !bytes.Equal(readFileT(t, filepath.Join(standing, "v.kdbx")), oldStanding) || !bytes.Equal(readFileT(t, filepath.Join(once, "v.kdbx")), oldOnce) {
		t.Fatal("a copy was changed without being asked")
	}

	// now with the refresh: the standing copy follows, the one-off copy is only listed, and the previous copy that the refresh keeps is listed too
	h.pw = []string{newPw, newPw + "-2", newPw + "-2"}
	h.pw[1], h.pw[2] = "Rt5%mK9&xWc2vBn8", "Rt5%mK9&xWc2vBn8"
	if rc := h.run("change-password", "--refresh-copies"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if !opensWith(t, filepath.Join(standing, "v.kdbx"), "Rt5%mK9&xWc2vBn8", "") {
		t.Fatal("the standing copy was not refreshed")
	}
	out = h.out.String() + h.errb.String()
	if !strings.Contains(out, filepath.Join(once, "v.kdbx")) || !strings.Contains(out, filepath.Join(standing, "v.kdbx.prev")) {
		t.Fatalf("the files that still open with an old password are not listed:\n%s", out)
	}
	if strings.Contains(out, "stale: "+p+" ") {
		t.Fatal("the vault itself is listed as old")
	}
	if _, err := os.Stat(filepath.Join(once, "v.kdbx")); err != nil {
		t.Fatal("a user file was deleted")
	}
	_ = p
}

// No copies at all: no warning about them.
func TestChangePasswordWithoutCopiesSaysNothingAboutThem(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	h.pw = []string{pw, newPw, newPw}
	if rc := h.run("change-password"); rc != 0 {
		t.Fatal(h.errb.String())
	}
	if strings.Contains(h.out.String()+h.errb.String(), "OLD password") {
		t.Fatalf("a warning without a copy: %s", h.out.String())
	}
}

// A binding that cannot be removed is reported, not called "off": it holds the old password.
func TestChangePasswordReportsABindingItCannotRemove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a read-only folder does not stop root")
	}
	h, _ := tidHarness(t)
	if rc := h.run("touchid", "enable"); rc != 0 {
		t.Fatal(h.errb.String())
	}
	tdir := h.env["ICEVAULT_TOUCHID_DIR"]
	if err := os.Chmod(tdir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(tdir, 0o700) }()
	h.pw = []string{pw, newPw, newPw}
	rc := h.run("change-password")
	_ = os.Chmod(tdir, 0o700)
	if rc != 0 {
		t.Fatalf("the change itself must stand: rc=%d %s", rc, h.errb.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "WARNING: the Touch ID binding") || strings.Contains(out, "Touch ID is off;") {
		t.Fatalf("the failed removal is not reported:\n%s", out)
	}
	ents, _ := os.ReadDir(tdir)
	if len(ents) != 2 {
		t.Fatalf("%d files", len(ents))
	}
	for _, en := range ents {
		if !strings.Contains(out, filepath.Join(tdir, en.Name())) {
			t.Errorf("the output does not name %s", en.Name())
		}
	}
	if !opensWith(t, h.env["ICEVAULT_VAULT"], newPw, "") {
		t.Fatal("the password was not changed")
	}
}
