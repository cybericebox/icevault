package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeAge stands in for age and age-plugin-se: it records calls, never touches a sensor, and "encrypts" by storing the password it was given.
type fakeAge struct {
	calls   []string
	stored  []byte // what age -r got on stdin
	decrypt []byte // what age --decrypt returns
	code    int    // exit code of age --decrypt
	timeout bool
	missing map[string]bool
}

func (f *fakeAge) Has(n string) bool { return !f.missing[n] }

func (f *fakeAge) Run(name string, args []string, stdin []byte, _ time.Duration) ([]byte, int, error) {
	f.calls = append(f.calls, name+" "+args[0])
	switch {
	case name == "age-plugin-se" && args[0] == "keygen":
		return nil, 0, os.WriteFile(args[len(args)-1], []byte("AGE-PLUGIN-SE-1FAKE"), 0o600)
	case name == "age-plugin-se" && args[0] == "recipients":
		return []byte("age1se1fakerecipient\n"), 0, nil
	case name == "age" && args[0] == "-r":
		f.stored = append([]byte(nil), stdin...)
		return nil, 0, os.WriteFile(args[len(args)-1], []byte("ciphertext-not-the-password"), 0o600)
	case name == "age" && args[0] == "--decrypt":
		if f.timeout {
			return nil, -1, errTimeout
		}
		return f.decrypt, f.code, nil
	}
	return nil, 1, errors.New("unexpected call")
}

func tidHarness(t *testing.T) (*harness, *fakeAge) {
	h := newHarness(t)
	h.initVault()
	f := &fakeAge{missing: map[string]bool{}}
	h.exec, h.tid = f, true
	h.env["ICEVAULT_TOUCHID_DIR"] = filepath.Join(h.dir, "tid")
	return h, f
}

func TestTouchIDEnableUnlockDisable(t *testing.T) {
	h, f := tidHarness(t)
	if rc := h.run("touchid", "status"); rc != 0 || !strings.Contains(h.out.String(), "Touch ID unlock: off") {
		t.Fatal(h.out.String())
	}
	h.pw = []string{"wrong"}
	if rc := h.run("touchid", "enable"); rc != 1 || !strings.Contains(h.errb.String(), "wrong password") || len(f.stored) != 0 {
		t.Fatalf("a wrong password was stored: rc=%d", rc)
	}
	h.pw = []string{pw}
	if rc := h.run("touchid", "enable"); rc != 0 || !strings.Contains(h.out.String(), "Touch ID unlock is on") {
		t.Fatalf("%s %s", h.out.String(), h.errb.String())
	}
	if string(f.stored) != pw {
		t.Fatal("age did not get the password on stdin")
	}
	// the password is in no file of the Touch ID folder
	ents, _ := os.ReadDir(h.env["ICEVAULT_TOUCHID_DIR"])
	if len(ents) != 2 {
		t.Fatalf("%d files", len(ents))
	}
	for _, en := range ents {
		data, _ := os.ReadFile(filepath.Join(h.env["ICEVAULT_TOUCHID_DIR"], en.Name()))
		if strings.Contains(string(data), pw) {
			t.Fatal("password on disk")
		}
		if st, _ := en.Info(); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
	if rc := h.run("touchid", "status"); !strings.Contains(h.out.String(), "Touch ID unlock: ON") || rc != 0 {
		t.Fatal(h.out.String())
	}
	// unlock through Touch ID: no password is asked
	f.decrypt, h.pw = []byte(pw), nil
	if rc := h.run("view", "--item", "a/b"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	// a stale password behind Touch ID falls back to typing
	f.decrypt, h.pw = []byte("stale"), []string{pw}
	if rc := h.run("view", "--item", "a/b"); rc != 0 || !strings.Contains(h.errb.String(), "no longer opens the vault") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	// cancelled, timed out: typing
	f.code = 1
	h.pw = []string{pw}
	if rc := h.run("view", "--item", "a/b"); rc != 0 || !strings.Contains(h.errb.String(), "Touch ID did not unlock") {
		t.Fatalf("%s", h.errb.String())
	}
	f.timeout = true
	h.pw = []string{pw}
	if rc := h.run("view", "--item", "a/b"); rc != 0 || !strings.Contains(h.errb.String(), "no touch in time") {
		t.Fatalf("%s", h.errb.String())
	}
	// off by the environment: age is not called
	f.calls = nil
	h.env["ICEVAULT_NO_TOUCHID"] = "1"
	h.pw = []string{pw}
	if rc := h.run("view", "--item", "a/b"); rc != 0 || len(f.calls) != 0 {
		t.Fatalf("calls %v", f.calls)
	}
	delete(h.env, "ICEVAULT_NO_TOUCHID")
	if rc := h.run("touchid", "disable"); rc != 0 || !strings.Contains(h.out.String(), "2 file(s) removed") {
		t.Fatal(h.out.String())
	}
}

// A program (no terminal) runs the command: Touch ID is the only way in, the owner is shown the command line, and without a touch the run stops
// without asking for the password.
func TestTouchIDWithoutTerminalShowsTheCommand(t *testing.T) {
	h, f := tidHarness(t)
	pw := h.pw[0]
	if rc := h.run("touchid", "enable"); rc != 0 {
		t.Fatal(h.errb.String())
	}
	f.decrypt, h.pw, h.notified, h.asked = []byte(pw), nil, nil, 0
	if rc := h.run("view", "--item", "a/b"); rc != 0 || h.asked != 0 {
		t.Fatalf("rc=%d asked=%d %s", rc, h.asked, h.errb.String())
	}
	if len(h.notified) != 1 || h.notified[0] != "icevault view --item a/b" {
		t.Fatalf("shown: %q", h.notified)
	}
	f.code = 1
	if rc := h.run("view", "--item", "a/b"); rc != 1 || !strings.Contains(h.errb.String(), NeedsOwner) {
		t.Fatalf("no touch: rc=%d %s", rc, h.errb.String())
	}
	if long := commandLine([]string{strings.Repeat("x", 500)}); len([]rune(long)) != 200 {
		t.Fatalf("the shown line is %d long", len([]rune(long)))
	}
}

func TestTouchIDMissingToolsAndPlatform(t *testing.T) {
	h, f := tidHarness(t)
	f.missing["age-plugin-se"] = true
	if rc := h.run("touchid", "enable"); rc != 1 || !strings.Contains(h.errb.String(), "age-plugin-se is not installed: brew install") {
		t.Fatal(h.errb.String())
	}
	if rc := h.run("touchid", "status"); rc != 0 || !strings.Contains(h.out.String(), "age-plugin-se: NOT installed") {
		t.Fatal(h.out.String())
	}
	h.tid = false // no terminal or not macOS
	if rc := h.run("touchid", "status"); rc != 0 || !strings.Contains(h.out.String(), "not available on this platform") {
		t.Fatal(h.out.String())
	}
}

func TestTouchIDMigratesOldBinding(t *testing.T) {
	h, _ := tidHarness(t)
	p := h.env["ICEVAULT_VAULT"]
	_ = os.WriteFile(p+oldKeySuffix, []byte("k"), 0o600)
	_ = os.WriteFile(p+oldBlobSuffix, []byte("b"), 0o600)
	if rc := h.run("touchid", "status"); rc != 0 || !strings.Contains(h.out.String(), "Touch ID unlock: ON") {
		t.Fatal(h.out.String())
	}
	if _, err := os.Stat(p + oldKeySuffix); err == nil {
		t.Fatal("old file left")
	}
}
