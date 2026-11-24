package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/password"
)

// fakeMaker makes an empty file where a vault would be and remembers what it was given (never printed in a failure message).
type fakeMaker struct {
	made        map[string]string // path -> password
	createErr   error
	touchReady  bool
	bindErr     error
	bound       map[string]string
	bindCalls   int
	createCalls int
}

func (m *fakeMaker) Create(path string, pw []byte) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	if m.made == nil {
		m.made = map[string]string{}
	}
	m.made[path] = string(pw)
	return os.WriteFile(path, []byte("vault"), 0o600)
}
func (m *fakeMaker) TouchIDReady() bool { return m.touchReady }
func (m *fakeMaker) TouchIDBind(path string, pw []byte) error {
	m.bindCalls++
	if m.bindErr != nil {
		return m.bindErr
	}
	if m.bound == nil {
		m.bound = map[string]string{}
	}
	m.bound[path] = string(pw)
	return nil
}

const strongPW = "k7Qm2xVb9RtZ"

type newHarnessT struct {
	t     *testing.T
	dir   string
	app   *App
	maker *fakeMaker
	vault *fakeVaults
	picks []string // what the save dialog answers, in order
	asked []string // the suggested names it was given
	timer func()   // the kit's timer, to fire it by hand
}

func newVaultApp(t *testing.T) *newHarnessT {
	h := &newHarnessT{t: t, dir: t.TempDir(), maker: &fakeMaker{touchReady: true}, vault: &fakeVaults{}}
	h.app = New(Options{Vaults: h.vault, Maker: h.maker,
		PickSave: func(_, name string) (string, error) {
			h.asked = append(h.asked, name)
			if len(h.picks) == 0 {
				return "", nil
			}
			p := h.picks[0]
			h.picks = h.picks[1:]
			return p, nil
		},
		AfterFunc: func(_ time.Duration, f func()) func() { h.timer = f; return func() {} },
		Clock:     func() time.Time { return time.Date(2026, 11, 24, 10, 30, 0, 0, time.UTC) }})
	return h
}

func (h *newHarnessT) place(name string) string {
	h.t.Helper()
	p := filepath.Join(h.dir, name)
	h.picks = append(h.picks, p)
	if r := h.app.NewVaultPlace("t"); r.Status != 200 {
		h.t.Fatalf("place: %+v", r)
	}
	return p
}

func dataOf(r Response) map[string]any {
	m, _ := r.Data.(map[string]any)
	return m
}

func codeOf(r Response) string { c, _ := dataOf(r)[keyCode].(string); return c }

func TestPasswordStrengthAnswers(t *testing.T) {
	a := New(Options{})
	for pw, want := range map[string]struct {
		ok   bool
		code string
	}{"": {false, password.CodeTooShort}, "Qwerty123!": {false, password.CodeTooShort}, "Qwerty123456!asdf": {false, password.CodeWeak}, strongPW: {true, ""}} {
		r := a.PasswordStrength(pw)
		d := dataOf(r)
		if r.Status != 200 || d["ok"] != want.ok || codeOf(r) != want.code {
			t.Errorf("%q: %+v", pw, r)
		}
		if _, leaked := d["password"]; leaked || strings.Contains(toJSON(r), pw) && pw != "" {
			t.Errorf("the answer repeats the password")
		}
	}
	if d := dataOf(a.PasswordStrength("Qwerty123456!asdf")); d["reason"] == "" || d["max_level"] != password.MaxLevel {
		t.Errorf("%+v", d)
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestGeneratePasswordPassesThePolicy(t *testing.T) {
	a := New(Options{})
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		r := a.GeneratePassword()
		p, _ := dataOf(r)[keyPassword].(string)
		if r.Status != 200 || p == "" || seen[p] {
			t.Fatalf("%+v", r)
		}
		seen[p] = true
		if password.Check([]byte(p)) != nil {
			t.Fatal("a generated password was refused by the policy")
		}
	}
}

func TestNewVaultPlace(t *testing.T) {
	h := newVaultApp(t)
	if r := h.app.NewVaultPlace("t"); r.Status != 200 || dataOf(r)["cancelled"] != true {
		t.Fatalf("cancel: %+v", r)
	}
	p := h.place("mine") // the extension is added
	h.app.mu.Lock()
	got := h.app.newPath
	h.app.mu.Unlock()
	if got != p+".kdbx" {
		t.Fatalf("path %q", got)
	}
	if len(h.asked) == 0 || h.asked[0] != "IceVault.kdbx" {
		t.Fatalf("suggested name %v", h.asked)
	}
	// an existing file is never the place
	ex := filepath.Join(h.dir, "taken.kdbx")
	if err := os.WriteFile(ex, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.picks = []string{ex}
	if r := h.app.NewVaultPlace("t"); r.Status != 409 || codeOf(r) != "vault_exists" {
		t.Fatalf("%+v", r)
	}
	h.picks = []string{"relative.kdbx"}
	if r := h.app.NewVaultPlace("t"); r.Status != 400 {
		t.Fatalf("%+v", r)
	}
	// off without a maker, a save dialog or a list
	for _, o := range []Options{{}, {Maker: h.maker}, {Maker: h.maker, Vaults: h.vault}, {PickSave: func(string, string) (string, error) { return "/x", nil }, Maker: h.maker}} {
		if r := New(o).NewVaultPlace("t"); r.Status != 409 || codeOf(r) != "new_unavailable" {
			t.Fatalf("%+v", r)
		}
	}
	if d := dataOf(New(Options{}).ListVaults()); d["can_create"] != false {
		t.Fatalf("%+v", d)
	}
	if d := dataOf(h.app.ListVaults()); d["can_create"] != true {
		t.Fatalf("%+v", d)
	}
	h.picks = []string{"/x"}
	if r := New(Options{Maker: h.maker, Vaults: h.vault, PickSave: func(string, string) (string, error) { return "", errors.New("/secret/path") }}).NewVaultPlace("t"); r.Status != 500 || strings.Contains(toJSON(r), "secret") {
		t.Fatalf("%+v", r)
	}
}

func TestCreateVaultRefusesBeforeAnythingIsWritten(t *testing.T) {
	h := newVaultApp(t)
	if r := h.app.CreateVault(strongPW, strongPW, false); codeOf(r) != "new_no_place" {
		t.Fatalf("no place: %+v", r)
	}
	p := h.place("v") + ".kdbx"
	cases := []struct {
		name, pw, again, code string
	}{
		{"mismatch", strongPW, strongPW + "x", "new_password_mismatch"},
		{"empty", "", "", password.CodeTooShort},
		{"short", "Qwerty123!", "Qwerty123!", password.CodeTooShort},
		{"qwerty long", "Qwerty123456!asdf", "Qwerty123456!asdf", password.CodeWeak},
		{"dictionary phrase", "iloveyouiloveyoutoo", "iloveyouiloveyoutoo", password.CodeWeak},
	}
	for _, c := range cases {
		r := h.app.CreateVault(c.pw, c.again, true)
		if r.Status != 400 || codeOf(r) != c.code {
			t.Errorf("%s: %+v", c.name, r)
		}
		if c.pw != "" && strings.Contains(toJSON(r), c.pw) {
			t.Errorf("%s: the answer repeats the password", c.name)
		}
	}
	if h.maker.createCalls != 0 || h.maker.bindCalls != 0 {
		t.Fatal("something was made after a refusal")
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("a file exists")
	}
	if r := h.app.CreateVault("", "", false); r.Status != 400 { // still has its place: the person can correct and go on
		t.Fatalf("%+v", r)
	}
	if r := h.app.CreateVault(strongPW, strongPW, false); r.Status != 200 {
		t.Fatalf("after the refusals: %+v", r)
	}
}

func TestCreateVaultMakesChoosesAndListsIt(t *testing.T) {
	h := newVaultApp(t)
	p := h.place("v") + ".kdbx"
	r := h.app.CreateVault(strongPW, strongPW, true)
	d := dataOf(r)
	if r.Status != 200 || d["ok"] != true || d["touchid"] != "on" || d["kit"] != true || d["file"] != "v.kdbx" {
		t.Fatalf("%+v", r)
	}
	if h.maker.made[p] != strongPW || h.maker.bound[p] != strongPW {
		t.Fatal("the vault or the binding was not made with the typed password")
	}
	if strings.Contains(toJSON(r), strongPW) || strings.Contains(toJSON(r), p) {
		t.Fatal("the answer holds the password or the path")
	}
	if len(h.vault.opened) != 1 || h.vault.opened[0] != p {
		t.Fatalf("opened %v", h.vault.opened)
	}
	cur, _ := dataOf(h.app.ListVaults())["current"].(VaultInfo)
	if cur.Path != p {
		t.Fatalf("the new vault is not the chosen one: %+v", cur)
	}
	// the place is used once
	if r := h.app.CreateVault(strongPW, strongPW, false); codeOf(r) != "new_no_place" {
		t.Fatalf("%+v", r)
	}
}

func TestCreateVaultTouchIDStates(t *testing.T) {
	for _, c := range []struct {
		name  string
		ready bool
		want  bool
		err   error
		state string
	}{{"not asked", true, false, nil, "off"}, {"asked and bound", true, true, nil, "on"}, {"asked, tools missing", false, true, nil, "unavailable"}, {"asked, binding fails", true, true, errors.New("/p secret"), "failed"}} {
		h := newVaultApp(t)
		h.maker.touchReady, h.maker.bindErr = c.ready, c.err
		h.place("v")
		r := h.app.CreateVault(strongPW, strongPW, c.want)
		// the vault stands whatever happens to the binding
		if r.Status != 200 || dataOf(r)["touchid"] != c.state || strings.Contains(toJSON(r), "secret") {
			t.Errorf("%s: %+v", c.name, r)
		}
		if !c.ready && h.maker.bindCalls != 0 {
			t.Errorf("%s: bound without the tools", c.name)
		}
	}
}

func TestCreateVaultFailureLeaksNothing(t *testing.T) {
	h := newVaultApp(t)
	h.maker.createErr = errors.New("SECRET-LEAK /private/path password=" + strongPW)
	h.place("v")
	r := h.app.CreateVault(strongPW, strongPW, false)
	if r.Status != 500 || codeOf(r) != "new_failed" || strings.Contains(toJSON(r), "SECRET") {
		t.Fatalf("%+v", r)
	}
	if len(h.vault.opened) != 0 {
		t.Fatal("a vault that was not made was listed")
	}
	if r := h.app.SaveRecoveryKit("t", "{password}"); codeOf(r) != "kit_none" {
		t.Fatalf("a kit after a failure: %+v", r)
	}
}

const kitTemplate = "name {name}\npath {path}\ncreated {created}\npassword {password}\nkeep away from the vault file"

func TestRecoveryKit(t *testing.T) {
	h := newVaultApp(t)
	if r := h.app.SaveRecoveryKit("t", kitTemplate); codeOf(r) != "kit_none" {
		t.Fatalf("%+v", r)
	}
	p := h.place("v") + ".kdbx"
	h.app.CreateVault(strongPW, strongPW, false)
	if r := h.app.SaveRecoveryKit("t", "no placeholder for it"); r.Status != 400 {
		t.Fatalf("%+v", r)
	}
	if r := h.app.SaveRecoveryKit("t", kitTemplate); dataOf(r)["cancelled"] != true { // no place: the kit waits
		t.Fatalf("%+v", r)
	}
	if h.asked[len(h.asked)-1] != "v-recovery.txt" {
		t.Fatalf("suggested %v", h.asked)
	}
	// the vault file itself is never the place
	h.picks = []string{p}
	if r := h.app.SaveRecoveryKit("t", kitTemplate); r.Status != 409 || codeOf(r) != "kit_same_file" {
		t.Fatalf("%+v", r)
	}
	other := filepath.Join(t.TempDir(), "kit.txt")
	h.picks = []string{other}
	r := h.app.SaveRecoveryKit("t", kitTemplate)
	if r.Status != 200 || dataOf(r)["same_folder"] != false || strings.Contains(toJSON(r), strongPW) {
		t.Fatalf("%+v", r)
	}
	b, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	want := "name v.kdbx\npath " + p + "\ncreated 2026-11-24 10:30\npassword " + strongPW + "\nkeep away from the vault file"
	if string(b) != want {
		t.Fatalf("the kit text differs (%d bytes)", len(b))
	}
	if st, _ := os.Stat(other); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	// saved once: the password is gone from memory
	if r := h.app.SaveRecoveryKit("t", kitTemplate); codeOf(r) != "kit_none" {
		t.Fatalf("%+v", r)
	}
}

func TestRecoveryKitMarksTheVaultFolderAndKeepsTheModeOfAReplacedFile(t *testing.T) {
	h := newVaultApp(t)
	h.place("v")
	h.app.CreateVault(strongPW, strongPW, false)
	beside := filepath.Join(h.dir, "kit.txt")
	if err := os.WriteFile(beside, []byte("old, world readable"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.picks = []string{beside}
	r := h.app.SaveRecoveryKit("t", kitTemplate)
	if r.Status != 200 || dataOf(r)["same_folder"] != true {
		t.Fatalf("%+v", r)
	}
	if st, _ := os.Stat(beside); st.Mode().Perm() != 0o600 {
		t.Fatalf("a replaced kit file has mode %v", st.Mode())
	}
}

func TestRecoveryKitFailureKeepsItPending(t *testing.T) {
	h := newVaultApp(t)
	h.place("v")
	h.app.CreateVault(strongPW, strongPW, false)
	h.picks = []string{filepath.Join(h.dir, "no", "such", "dir", "kit.txt")}
	if r := h.app.SaveRecoveryKit("t", kitTemplate); r.Status != 500 || codeOf(r) != "kit_not_saved" {
		t.Fatalf("%+v", r)
	}
	good := filepath.Join(t.TempDir(), "kit.txt")
	h.picks = []string{good}
	if r := h.app.SaveRecoveryKit("t", kitTemplate); r.Status != 200 {
		t.Fatalf("retry: %+v", r)
	}
}

func TestRecoveryKitPasswordDoesNotOutliveItsUse(t *testing.T) {
	// dropped by the person
	h := newVaultApp(t)
	h.place("v")
	h.app.CreateVault(strongPW, strongPW, false)
	h.app.mu.Lock()
	kept := h.app.kit.password
	h.app.mu.Unlock()
	h.app.DiscardRecoveryKit()
	if string(kept) == strongPW || h.app.kit != nil {
		t.Fatal("the password stayed after the kit was dropped")
	}
	// by the timer
	h = newVaultApp(t)
	h.place("v")
	h.app.CreateVault(strongPW, strongPW, false)
	h.app.mu.Lock()
	kept = h.app.kit.password
	h.app.mu.Unlock()
	h.timer()
	if string(kept) == strongPW || h.app.kit != nil {
		t.Fatal("the password stayed after the timer")
	}
	// by a lock
	h = newVaultApp(t)
	h.place("v")
	h.app.CreateVault(strongPW, strongPW, false)
	h.app.mu.Lock()
	kept = h.app.kit.password
	h.app.mu.Unlock()
	h.app.Lock()
	if string(kept) == strongPW || h.app.kit != nil {
		t.Fatal("the password stayed after a lock")
	}
}
