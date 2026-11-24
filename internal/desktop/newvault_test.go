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
	noProject   map[string]bool   // path -> made without a project
	createErr   error
	touchReady  bool
	bindErr     error
	bound       map[string]string
	bindCalls   int
	createCalls int
}

func (m *fakeMaker) Create(path string, pw []byte, noProject bool) error {
	m.createCalls++
	if m.noProject == nil {
		m.noProject = map[string]bool{}
	}
	m.noProject[path] = noProject
	if m.createErr != nil {
		return m.createErr
	}
	if m.made == nil {
		m.made = map[string]string{}
	}
	m.made[path] = string(pw)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
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
	t         *testing.T
	dir       string
	app       *App
	maker     *fakeMaker
	vault     *fakeVaults
	picks     []string // what the save dialog answers, in order
	asked     []string // the suggested names it was given
	timer     func()   // the kit's timer, to fire it by hand
	root      string   // the project folder the folder dialog answers
	dirs      []string // the folders the save dialog was asked to open in
	projected bool
}

func newVaultApp(t *testing.T) *newHarnessT {
	h := &newHarnessT{t: t, dir: t.TempDir(), root: t.TempDir(), maker: &fakeMaker{touchReady: true}, vault: &fakeVaults{}}
	h.app = New(Options{Vaults: h.vault, Maker: h.maker,
		Pick: func(kind, _ string) (string, error) { return h.root, nil },
		PickSave: func(_, dir, name string) (string, error) {
			h.dirs = append(h.dirs, dir)
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

// project chooses the project folder (the first step); the file the description names becomes the place.
func (h *newHarnessT) project() Response {
	h.t.Helper()
	r := h.app.NewVaultProject("t")
	if r.Status != 200 {
		h.t.Fatalf("project: %+v", r)
	}
	h.projected = true
	return r
}

// place chooses another place with the save dialog (after the project folder).
func (h *newHarnessT) place(name string) string {
	h.t.Helper()
	if !h.projected {
		h.project()
	}
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
	// the project folder comes first
	if r := h.app.NewVaultPlace("t"); r.Status != 409 || codeOf(r) != "new_no_project" {
		t.Fatalf("a place before the project: %+v", r)
	}
	h.project()
	if r := h.app.NewVaultPlace("t"); r.Status != 200 || dataOf(r)["cancelled"] != true {
		t.Fatalf("cancel: %+v", r)
	}
	// the dialog opens at the folder of the description (the nearest one that exists) with the file name it names
	if want := filepath.Join(h.root, "plain", "vault", "v.kdbx"); h.asked[0] != filepath.Base(want) || h.dirs[0] != h.root {
		t.Fatalf("dialog: dir %q name %q (the folder of the description is not made yet: its nearest existing parent)", h.dirs[0], h.asked[0])
	}
	p := h.place("mine") // the extension is added
	h.app.mu.Lock()
	got := h.app.newPath
	h.app.mu.Unlock()
	if got != p+".kdbx" {
		t.Fatalf("path %q", got)
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
	for _, o := range []Options{{}, {Maker: h.maker}, {Maker: h.maker, Vaults: h.vault}, {PickSave: func(string, string, string) (string, error) { return "/x", nil }, Maker: h.maker}} {
		if r := New(o).NewVaultPlace("t"); r.Status != 409 || codeOf(r) != "new_unavailable" {
			t.Fatalf("%+v", r)
		}
		if r := New(o).NewVaultProject("t"); r.Status != 409 || codeOf(r) != "new_unavailable" {
			t.Fatalf("%+v", r)
		}
	}
	if d := dataOf(New(Options{}).ListVaults()); d["can_create"] != false {
		t.Fatalf("%+v", d)
	}
	if d := dataOf(h.app.ListVaults()); d["can_create"] != true {
		t.Fatalf("%+v", d)
	}
	if r := New(Options{Maker: h.maker, Vaults: h.vault, PickSave: func(string, string, string) (string, error) { return "", errors.New("/secret/path") }, Pick: h.app.o.Pick}).NewVaultPlace("t"); r.Status != 409 {
		t.Fatalf("no project yet: %+v", r)
	}
}

// The project folder first: the vault file of its description is the place at once, and the vault is recorded with that folder, saved there or elsewhere.
func TestNewVaultProjectFirst(t *testing.T) {
	h := newVaultApp(t)
	if r := h.app.CreateVault(strongPW, strongPW, false); codeOf(r) != "new_no_project" {
		t.Fatalf("create with no project: %+v", r)
	}
	r := h.project()
	d := dataOf(r)
	if d["file"] != "v.kdbx" || d["exists"] != false || d["folder"] == "" {
		t.Fatalf("%+v", d)
	}
	def := filepath.Join(h.root, "plain", "vault", "v.kdbx") // the folder of the description does not exist yet
	// created at the default place with no save dialog at all: the parent folders are made by the maker
	if r := h.app.CreateVault(strongPW, strongPW, false); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(def); err != nil {
		t.Fatal("the vault is not at the place the description names")
	}
	if len(h.asked) != 0 {
		t.Fatalf("the save dialog was shown: %v", h.asked)
	}
	if h.vault.roots[def] != h.root {
		t.Fatalf("the checkout of the new vault is %q, want %q", h.vault.roots[def], h.root)
	}
	// saved elsewhere: still recorded with the chosen project folder
	h2 := newVaultApp(t)
	elsewhere := h2.place("elsewhere") + ".kdbx"
	if r := h2.app.CreateVault(strongPW, strongPW, false); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	if h2.vault.roots[elsewhere] != h2.root {
		t.Fatalf("saved elsewhere: the checkout is %q, want %q", h2.vault.roots[elsewhere], h2.root)
	}
	// the file of the description is there already: no place is set, the person chooses another
	h3 := newVaultApp(t)
	def3 := filepath.Join(h3.root, "plain", "vault", "v.kdbx")
	if err := os.MkdirAll(filepath.Dir(def3), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(def3, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := dataOf(h3.project()); d["exists"] != true {
		t.Fatalf("%+v", d)
	}
	if r := h3.app.CreateVault(strongPW, strongPW, false); codeOf(r) != "new_no_place" {
		t.Fatalf("%+v", r)
	}
	if h3.dirs != nil {
		t.Fatal("a dialog was shown")
	}
	h3.place("other")
	if h3.dirs[0] != filepath.Dir(def3) {
		t.Fatalf("the dialog opens at %q", h3.dirs[0])
	}
	if r := h3.app.CreateVault(strongPW, strongPW, false); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
}

func TestNewVaultProjectRefusals(t *testing.T) {
	h := newVaultApp(t)
	h.vault.defaultErr = &Error{Status: 409, Code: "vault_bad_root"}
	if r := h.app.NewVaultProject("t"); r.Status != 409 || codeOf(r) != "vault_bad_root" {
		t.Fatalf("%+v", r)
	}
	if r := h.app.NewVaultPlace("t"); codeOf(r) != "new_no_project" {
		t.Fatalf("a refused folder left a project: %+v", r)
	}
	// a cancelled folder dialog, a failing one, a relative answer
	for _, c := range []struct {
		pick func(string, string) (string, error)
		want int
	}{{func(string, string) (string, error) { return "", nil }, 200}, {func(string, string) (string, error) { return "", errors.New("/secret") }, 500}, {func(string, string) (string, error) { return "rel", nil }, 400}} {
		a := New(Options{Vaults: &fakeVaults{}, Maker: h.maker, Pick: c.pick, PickSave: func(string, string, string) (string, error) { return "", nil }})
		if r := a.NewVaultProject("t"); r.Status != c.want || strings.Contains(toJSON(r), "secret") {
			t.Fatalf("%+v want %d", r, c.want)
		}
	}
	if r := New(Options{Vaults: &fakeVaults{}, Maker: h.maker, PickSave: func(string, string, string) (string, error) { return "", nil }}).NewVaultProject("t"); codeOf(r) != "pick_unavailable" {
		t.Fatalf("%+v", r)
	}
}

func TestCreateVaultRefusesBeforeAnythingIsWritten(t *testing.T) {
	h := newVaultApp(t)
	if r := h.app.CreateVault(strongPW, strongPW, false); codeOf(r) != "new_no_project" {
		t.Fatalf("no project: %+v", r)
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

func TestCreateVaultMakesAndChoosesIt(t *testing.T) {
	h := newVaultApp(t)
	p := h.place("v") + ".kdbx"
	r := h.app.CreateVault(strongPW, strongPW, true)
	d := dataOf(r)
	if r.Status != 200 || d["ok"] != true || d["touchid"] != "on" || d["kit"] != true || d["file"] != "v.kdbx" {
		t.Fatalf("%+v", r)
	}
	if held := dataOf(h.app.KitHeld())["held"]; held != true {
		t.Fatalf("the kit is not held after the vault was made: %v", held)
	}
	h.app.DiscardRecoveryKit()
	if held := dataOf(h.app.KitHeld())["held"]; held != false {
		t.Fatalf("the kit is still held after it was discarded: %v", held)
	}
	if h.maker.made[p] != strongPW || h.maker.bound[p] != strongPW {
		t.Fatal("the vault or the binding was not made with the typed password")
	}
	if strings.Contains(toJSON(r), strongPW) || strings.Contains(toJSON(r), p) {
		t.Fatal("the answer holds the password or the path")
	}
	if len(h.vault.opened) != 0 {
		t.Fatalf("a vault never unlocked was recorded as opened: %v", h.vault.opened)
	}
	if len(h.vault.added) != 1 || h.vault.added[0] != p {
		t.Fatalf("the new vault is not in the recent list at once: %v", h.vault.added)
	}
	cur, _ := dataOf(h.app.ListVaults())["current"].(VaultInfo)
	if cur.Path != p {
		t.Fatalf("the new vault is not the chosen one: %+v", cur)
	}
	// the project and the place are used once
	if r := h.app.CreateVault(strongPW, strongPW, false); codeOf(r) != "new_no_project" {
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
	if len(h.vault.opened) != 0 || len(h.vault.added) != 0 {
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

func TestWriteKitIsPrivateBeforeTheFirstByte(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kit.txt")
	if err := os.WriteFile(p, []byte("old, world readable"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	seen := false
	err := writeKitWith(p, []byte("the secret"), func(f *os.File) {
		seen = true
		st, serr := f.Stat()
		if serr != nil || st.Mode().Perm() != 0o600 || st.Size() != 0 {
			t.Errorf("before the first write: mode %v size %d (the old content or the old mode is still there)", st.Mode().Perm(), st.Size())
		}
	})
	if err != nil || !seen {
		t.Fatalf("%v %v", err, seen)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if b, _ := os.ReadFile(p); string(b) != "the secret" {
		t.Fatalf("%d bytes", len(b))
	}
}

func TestWriteKitRefusesASymlinkAndLeavesItsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "kit.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("no symbolic links here")
	}
	if err := writeKit(link, []byte("secret")); err == nil {
		t.Fatal("a symbolic link was written through")
	}
	if b, _ := os.ReadFile(target); string(b) != "untouched" {
		t.Fatal("the target of the link changed")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatal("the link itself was removed")
	}
}

func TestWriteKitFailureLeavesNoPartialFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kit.txt")
	err := writeKitWith(p, []byte("secret"), func(f *os.File) { _ = f.Close() }) // the write after it fails
	if err == nil {
		t.Fatal("no error")
	}
	if _, serr := os.Lstat(p); serr == nil {
		t.Fatal("a partial kit file stays")
	}
}

func TestWriteKitWipesItsInput(t *testing.T) {
	b := []byte("secret")
	if err := writeKit(filepath.Join(t.TempDir(), "k"), b); err != nil {
		t.Fatal(err)
	}
	if string(b) == "secret" {
		t.Fatal("the body stayed in memory")
	}
}

func TestExpandKitAllocatesOnce(t *testing.T) {
	vals := map[string][]byte{"name": []byte("v.kdbx"), "path": []byte("/a/b/v.kdbx"), "created": []byte("2026-11-24 10:30"), "password": []byte("correct-horse-battery")}
	for _, tpl := range []string{"{password}", "x{name}y{path}z{created}w{password}\nkeep it away", "no placeholders", "", "{", "{unknown}{password}{", "{{password}}"} {
		got := expandKit(tpl, vals)
		if cap(got) != len(got) {
			t.Errorf("%q: cap %d, len %d: the buffer was larger than the text, or it grew", tpl, cap(got), len(got))
		}
	}
	if got := expandKit("a{password}b", vals); string(got) != "acorrect-horse-batteryb" {
		t.Fatalf("%q", got)
	}
}

func TestExpandKitIsOnePass(t *testing.T) {
	got := expandKit("a {name} b {password} c {unknown} {", map[string][]byte{"name": []byte("{password}"), "password": []byte("PW")})
	if string(got) != "a {password} b PW c {unknown} {" {
		t.Fatalf("%q", got)
	}
}

func TestPasswordTooLongAndAMeterThatDoesNotQueue(t *testing.T) {
	a := New(Options{})
	huge := strings.Repeat("aB3$xQ9!", 1250)
	start := time.Now()
	r := a.PasswordStrength(huge)
	if time.Since(start) > time.Second || codeOf(r) != password.CodeTooLong || dataOf(r)["max"] != password.MaxLength {
		t.Fatalf("%+v after %v", r, time.Since(start))
	}
	h := newVaultApp(t)
	h.place("v")
	if r := h.app.CreateVault(huge, huge, false); r.Status != 400 || codeOf(r) != password.CodeTooLong || h.maker.createCalls != 0 {
		t.Fatalf("%+v", r)
	}
}

// Without a project: no folder, no description; the place is chosen with the save dialog, the vault is made as one without a project and no checkout is
// recorded for it.
func TestNewVaultWithoutAProject(t *testing.T) {
	h := newVaultApp(t)
	if r := h.app.NewVaultPlace("t"); codeOf(r) != "new_no_project" {
		t.Fatalf("a place before any choice: %+v", r)
	}
	if r := h.app.NewVaultNoProject(); r.Status != 200 || dataOf(r)["touchid"] != true {
		t.Fatalf("%+v", r)
	}
	h.projected = true // no project step for the helper
	if r := h.app.CreateVault(strongPW, strongPW, false); codeOf(r) != "new_no_place" {
		t.Fatalf("no place yet: %+v", r)
	}
	p := h.place("loose") + ".kdbx"
	if h.asked[len(h.asked)-1] != "IceVault.kdbx" || h.dirs[len(h.dirs)-1] != "" {
		t.Fatalf("the dialog: dir %q name %q", h.dirs, h.asked)
	}
	if r := h.app.CreateVault(strongPW, strongPW, false); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	if !h.maker.noProject[p] {
		t.Fatal("the vault was not made as one without a project")
	}
	if len(h.vault.roots) != 0 {
		t.Fatalf("a checkout was recorded for a vault without a project: %v", h.vault.roots)
	}
	// the choice is used once
	if r := h.app.CreateVault(strongPW, strongPW, false); codeOf(r) != "new_no_project" {
		t.Fatalf("%+v", r)
	}
}

func TestChoosingProjectAndNoProjectReplaceEachOther(t *testing.T) {
	h := newVaultApp(t)
	h.project()
	h.app.NewVaultNoProject()
	h.app.mu.Lock()
	root, path := h.app.newRoot, h.app.newPath
	h.app.mu.Unlock()
	if root != "" || path != "" {
		t.Fatalf("the project choice stayed: %q %q", root, path)
	}
	h.project()
	if r := h.app.CreateVault(strongPW, strongPW, false); r.Status != 200 || h.maker.noProject[filepath.Join(h.root, "plain", "vault", "v.kdbx")] {
		t.Fatalf("a project chosen after \"without\" made a vault without a project: %+v", r)
	}
}

func TestUseWithoutAProject(t *testing.T) {
	fv := &fakeVaults{needRoot: map[string]bool{"/v/loose.kdbx": true}}
	a := New(Options{Vaults: fv, Vault: "/v/loose.kdbx"})
	if p, _ := dataOf(a.ListVaults())["problem"].(map[string]any); p == nil || p["code"] != "vault_needs_root" {
		t.Fatalf("%+v", dataOf(a.ListVaults())["problem"])
	}
	if r := a.UseWithoutProject(); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	if !fv.noProject["/v/loose.kdbx"] {
		t.Fatal("the vault was not marked")
	}
	if dataOf(a.ListVaults())["problem"] != nil {
		t.Fatal("the lock screen still has a problem")
	}
	if r := a.Unlock("password", "pw"); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	// it acts only on the question about a checkout: in any other state nothing is marked
	for name, e := range map[string]error{"another problem": &Error{Status: 409, Code: "setup_no_model"}, "no problem": nil} {
		other := &fakeVaults{needRoot: map[string]bool{}, prepareErr: e}
		o := New(Options{Vaults: other, Vault: "/v/other.kdbx"})
		if r := o.UseWithoutProject(); r.Status != 409 || codeOf(r) != "no_project_refused" || len(other.noProject) != 0 {
			t.Fatalf("%s: %+v marked %v", name, r, other.noProject)
		}
	}
	// refusals: no list, no vault chosen, a failing mark
	if r := New(Options{}).UseWithoutProject(); codeOf(r) != "vaults_off" {
		t.Fatalf("%+v", r)
	}
	if r := New(Options{Vaults: &fakeVaults{}}).UseWithoutProject(); codeOf(r) != "no_vault_chosen" {
		t.Fatalf("%+v", r)
	}
	bad := New(Options{Vaults: &fakeVaults{needRoot: map[string]bool{"/v/x.kdbx": true}, noProjectErr: errors.New("/secret/path")}, Vault: "/v/x.kdbx"})
	if r := bad.UseWithoutProject(); r.Status < 400 || codeOf(r) == "" || strings.Contains(toJSON(r), "secret") {
		t.Fatalf("%+v", r)
	}
}
