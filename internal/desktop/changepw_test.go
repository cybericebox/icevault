package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/pkg/vault"
)

const (
	oldPW = "Tj7#kQ2!vLxR9mZb"
	newPW = "Zq4#nW8@pRb3yHk7"
)

// changeCore is a Core that can change its password, the way modelCore does: the typed current password must be the vault's, and the outcome is
// whatever the test set.
type changeCore struct {
	*MemoryCore
	pw      string
	info    ChangeInfo
	outcome ChangeOutcome
	err     error
	calls   int
	refresh bool
	got     string
}

func (c *changeCore) PasswordInfo() ChangeInfo { return c.info }

func (c *changeCore) ChangePassword(cur, next []byte, refresh bool) (ChangeOutcome, error) {
	c.calls++
	if string(cur) != c.pw {
		return ChangeOutcome{}, ErrWrongPassword
	}
	if c.err != nil {
		return ChangeOutcome{}, c.err
	}
	c.pw, c.got, c.refresh = string(next), string(next), refresh
	return c.outcome, nil
}

type changeUnlocker struct{ core *changeCore }

func (u changeUnlocker) Open(p []byte) (Core, error) {
	if string(p) != u.core.pw {
		return nil, ErrWrongPassword
	}
	return u.core, nil
}
func (u changeUnlocker) Touch() ([]byte, error) { return nil, nil }
func (u changeUnlocker) HasKeyFile() bool       { return false }

type changeHarness struct {
	t     *testing.T
	app   *App
	core  *changeCore
	maker *fakeMaker
	vault string
	slept []time.Duration
	saved []string
	picks []string
}

func newChangeApp(t *testing.T) *changeHarness {
	h := &changeHarness{t: t, maker: &fakeMaker{touchReady: true}}
	h.core = &changeCore{MemoryCore: &MemoryCore{}, pw: oldPW}
	h.vault = filepath.Join(t.TempDir(), "v.kdbx")
	fv := &fakeVaults{unlockers: map[string]Unlocker{h.vault: changeUnlocker{h.core}}}
	h.app = New(Options{Vaults: fv, Maker: h.maker, Vault: h.vault,
		Sleep: func(d time.Duration) { h.slept = append(h.slept, d) },
		PickSave: func(_, _, name string) (string, error) {
			h.saved = append(h.saved, name)
			if len(h.picks) == 0 {
				return "", nil
			}
			p := h.picks[0]
			h.picks = h.picks[1:]
			return p, nil
		},
		AfterFunc: func(time.Duration, func()) func() { return func() {} }})
	if r := h.app.Unlock("password", oldPW); r.Status != 200 {
		t.Fatalf("unlock: %+v", r)
	}
	return h
}

func TestChangePasswordInfo(t *testing.T) {
	h := newChangeApp(t)
	h.core.info = ChangeInfo{Destinations: 2, TouchIDOn: true}
	r := h.app.ChangePasswordInfo()
	d := dataOf(r)
	if r.Status != 200 || d["available"] != true || d["destinations"] != 2 || d["touchid_on"] != true || d["touchid_ready"] != true {
		t.Fatalf("%+v", r)
	}
	// locked
	h.app.lock()
	if r := h.app.ChangePasswordInfo(); r.Status != 423 {
		t.Fatalf("locked: %+v", r)
	}
	// a core that cannot change a password (the demo)
	a := New(Options{Unlocker: &MemoryUnlocker{Password: "pw"}})
	a.Unlock("password", "pw")
	if r := a.ChangePasswordInfo(); r.Status != 200 || dataOf(r)["available"] != false {
		t.Fatalf("demo: %+v", r)
	}
	if r := a.ChangePassword("pw", newPW, newPW, false, false); r.Status != 409 || codeOf(r) != "change_unavailable" {
		t.Fatalf("demo change: %+v", r)
	}
}

func TestChangePasswordRefusesBeforeTheCoreIsAsked(t *testing.T) {
	cases := []struct {
		name, cur, pw, again, code string
	}{
		{"no current password", "", newPW, newPW, "type_password"},
		{"mismatch", oldPW, newPW, newPW + "x", "new_password_mismatch"},
		{"empty", oldPW, "", "", "password_too_short"},
		{"short", oldPW, "Qwerty123!", "Qwerty123!", "password_too_short"},
		{"dictionary phrase", oldPW, "iloveyouiloveyoutoo", "iloveyouiloveyoutoo", "password_weak"},
		{"the same", oldPW, oldPW, oldPW, "change_same_password"},
	}
	for _, c := range cases {
		h := newChangeApp(t)
		r := h.app.ChangePassword(c.cur, c.pw, c.again, true, true)
		if r.Status != 400 || codeOf(r) != c.code {
			t.Errorf("%s: %+v", c.name, r)
		}
		if h.core.calls != 0 || h.maker.bindCalls != 0 {
			t.Errorf("%s: something was done after a refusal", c.name)
		}
		for _, s := range []string{c.cur, c.pw} {
			if s != "" && strings.Contains(toJSON(r), s) {
				t.Errorf("%s: the answer repeats a password", c.name)
			}
		}
		if h.app.kit != nil {
			t.Errorf("%s: a kit is pending", c.name)
		}
	}
}

func TestChangePasswordWrongCurrentPasswordIsDelayedAndLocksAfterFive(t *testing.T) {
	h := newChangeApp(t)
	for i := 1; i < MaxWrong; i++ {
		r := h.app.ChangePassword("not-the-password", newPW, newPW, false, false)
		d := dataOf(r)
		if r.Status != 401 || codeOf(r) != "change_wrong_password" || d["left"] != MaxWrong-i {
			t.Fatalf("%d: %+v", i, r)
		}
	}
	if len(h.slept) != MaxWrong-1 || h.slept[0] != WrongDelay {
		t.Fatalf("the wrong ones were not delayed: %v", h.slept)
	}
	if h.core.got != "" {
		t.Fatal("the password changed")
	}
	r := h.app.ChangePassword("not-the-password", newPW, newPW, false, false)
	if r.Status != 423 || codeOf(r) != "locked" {
		t.Fatalf("the fifth: %+v", r)
	}
	if _, e := h.app.store(); e == nil {
		t.Fatal("the vault is still unlocked")
	}
	if !h.core.Locked {
		t.Fatal("the core was not locked")
	}
}

func TestChangePasswordSuccessAndTouchIDAndKit(t *testing.T) {
	h := newChangeApp(t)
	h.core.outcome = ChangeOutcome{TouchIDWasOn: true, Refreshed: []string{"/b/standing"}, Stale: []string{"/b/once/v.kdbx"}}
	// the binding of the old password is on: the lock screen offers Touch ID until the change removes it
	h.app.mu.Lock()
	h.app.cur.Binding, h.app.cur.Confirm = true, func(string) bool { return true }
	h.app.mu.Unlock()
	r := h.app.ChangePassword(oldPW, newPW, newPW, true, true)
	d := dataOf(r)
	if r.Status != 200 || d["ok"] != true || d["touchid"] != "on" || d["was_touchid"] != true || d["kit"] != true || d["file"] != "v.kdbx" {
		t.Fatalf("%+v", r)
	}
	if h.core.got != newPW || !h.core.refresh {
		t.Fatal("the core did not get the new password and the refresh choice")
	}
	if h.maker.bound[h.vault] != newPW {
		t.Fatal("Touch ID was not bound to the new password")
	}
	if strings.Contains(toJSON(r), newPW) || strings.Contains(toJSON(r), oldPW) || strings.Contains(toJSON(r), h.vault) {
		t.Fatal("the answer holds a password or the path")
	}
	if stale, _ := d["stale"].([]string); len(stale) != 1 || stale[0] != "/b/once/v.kdbx" {
		t.Fatalf("stale: %+v", d["stale"])
	}
	// the window stays unlocked, with the new password in force
	if _, e := h.app.store(); e != nil {
		t.Fatal("the window was locked")
	}
	// the kit is made from the NEW password and the vault's name
	out := filepath.Join(t.TempDir(), "kit.txt")
	h.picks = []string{out}
	if r := h.app.SaveRecoveryKit("t", "{name}|{password}"); r.Status != 200 {
		t.Fatalf("kit: %+v", r)
	}
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "v.kdbx|"+newPW {
		t.Fatalf("kit text: %q %v", b, err)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("kit mode %v", st.Mode())
	}
}

// The binding of the old password is gone when the person does not turn Touch ID on again: the lock screen does not offer it any more.
func TestChangePasswordWithoutRebindingDropsTheBindingOfTheLockScreen(t *testing.T) {
	h := newChangeApp(t)
	h.core.outcome = ChangeOutcome{TouchIDWasOn: true}
	h.app.mu.Lock()
	h.app.cur.Binding, h.app.cur.Confirm = true, func(string) bool { return true }
	h.app.mu.Unlock()
	r := h.app.ChangePassword(oldPW, newPW, newPW, false, false)
	if r.Status != 200 || dataOf(r)["touchid"] != "off" || h.maker.bindCalls != 0 {
		t.Fatalf("%+v", r)
	}
	tg := h.app.target()
	if tg.Binding || tg.Confirm != nil {
		t.Fatal("the lock screen still offers a Touch ID that no longer opens the vault")
	}
}

func TestChangePasswordTouchIDStates(t *testing.T) {
	for _, c := range []struct {
		name  string
		ready bool
		err   error
		state string
	}{{"tools missing", false, nil, "unavailable"}, {"binding fails", true, errors.New("/p secret"), "failed"}} {
		h := newChangeApp(t)
		h.maker.touchReady, h.maker.bindErr = c.ready, c.err
		r := h.app.ChangePassword(oldPW, newPW, newPW, true, false)
		if r.Status != 200 || dataOf(r)["touchid"] != c.state || strings.Contains(toJSON(r), "secret") {
			t.Errorf("%s: %+v", c.name, r)
		}
		if h.core.got != newPW {
			t.Errorf("%s: the change did not stand", c.name)
		}
	}
}

func TestChangePasswordCoreFailureAddsNothing(t *testing.T) {
	h := newChangeApp(t)
	h.core.err = vault.ErrChangedOnDisk
	r := h.app.ChangePassword(oldPW, newPW, newPW, true, true)
	if r.Status != 409 || codeOf(r) != CodeChangedOnDisk {
		t.Fatalf("%+v", r)
	}
	if h.maker.bindCalls != 0 || h.app.kit != nil {
		t.Fatal("a binding or a kit followed a failed change")
	}
	h.core.err = errors.New("/secret/path: boom")
	if r := h.app.ChangePassword(oldPW, newPW, newPW, false, false); strings.Contains(toJSON(r), "secret") {
		t.Fatalf("the text of the error reached the page: %+v", r)
	}
}
