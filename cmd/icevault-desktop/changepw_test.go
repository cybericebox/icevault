//go:build desktop

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/pkg/vault"
)

const changedPW = "Zq4#nW8@pRb3yHk7"

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// fakeAge stands in for age and age-plugin-se: it writes the files a real binding would and never touches a sensor.
type fakeAge struct{}

func (fakeAge) Has(string) bool { return true }
func (fakeAge) Run(name string, args []string, _ []byte, _ time.Duration) ([]byte, int, error) {
	switch {
	case name == "age-plugin-se" && args[0] == "keygen":
		return nil, 0, os.WriteFile(args[len(args)-1], []byte("identity"), 0o600)
	case name == "age-plugin-se" && args[0] == "recipients":
		return []byte("age1se1fake\n"), 0, nil
	case name == "age" && args[0] == "-r":
		return nil, 0, os.WriteFile(args[len(args)-1], []byte("ciphertext"), 0o600)
	}
	return nil, 1, errors.New("unexpected call")
}

func opensAt(p, pass string) bool {
	v, err := vault.Open(p, vault.Credentials{Password: []byte(pass)})
	if err == nil {
		v.Close()
	}
	return err == nil
}

// The whole way through the window's App on the real unlocker and core: the typed current password is checked, the policy decides first, the file is
// re-encrypted in place, the Touch ID binding of the old password is removed, the info file gets the date, the copies that still open with the old
// password are named, and the window stays unlocked and reads its own save as no change.
func TestChangePasswordThroughTheApp(t *testing.T) {
	p := makeVault(t, "")
	tid, copyDir := t.TempDir(), t.TempDir()
	env, _ := testEnv(t, map[string]string{"ICEVAULT_TOUCHID_DIR": tid, "ICEVAULT_VAULT": p})
	env.Out, env.Err, env.Exec, env.TouchID = io.Discard, io.Discard, fakeAge{}, true
	env.Ask = func(string) ([]byte, error) { return []byte(testPW), nil }
	if rc := cli.Run([]string{"touchid", "enable"}, env); rc != 0 {
		t.Fatalf("touchid enable rc=%d", rc)
	}
	if rc := cli.Run([]string{"copies", "add", copyDir}, env); rc != 0 { // makes the copy at once
		t.Fatalf("copies add rc=%d", rc)
	}
	if ents, _ := os.ReadDir(tid); len(ents) != 2 {
		t.Fatalf("the binding was not made: %d files", len(ents))
	}
	env.Ask = func(string) ([]byte, error) { return nil, errors.New("the window asks for the password itself") }
	oldCopy, _ := os.ReadFile(filepath.Join(copyDir, filepath.Base(p)))
	u := &vaultUnlocker{env: env, path: p, plat: testProject(t)}
	app := desktop.New(desktop.Options{Unlocker: u, SyncEvery: -1, AfterFunc: func(_ time.Duration, f func()) func() { return func() {} }})
	if r := app.Unlock("password", testPW); r.Status != 200 {
		t.Fatalf("unlock %d", r.Status)
	}
	if r := app.ChangePasswordInfo(); r.Status != 200 || r.Data.(map[string]any)["available"] != true || r.Data.(map[string]any)["destinations"] != 1 || r.Data.(map[string]any)["touchid_on"] != true {
		t.Fatalf("info: %+v", r)
	}
	before, _ := os.ReadFile(p)
	// a wrong current password, a weak new one: the file is as it was
	if r := app.ChangePassword("not-it", changedPW, changedPW, false, false); r.Status != 401 {
		t.Fatalf("wrong current: %+v", r)
	}
	if r := app.ChangePassword(testPW, "Qwerty123!", "Qwerty123!", false, false); r.Status != 400 {
		t.Fatalf("weak: %+v", r)
	}
	if now, _ := os.ReadFile(p); !bytes.Equal(now, before) {
		t.Fatal("the vault changed after a refusal")
	}
	r := app.ChangePassword(testPW, changedPW, changedPW, false, false)
	d, _ := r.Data.(map[string]any)
	if r.Status != 200 || d["was_touchid"] != true || d["touchid"] != "off" {
		t.Fatalf("change: %+v", r)
	}
	if strings.Contains(toJSON(r), changedPW) || strings.Contains(toJSON(r), testPW) {
		t.Fatal("the answer holds a password")
	}
	if opensAt(p, testPW) || !opensAt(p, changedPW) {
		t.Fatal("the file is not under the new password")
	}
	if ents, _ := os.ReadDir(tid); len(ents) != 0 {
		t.Fatalf("%d Touch ID files are left", len(ents))
	}
	if inf, _ := os.ReadFile(p + ".info.json"); !bytes.Contains(inf, []byte("password_changed")) || bytes.Contains(inf, []byte(changedPW)) {
		t.Fatalf("info file: %s", inf)
	}
	stale, _ := d["stale"].([]string)
	if len(stale) != 1 || stale[0] != filepath.Join(copyDir, filepath.Base(p)) {
		t.Fatalf("stale: %v", d["stale"])
	}
	if now, _ := os.ReadFile(filepath.Join(copyDir, filepath.Base(p))); !bytes.Equal(now, oldCopy) {
		t.Fatal("the copy was changed or deleted")
	}
	// still unlocked, still the same vault, and no change noticed
	if r := app.Refresh(); r.Status != 200 || r.Data.(map[string]any)["changed"] != false {
		t.Fatalf("the window saw its own save as a change: %+v", r)
	}
	// and a later write in the window saves with the new key
	if r := app.SetMode("edit"); r.Status != 200 {
		t.Fatal("edit")
	}
	if r := app.Write("m-other", map[string]any{"action": "create", "title": "AFTER", "value": "a"}); r.Status != 200 {
		t.Fatalf("a write after the change: %d %v", r.Status, r.Data)
	}
	if !opensAt(p, changedPW) {
		t.Fatal("the new password no longer opens the vault after a write")
	}
	app.Lock()
}
