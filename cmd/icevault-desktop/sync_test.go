//go:build desktop

package main

import (
	"os"
	"testing"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// The window and another writer on one throwaway vault: the window's own saves are not a change, a save by the other writer is noticed and read again
// with the key of the unlock (no password), and a write after it lands on the other writer's file instead of failing.
func TestWindowReadsWhatAnotherWriterSaved(t *testing.T) {
	p := makeVault(t, "")
	u := &vaultUnlocker{env: cli.NewWindowEnv(), path: p, plat: testProject(t)}
	var events int
	app := desktop.New(desktop.Options{Unlocker: u, SyncEvery: -1, Notify: func(string, any) { events++ }})
	if r := app.Unlock("password", testPW); r.Status != 200 {
		t.Fatalf("unlock %d", r.Status)
	}
	if r := app.SetMode("edit"); r.Status != 200 {
		t.Fatalf("edit %d", r.Status)
	}
	if r := app.Write("m-other", map[string]any{"action": "create", "title": "MINE", "value": "m"}); r.Status != 200 {
		t.Fatalf("own write %d %v", r.Status, r.Data)
	}
	if r := app.Refresh(); r.Status != 200 || r.Data.(map[string]any)["changed"] != false || events != 0 {
		t.Fatalf("the window's own save counted as a change: %v (events %d)", r.Data, events)
	}

	other, err := vault.Open(p, vault.Credentials{Password: []byte(testPW)})
	if err != nil {
		t.Fatal(err)
	}
	addOther(t, other, "THEIRS", "their-value")

	if r := app.Refresh(); r.Status != 200 || r.Data.(map[string]any)["changed"] != true || events != 1 {
		t.Fatalf("the other writer's save was not read: %v (events %d)", r.Data, events)
	}
	if r := app.Refresh(); r.Data.(map[string]any)["changed"] != false || events != 1 {
		t.Fatalf("read twice: %v", r.Data)
	}
	if r := app.Reveal(map[string]any{"section": "m", "name": "other/" + otherUUID(t, p, "THEIRS"), "group": "", "key": ""}); r.Status != 200 || r.Data.(map[string]any)["value"] != "their-value" {
		t.Fatalf("the reloaded window does not see the other writer's entry: %d", r.Status)
	}

	// the other writer saves again; the window writes before its next check: the write reads the file first and lands on it
	addOther(t, other, "SECOND", "v2")
	other.Close()
	if r := app.Write("m-other", map[string]any{"action": "create", "title": "AFTER", "value": "a"}); r.Status != 200 {
		t.Fatalf("a write after another writer's save: %d %v", r.Status, r.Data)
	}
	if events != 2 {
		t.Fatalf("events %d", events)
	}
	for _, k := range []string{"MINE", "THEIRS", "SECOND", "AFTER"} {
		if otherUUID(t, p, k) == "" {
			t.Errorf("%s is not on disk", k)
		}
	}
	app.Lock()
}

// addOther is another writer: it adds an entry of Other secrets to the model and saves.
func addOther(t *testing.T, v *vault.Vault, title, value string) {
	t.Helper()
	m, err := vmodel.Load(v)
	if err != nil {
		t.Fatal(err)
	}
	m.Other = append(m.Other, &vmodel.Other{Title: title, Value: value})
	if err := vmodel.Sync(v, m); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
}

// otherUUID is the UUID of the Other entry with that title in the file ("" when none).
func otherUUID(t *testing.T, path, title string) string {
	t.Helper()
	v, err := vault.Open(path, vault.Credentials{Password: []byte(testPW)})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	m, err := vmodel.Load(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range m.Other {
		if o.Title == title {
			return o.UUID
		}
	}
	return ""
}

// A file the window cannot read again (damaged, or another writer changed the password) is tried once by the background check, not every few seconds;
// the Refresh button (full) tries again and says why it failed.
func TestUnreadableChangeIsTriedOnce(t *testing.T) {
	p := makeVault(t, "")
	u := &vaultUnlocker{env: cli.NewWindowEnv(), path: p, plat: testProject(t)}
	core, err := u.Open([]byte(testPW))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Lock()
	m := core.(*modelCore)
	id := connUUID(t, p, "")
	if err := os.WriteFile(p, []byte("not a vault any more"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ch, err := m.Sync(false); ch || err == nil {
		t.Fatalf("a damaged file must fail: %v %v", ch, err)
	}
	if ch, err := m.Sync(false); ch || err != nil {
		t.Fatalf("the same damaged file was tried again: %v %v", ch, err)
	}
	if ch, err := m.Sync(true); ch || err == nil {
		t.Fatalf("a full check must try again: %v %v", ch, err)
	}
	if got, err := core.Reveal("m", "conn/"+id, "", "credentials"); err != nil || got != "the-value" {
		t.Fatalf("the window lost what it had: %v", err)
	}
}
