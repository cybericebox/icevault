//go:build desktop

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// testEnv is the window's environment with a throwaway configuration folder and nothing else from the process.
func testEnv(t *testing.T, vars map[string]string) (*cli.Env, string) {
	t.Helper()
	cfg := t.TempDir()
	env := cli.NewWindowEnv()
	env.Root = ""
	env.Getenv = func(k string) string {
		if k == "ICEVAULT_CONFIG_DIR" {
			return cfg
		}
		return vars[k]
	}
	return env, cfg
}

// checkout makes a checkout of the example project; a vault is made under its plain/vault/.
func checkout(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := example.Write(root); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "plain", "vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

// modelAt makes a vault of the vault model at path.
func modelAt(t *testing.T, path string) {
	t.Helper()
	v, err := vault.Create(path, vault.Credentials{Password: []byte(testPW)}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := vmodel.Write(v, &vmodel.Vault{}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	v.Close()
}

func vaultAt(t *testing.T, path string, entries ...vault.Entry) {
	t.Helper()
	v, err := vault.Create(path, vault.Credentials{Password: []byte(testPW)}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := v.Put(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	v.Close()
}

func code(err error) string {
	var de *desktop.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

// Only vaults of the vault model are opened: a KeePass file with other groups, or an empty one that init did not make, is refused after the password.
func TestForeignVaultIsRefused(t *testing.T) {
	dir := t.TempDir()
	plat := testProject(t)
	foreign := filepath.Join(dir, "personal.kdbx")
	vaultAt(t, foreign, vault.Entry{Group: "Personal", Title: "mail", Password: []byte("x")})
	empty := filepath.Join(dir, "empty.kdbx")
	vaultAt(t, empty)
	fresh := filepath.Join(dir, "fresh.kdbx")
	vaultAt(t, fresh) // made by another program, but with the info file of init beside it
	if err := os.WriteFile(fresh+".info.json", []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{foreign, empty} {
		u := &vaultUnlocker{env: cli.NewWindowEnv(), path: p, plat: plat}
		if _, err := u.Open([]byte(testPW)); code(err) != "vault_foreign" {
			t.Fatalf("%s: %v", filepath.Base(p), err)
		}
		if _, err := u.Open([]byte("wrong")); !errors.Is(err, desktop.ErrWrongPassword) {
			t.Fatalf("a wrong password comes first: %v", err)
		}
	}
	u := &vaultUnlocker{env: cli.NewWindowEnv(), path: fresh, plat: plat}
	core, err := u.Open([]byte(testPW))
	if err != nil {
		t.Fatalf("the empty vault of init: %v", err)
	}
	core.Lock()
	u = &vaultUnlocker{env: cli.NewWindowEnv(), path: makeVault(t, ""), plat: plat}
	if core, err = u.Open([]byte(testPW)); err != nil {
		t.Fatal(err)
	}
	core.Lock()
}

// The list on vaults.json: the first start takes the vault found the old way, unlocking puts a vault first, a foreign one is never added, a file
// outside a checkout needs its checkout named (validated), and removing an entry leaves the file.
func TestFileVaults(t *testing.T) {
	root := checkout(t)
	main := filepath.Join(root, "plain", "vault", "lumen.kdbx")
	modelAt(t, main)
	env, cfg := testEnv(t, nil)
	env.Root = root
	f := newFileVaults(env)
	if got := f.first(); got != main {
		t.Fatalf("first: %q", got)
	}
	l := f.List()
	if len(l) != 1 || l[0].Path != main || l[0].Missing || l[0].LastOpened != "" || l[0].Label != "lumen.kdbx" {
		t.Fatalf("migrated list: %+v", l)
	}
	a := desktop.New(desktop.Options{Vaults: f, Vault: f.first()})
	if r := a.Unlock("password", testPW); r.Status != 200 {
		t.Fatalf("unlock: %+v", r)
	}
	if l := f.List(); l[0].LastOpened == "" {
		t.Fatal("the unlock was not recorded")
	}
	// a loose copy outside any checkout: the checkout is asked for, a wrong folder refused, the right one used and kept with the entry
	loose := filepath.Join(t.TempDir(), "copy.kdbx")
	data, err := os.ReadFile(main)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loose, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Prepare(loose); code(err) != "vault_needs_root" {
		t.Fatalf("loose: %v", err)
	}
	if err := f.SetRoot(loose, t.TempDir()); code(err) != "vault_bad_root" {
		t.Fatalf("a folder that is not a checkout: %v", err)
	}
	if err := f.SetRoot(loose, root); err != nil {
		t.Fatal(err)
	}
	if r := a.SelectVault(loose); r.Status != 200 || r.Data.(map[string]any)["ok"] != true {
		t.Fatalf("select loose: %+v", r)
	}
	if r := a.Unlock("password", testPW); r.Status != 200 {
		t.Fatalf("unlock loose: %+v", r)
	}
	var saved []cli.RecentVault
	raw, err := os.ReadFile(filepath.Join(cfg, "com.cybericebox.icevault", "vaults.json"))
	if err != nil || json.Unmarshal(raw, &saved) != nil {
		t.Fatalf("vaults.json: %v", err)
	}
	if len(saved) != 2 || saved[0].Path != loose || saved[0].Root != root || saved[1].Path != main {
		t.Fatalf("saved: %+v", saved)
	}
	// a foreign file: refused, not added
	foreign := filepath.Join(root, "plain", "vault", "personal.kdbx")
	vaultAt(t, foreign, vault.Entry{Group: "Personal", Title: "mail"})
	a.SelectVault(foreign)
	if r := a.Unlock("password", testPW); r.Status != 409 || r.Data.(map[string]any)["code"] != "vault_foreign" {
		t.Fatalf("foreign: %+v", r)
	}
	if len(f.List()) != 2 {
		t.Fatalf("a foreign vault entered the list: %+v", f.List())
	}
	// a missing file
	if _, err := f.Prepare(filepath.Join(root, "gone.kdbx")); code(err) != "vault_missing" {
		t.Fatalf("missing: %v", err)
	}
	// removed from the list, the file stays
	if err := f.Forget(loose); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(loose); err != nil || len(f.List()) != 1 {
		t.Fatalf("forget: %v %+v", err, f.List())
	}
	// the home folder is shown as ~
	f.home = filepath.Dir(root)
	if got := f.Describe(main); got.Folder != "~/"+filepath.Base(root)+"/plain/vault" || got.Root != "~/"+filepath.Base(root) {
		t.Fatalf("describe: %+v", got)
	}
}

// ICEVAULT_VAULT (the command line's --vault) is chosen at the start, even when the list has others.
func TestTheNamedVaultIsChosenFirst(t *testing.T) {
	other := filepath.Join(t.TempDir(), "named.kdbx")
	env, _ := testEnv(t, map[string]string{"ICEVAULT_VAULT": other})
	f := newFileVaults(env)
	if got := f.first(); got != other {
		t.Fatalf("first: %q", got)
	}
}
