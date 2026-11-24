//go:build desktop

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/pkg/vault"
)

const newPW = "k7Qm2xVb9RtZ" // a throwaway that passes the policy

func TestMakerAppliesThePolicyAndMakesAnOpenableVault(t *testing.T) {
	env, _ := testEnv(t, nil)
	m := makerFor(newFileVaults(env))
	if m == nil {
		t.Fatal("no maker for a list of vaults on files")
	}
	p := filepath.Join(t.TempDir(), "v.kdbx")
	if err := m.Create(p, []byte("Qwerty123456!asdf")); err == nil {
		t.Fatal("a weak password made a vault")
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("a file was written for a refused password")
	}
	if err := m.Create(p, []byte(newPW)); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	v, err := vault.Open(p, vault.Credentials{Password: []byte(newPW)})
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	if err := m.Create(p, []byte(newPW)); err == nil {
		t.Fatal("an existing vault was overwritten")
	}
	if makerFor(nil) != nil {
		t.Fatal("the demo has a maker")
	}
}

// The whole way through the window's App on the real list of vaults and the real unlocker: the project folder first, the file its description names is the
// place (no save dialog for it), the new vault opens with that project at once and with the password; the recovery kit is saved where the person says.
func TestNewVaultThroughTheApp(t *testing.T) {
	env, _ := testEnv(t, nil)
	f := newFileVaults(env)
	root := checkout(t)
	target, err := cli.DefaultVaultPath(root)
	if err != nil {
		t.Fatal(err)
	}
	kit := filepath.Join(t.TempDir(), "kit.txt")
	saves := 0
	a := desktop.New(desktop.Options{Vaults: f, Maker: makerFor(f),
		Pick:     func(string, string) (string, error) { return root, nil },
		PickSave: func(string, string, string) (string, error) { saves++; return kit, nil }})
	if r := a.NewVaultPlace("t"); r.Status != 409 { // the project folder comes first
		t.Fatalf("%+v", r)
	}
	r := a.NewVaultProject("t")
	if d, _ := r.Data.(map[string]any); r.Status != 200 || d["file"] != filepath.Base(target) || d["exists"] != false {
		t.Fatalf("%+v (want the file of the description, %s)", r, filepath.Base(target))
	}
	if r := a.CreateVault(newPW, newPW, false); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("the vault is not where the project description names it")
	}
	// no question about a checkout on the lock screen
	if d, _ := a.ListVaults().Data.(map[string]any); d["problem"] != nil {
		t.Fatalf("the lock screen asks something: %+v", d["problem"])
	}
	if r := a.Unlock("password", newPW); r.Status != 200 {
		t.Fatalf("the new vault does not unlock: %+v", r)
	}
	if r := a.SaveRecoveryKit("t", "{name}\n{path}\n{password}"); r.Status != 200 || saves != 1 {
		t.Fatalf("%+v", r)
	}
	b, err := os.ReadFile(kit)
	if err != nil || string(b) != filepath.Base(target)+"\n"+target+"\n"+newPW {
		t.Fatalf("kit: %v (%d bytes)", err, len(b))
	}
	if list := f.List(); len(list) != 1 || list[0].Path != target {
		t.Fatalf("%+v", list)
	}
}

// Saved elsewhere, outside the checkout: the chosen project folder is recorded with the vault all the same, so it opens without the question.
func TestNewVaultSavedElsewhereKeepsItsProject(t *testing.T) {
	env, _ := testEnv(t, nil)
	f := newFileVaults(env)
	root := checkout(t)
	elsewhere := filepath.Join(t.TempDir(), "mine.kdbx")
	a := desktop.New(desktop.Options{Vaults: f, Maker: makerFor(f),
		Pick:     func(string, string) (string, error) { return root, nil },
		PickSave: func(string, string, string) (string, error) { return elsewhere, nil }})
	if r := a.NewVaultProject("t"); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	if r := a.NewVaultPlace("t"); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	if r := a.CreateVault(newPW, newPW, false); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	if d, _ := a.ListVaults().Data.(map[string]any); d["problem"] != nil {
		t.Fatalf("the vault saved elsewhere asks for a checkout: %+v", d["problem"])
	}
	if r := a.Unlock("password", newPW); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	list := f.List()
	if len(list) != 1 || list[0].Path != elsewhere || list[0].Root == "" {
		t.Fatalf("the vault is recorded without its checkout: %+v", list)
	}
}

func TestNewVaultNeedsAProjectDescription(t *testing.T) {
	env, _ := testEnv(t, nil)
	f := newFileVaults(env)
	empty := t.TempDir()
	if _, err := f.DefaultVault(empty); err == nil {
		t.Fatal("a folder without a project description was accepted")
	}
	a := desktop.New(desktop.Options{Vaults: f, Maker: makerFor(f), Pick: func(string, string) (string, error) { return empty, nil },
		PickSave: func(string, string, string) (string, error) { return filepath.Join(t.TempDir(), "x.kdbx"), nil }})
	r := a.NewVaultProject("t")
	if d, _ := r.Data.(map[string]any); r.Status != 409 || d["code"] != "vault_bad_root" {
		t.Fatalf("%+v", r)
	}
}

func TestNoMakerNoNewVault(t *testing.T) {
	a := desktop.New(desktop.Options{Unlocker: &desktop.MemoryUnlocker{Password: "throwaway"}})
	if r := a.NewVaultPlace("t"); r.Status != 409 {
		t.Fatalf("%+v", r)
	}
}
