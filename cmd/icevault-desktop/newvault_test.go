//go:build desktop

package main

import (
	"os"
	"path/filepath"
	"testing"

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

// The whole way through the window's App on the real list of vaults and the real unlocker: place, create, the new vault is the chosen one and opens
// with the password; the recovery kit is saved where the person says.
func TestNewVaultThroughTheApp(t *testing.T) {
	env, _ := testEnv(t, nil)
	f := newFileVaults(env)
	root := checkout(t)
	target := filepath.Join(root, "plain", "vault", "fresh.kdbx")
	kit := filepath.Join(t.TempDir(), "kit.txt")
	next := []string{target, kit}
	a := desktop.New(desktop.Options{Vaults: f, Maker: makerFor(f),
		PickSave: func(string, string) (string, error) { p := next[0]; next = next[1:]; return p, nil }})
	if r := a.NewVaultPlace("t"); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	if r := a.CreateVault(newPW, newPW, false); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	if r := a.Unlock("password", newPW); r.Status != 200 {
		t.Fatalf("the new vault does not unlock: %+v", r)
	}
	if r := a.SaveRecoveryKit("t", "{name}\n{path}\n{password}"); r.Status != 200 {
		t.Fatalf("%+v", r)
	}
	b, err := os.ReadFile(kit)
	if err != nil || string(b) != "fresh.kdbx\n"+target+"\n"+newPW {
		t.Fatalf("kit: %v (%d bytes)", err, len(b))
	}
	if list := f.List(); len(list) != 1 || list[0].Path != target {
		t.Fatalf("%+v", list)
	}
}

func TestNoMakerNoNewVault(t *testing.T) {
	a := desktop.New(desktop.Options{Unlocker: &desktop.MemoryUnlocker{Password: "throwaway"}})
	if r := a.NewVaultPlace("t"); r.Status != 409 {
		t.Fatalf("%+v", r)
	}
}
