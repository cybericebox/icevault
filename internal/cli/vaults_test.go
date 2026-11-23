//go:build !windows

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/example"
)

func cfgEnv(base string, extra map[string]string) func(string) string {
	return func(k string) string {
		if k == configDirVar {
			return base
		}
		return extra[k]
	}
}

// A checkout of the example project; a vault file at plain/vault/<name> when name is not "".
func fakeCheckout(t *testing.T, name string) (root, vaultFile string) {
	t.Helper()
	root = t.TempDir()
	if err := example.Write(root); err != nil {
		t.Fatal(err)
	}
	if name == "" {
		return root, ""
	}
	vaultFile = filepath.Join(root, "plain", "vault", name)
	if err := os.MkdirAll(filepath.Dir(vaultFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultFile, []byte("not read"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, vaultFile
}

// vaults.json: written 0600 in a 0700 folder, read back the same, the newest first, cut to MaxRecent, a path kept once, never a secret field.
func TestRecentVaultsReadWriteAndLimit(t *testing.T) {
	base := t.TempDir()
	getenv := cfgEnv(base, nil)
	if list, found, err := LoadRecent(getenv); err != nil || found || len(list) != 0 {
		t.Fatalf("no file yet: %v %v %v", list, found, err)
	}
	var list []RecentVault
	at := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < MaxRecent+3; i++ {
		list = TouchRecent(list, RecentVault{Path: fmt.Sprintf("/v/%02d.kdbx", i)}, at.Add(time.Duration(i)*time.Minute))
	}
	if len(list) != MaxRecent || list[0].Path != "/v/12.kdbx" || list[MaxRecent-1].Path != "/v/03.kdbx" {
		t.Fatalf("limit and order: %+v", list)
	}
	if list[0].Label != "12.kdbx" || list[0].LastOpened != "2026-11-01T10:12:00Z" {
		t.Fatalf("label and time: %+v", list[0])
	}
	// opening one again moves it to the front and keeps its saved checkout
	list[4].Root = "/project"
	again := TouchRecent(list, RecentVault{Path: list[4].Path}, at.Add(time.Hour))
	if again[0].Path != list[4].Path || again[0].Root != "/project" || len(again) != MaxRecent {
		t.Fatalf("open again: %+v", again[0])
	}
	if err := SaveRecent(getenv, again); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(base, appDirName, vaultsName)
	st, err := os.Stat(f)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v %v", st, err)
	}
	dst, err := os.Stat(filepath.Dir(f))
	if err != nil || dst.Mode().Perm() != 0o700 {
		t.Fatalf("folder mode: %v %v", dst, err)
	}
	got, found, err := LoadRecent(getenv)
	if err != nil || !found || len(got) != MaxRecent || got[0] != again[0] {
		t.Fatalf("read back: %+v %v %v", got, found, err)
	}
	var raw []map[string]any
	data, _ := os.ReadFile(f)
	if json.Unmarshal(data, &raw) != nil {
		t.Fatal("not JSON")
	}
	for _, m := range raw {
		for k := range m {
			if k != "path" && k != "checkout" && k != "label" && k != "last_opened" {
				t.Fatalf("an unexpected field %q", k)
			}
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(f))
	for _, e := range entries {
		if e.Name() != vaultsName {
			t.Fatalf("left behind: %s", e.Name())
		}
	}
	// forgetting drops the entry only: the file of the vault is not touched
	_, vf := fakeCheckout(t, "keep.kdbx")
	l2 := ForgetRecent(TouchRecent(got, RecentVault{Path: vf}, at), vf)
	if len(l2) != MaxRecent-1 || l2[0].Path == vf { // the eleventh pushed the oldest out
		t.Fatalf("forget: %+v", l2)
	}
	if _, err := os.Stat(vf); err != nil {
		t.Fatal("the vault file was removed")
	}
	// relative paths and duplicates in a hand-edited file are dropped
	if err := os.WriteFile(f, []byte(`[{"path":"rel.kdbx"},{"path":"/a/x.kdbx","checkout":"rel"},{"path":"/a/x.kdbx"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err = LoadRecent(getenv)
	if err != nil || len(got) != 1 || got[0].Path != "/a/x.kdbx" || got[0].Root != "" || got[0].Label != "x.kdbx" {
		t.Fatalf("clean: %+v %v", got, err)
	}
	if err := os.WriteFile(f, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := LoadRecent(getenv); err == nil || !found {
		t.Fatal("a broken file must be an error, not an empty list that overwrites it")
	}
}

// The first start: the vault found the old way becomes the first entry; the file is written once and wins afterwards.
func TestRecentVaultsMigration(t *testing.T) {
	root, vf := fakeCheckout(t, "lumen.kdbx")
	base := t.TempDir()
	e := &Env{Getenv: cfgEnv(base, nil), Root: root}
	list, err := MigrateRecent(e)
	if err != nil || len(list) != 1 || list[0].Path != vf || list[0].Root != root || list[0].Label != "lumen.kdbx" || list[0].LastOpened != "" {
		t.Fatalf("migrated: %+v %v", list, err)
	}
	if _, found, _ := LoadRecent(e.Getenv); !found {
		t.Fatal("the migrated list was not written")
	}
	// ICEVAULT_VAULT names the vault when it is set
	other := filepath.Join(t.TempDir(), "other.kdbx")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	base2 := t.TempDir()
	e2 := &Env{Getenv: cfgEnv(base2, map[string]string{"ICEVAULT_VAULT": other}), Root: root}
	list, err = MigrateRecent(e2)
	if err != nil || len(list) != 1 || list[0].Path != other || list[0].Root != root {
		t.Fatalf("ICEVAULT_VAULT: %+v %v", list, err)
	}
	// the file exists now: the next start reads it and migrates nothing
	if err := SaveRecent(e2.Getenv, []RecentVault{}); err != nil {
		t.Fatal(err)
	}
	if list, err := MigrateRecent(e2); err != nil || len(list) != 0 {
		t.Fatalf("an existing list must win: %+v %v", list, err)
	}
	// nothing to migrate (no checkout, no file): nothing is written, so a later where --remember is still taken up
	base3 := t.TempDir()
	e3 := &Env{Getenv: cfgEnv(base3, nil)}
	if list, err := MigrateRecent(e3); err != nil || len(list) != 0 {
		t.Fatalf("empty: %+v %v", list, err)
	}
	if _, err := os.Stat(filepath.Join(base3, appDirName, vaultsName)); !os.IsNotExist(err) {
		t.Fatal("a list was written with nothing in it")
	}
	// a checkout without the vault file migrates nothing either
	empty, _ := fakeCheckout(t, "")
	_ = os.RemoveAll(filepath.Join(empty, "plain", "vault"))
	if list, err := MigrateRecent(&Env{Getenv: cfgEnv(t.TempDir(), nil), Root: empty}); err != nil || len(list) != 0 {
		t.Fatalf("no vault file: %+v %v", list, err)
	}
}

func TestRootOf(t *testing.T) {
	root, vf := fakeCheckout(t, "team.kdbx")
	if got := RootOf(vf, ""); got != root {
		t.Fatalf("a vault inside a checkout: %q", got)
	}
	saved, _ := fakeCheckout(t, "")
	loose := filepath.Join(t.TempDir(), "loose.kdbx")
	if got := RootOf(loose, saved); got != saved {
		t.Fatalf("the saved checkout: %q", got)
	}
	if got := RootOf(loose, ""); got != "" {
		t.Fatalf("nothing known: %q", got)
	}
	// a saved folder that is not a checkout is not used
	notCheckout := t.TempDir()
	if got := RootOf(loose, notCheckout); got != "" {
		t.Fatalf("a folder without a description: %q", got)
	}
	if ValidRoot("relative") || !ValidRoot(saved) || ValidRoot(notCheckout) {
		t.Fatal("ValidRoot")
	}
	// the info file of init is looked at, not read
	if HasInfoFile(vf) {
		t.Fatal("no info file yet")
	}
	if err := os.WriteFile(vf+infoSuffix, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !HasInfoFile(vf) {
		t.Fatal("the info file")
	}
}
