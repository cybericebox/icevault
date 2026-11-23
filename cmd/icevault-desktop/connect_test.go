//go:build desktop

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

const testPW = "pw-throwaway-1"

// makeVault is a vault of the vault model with one connection (password testPW, the key file kf when not "").
func makeVault(t *testing.T, kf string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "v.kdbx")
	v, err := vault.Create(p, vault.Credentials{Password: []byte(testPW), KeyFile: kf}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	m := &vmodel.Vault{Connections: []*vmodel.Connection{{Name: "GCP", Kind: "google", Fields: []*vmodel.Field{{Name: "credentials", Value: "the-value", Secret: true}}}}}
	if err := vmodel.Write(v, m); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	v.Close()
	return p
}

// connUUID is the UUID of the connection of the vault at path.
func connUUID(t *testing.T, path, key string) string {
	t.Helper()
	v, err := vault.Open(path, vault.Credentials{Password: []byte(testPW), KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	m, err := vmodel.Load(v)
	if err != nil {
		t.Fatal(err)
	}
	return m.Connection("GCP").UUID
}

func TestUnlockerPasswordAndKeyFile(t *testing.T) {
	kf := filepath.Join(t.TempDir(), "k.keyx")
	if err := vault.NewKeyFile(kf); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", kf} {
		p := makeVault(t, key)
		u := &vaultUnlocker{env: cli.NewWindowEnv(), path: p, keyFile: key, plat: testProject(t)}
		id := connUUID(t, p, key)
		if u.HasKeyFile() != (key != "") {
			t.Fatal("HasKeyFile")
		}
		if _, err := u.Open([]byte("wrong")); !errors.Is(err, desktop.ErrWrongPassword) {
			t.Fatalf("wrong password: %v", err)
		}
		core, err := u.Open([]byte(testPW))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := core.Reveal("m", "conn/"+id, "", "credentials"); err != nil || got != "the-value" {
			t.Fatalf("reveal: %v", err)
		}
		if _, err := core.Reveal("m", "conn/"+id, "", "nope"); err == nil {
			t.Fatal("reveal of a missing field")
		}
		if err := coreWrite(t, core, key, p); err != nil {
			t.Fatal(err)
		}
		nav, err := core.Read("nav", nil)
		if err != nil || nav == nil {
			t.Fatalf("nav: %v", err)
		}
		core.Lock()
		if _, err := core.Reveal("m", "conn/"+id, "", "credentials"); err == nil {
			t.Fatal("reveal after lock")
		}
		if key != "" {
			wrong := &vaultUnlocker{env: cli.NewWindowEnv(), path: p, plat: testProject(t)}
			if _, err := wrong.Open([]byte(testPW)); !errors.Is(err, desktop.ErrWrongPassword) {
				t.Fatalf("without the key file: %v", err)
			}
		}
	}
	if _, err := (&vaultUnlocker{env: cli.NewWindowEnv(), path: filepath.Join(t.TempDir(), "none"), plat: testProject(t)}).Open([]byte(testPW)); err == nil || errors.Is(err, desktop.ErrWrongPassword) {
		t.Fatalf("a missing file: %v", err)
	}
}

func m(x any) map[string]any { r, _ := x.(map[string]any); return r }

func TestConnectDemo(t *testing.T) {
	t.Setenv("ICEVAULT_CONFIG_DIR", t.TempDir()) // the demo never reads or writes the list of vaults
	testConnectDemo(t, "demo")
}

func testConnectDemo(t *testing.T, mode string) {
	vs, first, cleanup, err := connect(mode)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if first == "" || len(vs.List()) < 2 {
		t.Fatalf("the demo has a sample list: %q %v", first, vs.List())
	}
	tg, err := vs.Prepare(first)
	if err != nil || tg.Binding || tg.Confirm != nil {
		t.Fatalf("demo target: %+v %v", tg, err)
	}
	core, err := tg.Unlocker.Open([]byte("demo"))
	if err != nil {
		t.Fatal(err)
	}
	nav, err := core.Read("nav", nil)
	if err != nil || nav == nil {
		t.Fatalf("%s nav: %v", mode, err)
	}
	if m, _ := nav.(map[string]any); (mode == "demo") != (m["model"] == true) {
		t.Fatalf("%s: model %v", mode, m["model"])
	}
	if mode == "demo" {
		checkNothingUnwired(t, nav)
		testRememberProject(t, core)
	}
	core.Lock()
	entries, _ := os.ReadDir(os.Getenv("ICEVAULT_CONFIG_DIR"))
	if len(entries) != 0 {
		t.Fatalf("the demo wrote into the configuration folder: %v", entries)
	}
}

// checkNothingUnwired: in the demo (the import of the example's trees), no product of the window misses a site, or the connection of its site or of
// a kind it needs when the vault has a connection of that kind.
func checkNothingUnwired(t *testing.T, nav any) {
	t.Helper()
	envs, _ := m(nav)["envs"].([]map[string]any)
	if len(envs) == 0 {
		t.Fatalf("no environments in the nav: %T", m(nav)["envs"])
	}
	kinds := map[any]bool{} // the kinds the vault has a connection of
	conns, _ := m(nav)["connections"].([]map[string]any)
	for _, c := range conns {
		kinds[c["kind"]] = true
	}
	for _, e := range envs {
		prods, _ := e["products"].([]map[string]any)
		for _, p := range prods {
			miss, _ := p["missing"].([]map[string]any)
			for _, x := range miss {
				switch x["where"] {
				case "site_connection", "connection":
					if !kinds[x["key"]] {
						continue
					}
					t.Errorf("%v: product %v misses %v %v though the vault has one", e["name"], p["name"], x["where"], x["key"])
				case "site":
					t.Errorf("%v: product %v misses %v %v", e["name"], p["name"], x["where"], x["key"])
				}
			}
		}
	}
}

// testRememberProject: the path of the description given in the window is read once, refused when relative or not a description, and saved in the
// configuration folder of the window's environment (the demo's own temp folder).
func testRememberProject(t *testing.T, core desktop.Core) {
	t.Helper()
	mc, ok := core.(*modelCore)
	if !ok {
		t.Fatalf("core %T", core)
	}
	code := func(path string) string {
		_, err := core.Write("m-project", map[string]any{"path": path})
		var de *desktop.Error
		if errors.As(err, &de) {
			return de.Code
		}
		if err != nil {
			t.Fatal(err)
		}
		return ""
	}
	if c := code("project.yaml"); c != "project_relative" {
		t.Fatalf("a relative path: %q", c)
	}
	if c := code(filepath.Join(t.TempDir(), "none.yaml")); c != "project_invalid" {
		t.Fatalf("a missing file: %q", c)
	}
	p := filepath.Join(mc.root, "icevault-project.yaml")
	if c := code(p); c != "" || cli.SavedProject(mc.env.Getenv) != p {
		t.Fatalf("the description is not remembered: %q %q", c, cli.SavedProject(mc.env.Getenv))
	}
}

func testProject(t *testing.T) *render.Project {
	t.Helper()
	dir := t.TempDir()
	if err := example.Write(dir); err != nil {
		t.Fatal(err)
	}
	p, err := cli.LoadProject(dir)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// coreWrite: a write op through the adapter reaches the file (the model, then the atomic save), a refusal comes back as a desktop.Error, and a
// reopen of the vault sees the change.
func coreWrite(t *testing.T, core desktop.Core, key, path string) error {
	t.Helper()
	if _, err := core.Write("m-other", map[string]any{"action": "create", "title": "router", "value": "new-value"}); err != nil {
		return err
	}
	if _, werr := core.Write("no-such-op", map[string]any{}); werr == nil {
		t.Fatal("an unknown op must be refused")
	}
	re, rerr := vault.Open(path, vault.Credentials{Password: []byte(testPW), KeyFile: key})
	if rerr != nil {
		return rerr
	}
	defer re.Close()
	m, err := vmodel.Load(re)
	if err != nil || len(m.Other) != 1 || m.Other[0].Value != "new-value" {
		t.Fatalf("the write is not on disk: %v", err)
	}
	return nil
}
