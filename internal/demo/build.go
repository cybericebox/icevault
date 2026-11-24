// Package demo is the throwaway vault of the window's demo and of its browser test harness: the example project (internal/example) written into a
// temp folder, a vault of the vault model made there and filled by the import of the example's plaintext trees, the same path the command line
// takes. Nothing outside that folder is read or written.
package demo

import (
	"os"
	"path/filepath"
	"time"

	"github.com/cybericebox/icevault/internal/bridge"
	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// Password opens the demo vault.
const Password = "demo"

// The fixed time of every entry the import makes (a fixed sample looks the same in every run).
const stamp = "2026-11-02T09:30:00Z"

// Build writes the example checkout into dir/checkout and makes its vault there (the description's vault file, password password), filled from
// the plaintext trees of the example's environments, which are removed afterwards. It returns the vault file and the checkout.
func Build(dir, password string) (string, string, error) {
	root := filepath.Join(dir, "checkout")
	if err := example.Write(root); err != nil {
		return "", "", err
	}
	plat, err := cli.LoadProject(root)
	if err != nil {
		return "", "", err
	}
	d := plat.D
	path := filepath.Join(root, filepath.FromSlash(d.Checkout.Vault))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", err
	}
	v, err := vault.Create(path, vault.Credentials{Password: []byte(password)}, vault.CreateOptions{DecryptionTime: 200 * time.Millisecond, Name: d.Name})
	if err != nil {
		return "", "", err
	}
	defer v.Close()
	if err := vmodel.Write(v, &vmodel.Vault{}); err != nil {
		return "", "", err
	}
	if err := v.Save(); err != nil {
		return "", "", err
	}
	for _, env := range example.Environments {
		if err := importEnv(v, plat, root, env); err != nil {
			return "", "", err
		}
	}
	if err := markExpiries(v); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(path+".info.json", []byte("{\"copies\": [], \"sealed\": {}}\n"), 0o600); err != nil {
		return "", "", err
	}
	for _, env := range example.Environments {
		_ = os.RemoveAll(filepath.Join(root, filepath.FromSlash(d.Checkout.Plaintext), env))
	}
	return path, root, nil
}

func importEnv(v *vault.Vault, plat *render.Project, root, env string) error {
	d := plat.D
	w, err := bridge.NewWriter(v, d, plat)
	if err != nil {
		return err
	}
	tree := filepath.Join(root, filepath.FromSlash(d.Checkout.Plaintext), env)
	o := render.Options{Env: env, Tree: render.FSSource{FS: os.DirFS(tree)}, Now: func() string { return stamp }}
	conf := filepath.Join(root, filepath.FromSlash(d.Checkout.Environments), env, filepath.FromSlash(d.GeneralFile()))
	if data, err := os.ReadFile(conf); err == nil { // #nosec G304 -- the example's committed settings
		o.Extra = map[string][]byte{d.GeneralFile(): data}
	}
	snap, _ := w.Snapshot()
	if _, _, err := plat.ImportTree(w, snap, o, tree); err != nil {
		return err
	}
	return w.Commit()
}

// markExpiries gives a few values of the demo an expiry, relative to today, so that the window shows each state: one token expired two days ago, one
// expires in five days, one in a year.
func markExpiries(v *vault.Vault) error {
	m, err := vmodel.Load(v)
	if err != nil {
		return err
	}
	day := func(n int) string { return time.Now().UTC().AddDate(0, 0, n).Format(vmodel.DayFormat) }
	if len(m.Envs) > 0 && len(m.Envs[0].General) > 0 {
		m.Envs[0].General[0].Expires = day(-2)
	}
	for _, c := range m.Connections {
		for _, f := range c.Fields {
			if f.Name == "api_token" {
				f.Expires = day(5)
			}
		}
	}
	if len(m.Shared) > 0 {
		m.Shared[0].Expires = day(365)
	}
	if err := vmodel.Sync(v, m); err != nil {
		return err
	}
	return v.Save()
}
