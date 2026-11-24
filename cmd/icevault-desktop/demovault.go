//go:build desktop || harness

package main

import (
	"crypto/subtle"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/demo"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/pkg/vault"
)

// The throwaway vault of the demo and of the browser test harness: the example project written into a temp folder of its own (deleted when the
// program ends) with its vault made and filled there (internal/demo). The real vaults and the user's configuration are never touched (the folder
// has its own).

// demoWithoutDescription leaves the project description out of the demo's environment (the harness's --no-description: the window then offers
// to choose one).
var demoWithoutDescription bool

// demoEnv is the environment of a throwaway folder: the checkout and the configuration are the folder's.
func demoEnv(dir, root string) *cli.Env {
	env := cli.NewWindowEnv()
	orig := env.Getenv
	env.Getenv = func(k string) string {
		switch k {
		case "ICEVAULT_PROJECT", "ICEVAULT_ROOT":
			return ""
		case "ICEVAULT_CONFIG_DIR":
			return filepath.Join(dir, "config")
		}
		return orig(k)
	}
	env.Root = root
	if demoWithoutDescription {
		env.Root = ""
	}
	return env
}

// fileVault makes the throwaway vault in dir (the example checkout with its vault, the given password) and returns the vault file and the checkout.
func fileVault(dir, password string) (string, string, error) { return demo.Build(dir, password) }

// demoUnlocker opens the throwaway vault of the demo (password demo), made on the first unlock.
type demoUnlocker struct {
	mu   sync.Mutex
	dir  string
	path string
	root string
}

func (u *demoUnlocker) Open(password []byte) (desktop.Core, error) {
	if subtle.ConstantTimeCompare(password, []byte(demo.Password)) != 1 {
		return nil, desktop.ErrWrongPassword
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.path == "" {
		p, root, err := fileVault(u.dir, demo.Password)
		if err != nil {
			return nil, err
		}
		u.path, u.root = p, root
	}
	v, err := vault.Open(u.path, vault.Credentials{Password: password})
	if err != nil {
		return nil, err
	}
	env := demoEnv(u.dir, u.root)
	plat, err := cli.LoadProject(u.root)
	if err != nil {
		v.Close()
		return nil, err
	}
	c, err := newModelCore(v, plat, env, env.Root, false)
	if err != nil {
		v.Close()
		return nil, err
	}
	return c, nil
}

func (u *demoUnlocker) Touch() ([]byte, error) { return nil, nil }
func (u *demoUnlocker) HasKeyFile() bool       { return false }

// demoVaults is the list of the demo (made-up entries, all opening the throwaway vault) and the cleanup that deletes its folder.
func demoVaults() (desktop.Vaults, string, func(), error) {
	dir, err := os.MkdirTemp("", "icevault-demo-")
	if err != nil {
		return nil, "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	v := demo.NewVaults(&demoUnlocker{dir: dir}, time.Now)
	return v, v.First(), cleanup, nil
}
