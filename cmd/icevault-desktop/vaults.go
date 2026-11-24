//go:build desktop || harness

package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// fileVaults is the list of vaults of the window on vaults.json (internal/cli/vaults.go): the recent vaults, the project checkout of each and
// what it takes to unlock one. It holds paths only; the vault files are opened by vaultUnlocker.
type fileVaults struct {
	mu    sync.Mutex
	env   *cli.Env
	list  []cli.RecentVault
	roots map[string]string // checkouts found or named for files that are not in the list yet
	home  string
	now   func() time.Time
}

func newFileVaults(env *cli.Env) *fileVaults {
	list, err := cli.MigrateRecent(env)
	if err != nil {
		list = nil // an unreadable vaults.json: the window starts with an empty list and does not overwrite the file until a vault is opened
	}
	home, _ := os.UserHomeDir()
	return &fileVaults{env: env, list: list, roots: map[string]string{}, home: home, now: time.Now}
}

// first is the vault the window chooses at the start: ICEVAULT_VAULT (the command line's --vault), else the newest of the list.
func (f *fileVaults) first() string {
	if v := f.env.Getenv("ICEVAULT_VAULT"); v != "" {
		if abs, err := filepath.Abs(v); err == nil {
			return abs
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.list) > 0 {
		return f.list[0].Path
	}
	return ""
}

// tilde writes the home folder as "~" (what the lock screen shows).
func (f *fileVaults) tilde(p string) string {
	if p == "" || f.home == "" {
		return p
	}
	if p == f.home {
		return "~"
	}
	if strings.HasPrefix(p, f.home+string(filepath.Separator)) {
		return "~" + p[len(f.home):]
	}
	return p
}

func (f *fileVaults) entry(path string) (cli.RecentVault, bool) {
	for _, v := range f.list {
		if v.Path == path {
			return v, true
		}
	}
	return cli.RecentVault{}, false
}

func (f *fileVaults) info(v cli.RecentVault) desktop.VaultInfo {
	st, err := os.Stat(v.Path)
	root := cli.RootOf(v.Path, v.Root)
	if root == "" {
		root = v.Root
	}
	return desktop.VaultInfo{Path: v.Path, Label: v.Label, Folder: f.tilde(filepath.Dir(v.Path)), Root: f.tilde(root), LastOpened: v.LastOpened,
		Missing: err != nil || !st.Mode().IsRegular()}
}

func (f *fileVaults) List() []desktop.VaultInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]desktop.VaultInfo, 0, len(f.list))
	for _, v := range f.list {
		out = append(out, f.info(v))
	}
	return out
}

func (f *fileVaults) Describe(path string) desktop.VaultInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, found := f.entry(path)
	if !found {
		v = cli.RecentVault{Path: path, Label: filepath.Base(path), Root: f.roots[path]}
	}
	return f.info(v)
}

// Prepare: the file must be there, its checkout known (a folder above it with a project description, the saved one, or one named in the folder
// dialog) and the description of that checkout readable. The description is read per vault.
func (f *fileVaults) Prepare(path string) (desktop.Target, error) {
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		return desktop.Target{}, &desktop.Error{Status: 409, Code: "vault_missing"}
	}
	f.mu.Lock()
	saved := f.roots[path]
	if v, found := f.entry(path); found && saved == "" {
		saved = v.Root
	}
	f.mu.Unlock()
	root := cli.RootOf(path, saved)
	if root == "" {
		return desktop.Target{}, &desktop.Error{Status: 409, Code: "vault_needs_root"}
	}
	plat, err := cli.LoadProject(root)
	if err != nil {
		return desktop.Target{}, &desktop.Error{Status: 409, Code: "setup_no_model"}
	}
	f.mu.Lock()
	f.roots[path] = root
	f.mu.Unlock()
	u := &vaultUnlocker{env: f.env, path: path, keyFile: f.env.Getenv("ICEVAULT_KEYFILE"), plat: plat, root: root}
	t := desktop.Target{Unlocker: u}
	if f.env.TouchIDEnabled(path) {
		env := f.env
		t.Binding = true
		t.Confirm = func(string) bool {
			pw := env.TouchIDPassword(path)
			defer wipe(pw)
			return pw != nil
		}
	}
	return t, nil
}

// DefaultVault is the vault file the description in the folder names (what init-vault uses); the folder is the checkout of a vault made there.
func (f *fileVaults) DefaultVault(root string) (string, error) {
	root = filepath.Clean(root)
	if !cli.ValidRoot(root) {
		return "", &desktop.Error{Status: 409, Code: "vault_bad_root"}
	}
	p, err := cli.DefaultVaultPath(root)
	if err != nil {
		return "", &desktop.Error{Status: 409, Code: "setup_no_model"}
	}
	f.mu.Lock()
	f.roots[p] = root // so that the page can show it with its checkout
	f.mu.Unlock()
	return p, nil
}

func (f *fileVaults) SetRoot(path, root string) error {
	root = filepath.Clean(root)
	if !cli.ValidRoot(root) {
		return &desktop.Error{Status: 409, Code: "vault_bad_root"}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roots[path] = root
	for i := range f.list {
		if f.list[i].Path == path {
			f.list[i].Root = root
			return f.save()
		}
	}
	return nil // saved with the entry when the vault is unlocked
}

func (f *fileVaults) save() error {
	if err := cli.SaveRecent(f.env.Getenv, f.list); err != nil {
		return &desktop.Error{Status: 500, Code: "vaults_not_saved"}
	}
	return nil
}

func (f *fileVaults) Opened(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := cli.RecentVault{Path: path, Root: f.roots[path]}
	if old, found := f.entry(path); found {
		v.Label = old.Label
	}
	f.list = cli.TouchRecent(f.list, v, f.now())
	return f.save()
}

func (f *fileVaults) Forget(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = cli.ForgetRecent(f.list, path)
	delete(f.roots, path)
	return f.save()
}

var _ desktop.Vaults = (*fileVaults)(nil)

// ours says whether an open vault is of our kind: it is in the vault model, or it is an empty vault with the info file of `icevault init` beside
// it. Any other KeePass file is refused, and never enters the list.
func ours(v *vault.Vault, path string) bool {
	if vmodel.IsModel(v) {
		return true
	}
	groups, gerr := v.Groups("")
	entries, eerr := v.Entries("")
	return gerr == nil && eerr == nil && len(groups) == 0 && len(entries) == 0 && cli.HasInfoFile(path)
}
