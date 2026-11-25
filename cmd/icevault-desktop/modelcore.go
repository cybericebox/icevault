//go:build desktop || harness

package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/mpage"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/pkg/vault"
)

// THE ADAPTER FILE for the vault model: desktop.Core over the vault is mpage.Core (the window of the model), which saves itself.

type modelCore struct {
	mu   sync.Mutex
	v    *vault.Vault
	mp   *mpage.Core
	plat *render.Project
	env  *cli.Env
	root string // the project checkout of the vault ("" when not known)
}

// description finds the project description: the one of the vault's checkout, else ICEVAULT_PROJECT, else the path remembered for the window:
// (nil, "", "") when there is none.
func description(env *cli.Env, root string) (*project.Description, string, string) {
	if env == nil {
		return nil, "", ""
	}
	p := project.Find(env.Getenv, root, cli.SavedProject(env.Getenv))
	if p == "" {
		return nil, "", ""
	}
	d, err := project.Load(p)
	if err != nil {
		return nil, p, "invalid"
	}
	return d, p, ""
}

// loose says the vault has no project.
func (m *modelCore) loose() bool { return m.plat == nil && m.root == "" }

// newModelCore opens the model of an unlocked vault.
// loose says the vault has no project (no checkout, no description): plat is nil then.
func newModelCore(v *vault.Vault, plat *render.Project, env *cli.Env, root string, loose bool) (*modelCore, error) {
	mp, err := buildModel(v, env, root, loose)
	if err != nil {
		return nil, err
	}
	return &modelCore{v: v, mp: mp, plat: plat, env: env, root: root}, nil
}

func buildModel(v *vault.Vault, env *cli.Env, root string, loose bool) (*mpage.Core, error) {
	d, p, why := description(env, root)
	if loose { // a vault without a project: no description, not even a remembered one of another project
		d, p, why = nil, "", ""
	}
	mp, err := mpage.New(v, d)
	if err != nil {
		return nil, err
	}
	mp.DescPath, mp.DescErr, mp.NoProject = p, why, loose && d == nil
	if env != nil {
		mp.Remember = func(path string) error { return cli.RememberProject(env.Getenv, path) }
	}
	return mp, nil
}

// Sync implements desktop.Syncer: when another writer (the command line, a second window) saved the vault file, it is read again with the key derived at
// unlock (no password is asked for or kept) and the core is rebuilt from it. The window's own saves never count (pkg/vault records what it wrote). The
// slow part, the key derivation of the new file, runs without the lock, so reads go on meanwhile; a lock or another reload in between wins and this one is
// dropped.
func (m *modelCore) Sync(full bool) (bool, error) {
	m.mu.Lock()
	if m.v == nil {
		m.mu.Unlock()
		return false, errLocked
	}
	changed, err := m.v.Changed(full)
	if err != nil || !changed {
		m.mu.Unlock()
		return false, err
	}
	old, key := m.v, m.v.Key()
	m.mu.Unlock()
	seen, _ := os.Stat(old.Path()) // before the read: a file replaced after this look is a change again
	nv, err := vault.Reopen(old.Path(), key)
	key.Wipe()
	if err == nil {
		next := &modelCore{plat: m.plat, env: m.env, v: nv, root: m.root}
		next.mp, err = buildModel(nv, m.env, m.root, m.loose())
		if err == nil {
			return m.swap(old, next), nil
		}
		nv.Close()
	}
	m.mu.Lock()
	if m.v == old {
		old.SkipChange(seen) // the background check does not try this file again; Refresh (full) does
	}
	m.mu.Unlock()
	return false, err
}

// swap puts the vault read again in place of old, unless the window was locked or reloaded meanwhile.
func (m *modelCore) swap(old *vault.Vault, next *modelCore) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.v != old {
		next.v.Close()
		return false
	}
	old.Close()
	m.v, m.mp = next.v, next.mp
	return true
}

// errLocked is the refusal of a core that was locked while a call was running: the page shows the "locked" message.
var errLocked = &desktop.Error{Status: 423, Code: "locked"}

var _ desktop.Syncer = (*modelCore)(nil)

func (m *modelCore) Read(op string, args map[string]any) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.v == nil {
		return nil, errLocked
	}
	return m.mp.Read(op, args)
}

// DefaultVisibility and EnvHoldsSecrets are the optional parts of desktop.Core the agent API uses (desktop.VisDefaulter, desktop.SecretCounter).
func (m *modelCore) DefaultVisibility(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.v == nil {
		return "secret"
	}
	return m.mp.DefaultVisibility(key)
}

func (m *modelCore) EnvHoldsSecrets(env string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.v == nil || m.mp.EnvHoldsSecrets(env)
}

func (m *modelCore) Write(op string, args map[string]any) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.v == nil {
		return nil, errLocked
	}
	if op == "m-project" {
		return m.rememberProject(args)
	}
	return m.mp.Write(op, args)
}

// rememberProject saves the path of the project description the window was given (the description of the vault's checkout and ICEVAULT_PROJECT
// still come first) after reading it once, and rebuilds the core of the model with it.
func (m *modelCore) rememberProject(args map[string]any) (any, error) {
	p, _ := args["path"].(string)
	p = strings.TrimSpace(p)
	if !filepath.IsAbs(p) {
		return nil, &desktop.Error{Status: 409, Code: "project_relative", Params: map[string]any{}}
	}
	if _, err := project.Load(p); err != nil {
		return nil, &desktop.Error{Status: 409, Code: "project_invalid", Params: map[string]any{"path": p}}
	}
	if m.env == nil || cli.RememberProject(m.env.Getenv, p) != nil {
		return nil, &desktop.Error{Status: 409, Code: "project_not_saved", Params: map[string]any{}}
	}
	mp, err := buildModel(m.v, m.env, m.root, m.loose())
	if err != nil {
		return nil, err
	}
	m.mp = mp
	return map[string]any{"ok": true}, nil
}

func (m *modelCore) Reveal(section, name, group, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.v == nil {
		return "", errLocked
	}
	return m.mp.Reveal(section, name, group, key)
}

func (m *modelCore) Lock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.v != nil {
		m.v.Close()
		m.v, m.mp = nil, nil
	}
}
