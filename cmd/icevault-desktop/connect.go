//go:build desktop || harness

package main

import (
	"errors"
	"strings"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// connect is the one place where the vault core is plugged in: the list of vaults on vaults.json (vaults.go) whose files are opened by the real
// unlocker on pkg/vault (master password, plus the key file named by ICEVAULT_KEYFILE) with the Touch ID binding of each file; for the demo a
// throwaway vault of the example project with a made-up list. first is the vault chosen at the start; cleanup deletes what the demo made.
func connect(mode string) (vaults desktop.Vaults, first string, cleanup func(), err error) {
	if mode == "demo" {
		return demoVaults()
	}
	f := newFileVaults(cli.NewWindowEnv())
	return f, f.first(), func() {}, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// vaultUnlocker implements desktop.Unlocker.
type vaultUnlocker struct {
	env     *cli.Env
	path    string
	keyFile string
	plat    *render.Project
	root    string // the project checkout of the vault
}

func (u *vaultUnlocker) Open(password []byte) (desktop.Core, error) {
	c := vault.Credentials{Password: password, KeyFile: u.keyFile}
	v, err := vault.Open(u.path, c) // the caller wipes password; the key file path is the core's business
	if err != nil {
		if errors.Is(err, vault.ErrBadCredentials) {
			return nil, desktop.ErrWrongPassword
		}
		return nil, err // refusals (KDBX 3, Argon2id, no file) carry an instruction and no secret
	}
	if !ours(v, u.path) {
		v.Close()
		return nil, &desktop.Error{Status: 409, Code: "vault_foreign"}
	}
	if !vmodel.IsModel(v) { // the empty vault of init (before it had the format of the model): it becomes an empty vault of the model
		if err := vmodel.Write(v, &vmodel.Vault{}); err == nil {
			err = v.Save()
		}
		if err != nil {
			v.Close()
			return nil, err
		}
	}
	core, err := newModelCore(v, u.plat, u.env, u.root)
	if err != nil {
		v.Close()
		return nil, err
	}
	return core, nil
}

func (u *vaultUnlocker) Touch() ([]byte, error) {
	if !u.env.TouchIDEnabled(u.path) {
		return nil, nil
	}
	if miss := u.env.TouchIDMissingTools(); len(miss) > 0 {
		return nil, &desktop.Error{Status: 409, Code: "touch_tools_missing", Params: map[string]any{"tools": strings.Join(miss, ", ")}}
	}
	return u.env.TouchIDPassword(u.path), nil
}

func (u *vaultUnlocker) HasKeyFile() bool { return u.keyFile != "" }
