//go:build desktop || harness

package main

import (
	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/desktop"
)

// vaultMaker makes the vault files of the window's "New vault" with the rules of init-vault (internal/cli: the password policy, the file mode, the info
// file) and the Touch ID binding of `touchid enable`. A key file named by ICEVAULT_KEYFILE belongs to the new vault as it does to every vault this
// window opens.
type vaultMaker struct{ env *cli.Env }

func (m vaultMaker) Create(path string, password []byte) error {
	return m.env.NewVault(path, password, m.env.Getenv("ICEVAULT_KEYFILE"), "IceVault", 0)
}

func (m vaultMaker) TouchIDReady() bool { return m.env.TouchIDReady() }

func (m vaultMaker) TouchIDBind(path string, password []byte) error {
	return m.env.TouchIDBind(path, password)
}

var _ desktop.VaultMaker = vaultMaker{}

// makerFor is the maker of a list of vaults on files; the demo's made-up list has none (no New vault there).
func makerFor(v desktop.Vaults) desktop.VaultMaker {
	if f, ok := v.(*fileVaults); ok {
		return vaultMaker{f.env}
	}
	return nil
}
