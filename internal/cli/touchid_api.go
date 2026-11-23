package cli

// The exported face of Touch ID for the desktop window: the same binding, the same tools, no terminal.

// NewWindowEnv is the environment for a program with its own user interface: the process environment, Touch ID wherever the platform has it
// (no terminal is needed, the system dialog is the interaction), and no password prompt (the window supplies passwords itself).
func NewWindowEnv() *Env {
	e := DefaultEnv()
	e.TouchID = touchIDPlatform
	e.Exec = execRunner{dirs: KnownToolDirs} // not PATH: the minimal launchd PATH of a program started from Finder, and PATH is no place to trust here
	e.Ask = func(string) ([]byte, error) { return nil, errExit{"the window asks for the password itself"} }
	return e
}

// VaultPath is the vault file this environment names (ICEVAULT_VAULT, or the vault the project description of the checkout names).
func (e *Env) VaultPath() (string, error) { return vaultPath(e) }

// TouchIDEnabled says whether a Touch ID binding exists for the vault and is not switched off.
func (e *Env) TouchIDEnabled(vaultFile string) bool { return e.touchIDEnabled(vaultFile) }

// TouchIDPassword raises the system dialog through age and returns the master password, or nil when it was refused, timed out or failed. The caller
// wipes the slice.
func (e *Env) TouchIDPassword(vaultFile string) []byte { return e.touchIDPassword(vaultFile) }
