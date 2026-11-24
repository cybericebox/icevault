//go:build desktop || harness

package main

import (
	"errors"
	"io"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/pkg/vault"
)

// ChangePassword implements desktop.PasswordChanger on the vault the window has open: the typed current password must open the file (a fresh open,
// so a mistyped one never reaches the vault in memory), then internal/cli does the change (the policy, the atomic save, the Touch ID binding, the info
// file, the copies). The vault in memory takes the new key in the same step, so the window stays unlocked and does not see its own save as a change.
func (m *modelCore) ChangePassword(current, next []byte, refresh bool) (desktop.ChangeOutcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.v == nil {
		return desktop.ChangeOutcome{}, errLocked
	}
	if m.env == nil {
		return desktop.ChangeOutcome{}, &desktop.Error{Status: 409, Code: "change_unavailable"}
	}
	kf := m.env.Getenv("ICEVAULT_KEYFILE")
	c := vault.Credentials{Password: append([]byte(nil), current...), KeyFile: kf}
	chk, err := vault.Open(m.v.Path(), c)
	c.Wipe()
	if err != nil {
		if errors.Is(err, vault.ErrBadCredentials) {
			return desktop.ChangeOutcome{}, desktop.ErrWrongPassword
		}
		return desktop.ChangeOutcome{}, err
	}
	chk.Close()
	rep, err := m.env.ChangePassword(m.v, next, kf, refresh, io.Discard)
	if err != nil {
		return desktop.ChangeOutcome{}, changeError(err)
	}
	return desktop.ChangeOutcome{TouchIDWasOn: rep.TouchIDWasOn, TouchIDRemoveFailed: rep.TouchIDRemoveFailed, Refreshed: rep.Refreshed, Stale: rep.Stale}, nil
}

// changeError keeps a vault error (the file changed under the window, a save in progress) so that the page gets its code; the text of a command line
// refusal (it may name a path) is dropped.
func changeError(err error) error {
	for _, known := range []error{vault.ErrChangedOnDisk, vault.ErrLocked, vault.ErrNoCredentials} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errors.New("the password was not changed")
}

func (m *modelCore) PasswordInfo() desktop.ChangeInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.v == nil || m.env == nil {
		return desktop.ChangeInfo{}
	}
	return desktop.ChangeInfo{Destinations: len(cli.CopyDestinations(m.v.Path())), TouchIDOn: m.env.TouchIDBound(m.v.Path())}
}

var _ desktop.PasswordChanger = (*modelCore)(nil)
