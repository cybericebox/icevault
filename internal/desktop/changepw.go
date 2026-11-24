package desktop

import (
	"crypto/subtle"
	"errors"
	"path/filepath"

	"github.com/cybericebox/icevault/internal/password"
)

// Change the master password of the unlocked vault. The page asks for the current password (typed: a Touch ID unlock does not stand in for it), the new
// one with the live meter of PasswordStrength (or one made by GeneratePassword) typed again, and the choices: Touch ID again with the new password, and
// whether to refresh the standing copies of the vault file now. The core re-encrypts the file in place (internal/cli: ChangePassword).
//
// The password handling is the one of an unlock and of a new vault: each comes in by one call, the byte copies are wiped after use, nothing is logged or
// put in an answer, and the text of an error never reaches the page. After a change the pending recovery kit is made from the NEW password (the same
// kit steps as a new vault: SaveRecoveryKit, DiscardRecoveryKit), and the copies that still open with the old password are named in the answer.
// The window stays unlocked: the core holds the vault with the new key.

// ChangeInfo is what the page needs to know before it asks.
type ChangeInfo struct {
	Destinations int  // standing copy destinations: the page offers to refresh them when there are any
	TouchIDOn    bool // a Touch ID binding of this vault exists: the change removes it, and the page offers it again
}

// ChangeOutcome is what a change left to say.
type ChangeOutcome struct {
	TouchIDWasOn bool     // the binding of the old password was removed
	Refreshed    []string // the standing destinations that got the new file
	Stale        []string // the files that still open with the OLD password (never deleted)
}

// PasswordChanger is a Core that can replace the master password of its vault. The demo core cannot.
type PasswordChanger interface {
	PasswordInfo() ChangeInfo
	// ChangePassword checks that current opens the vault (ErrWrongPassword when it does not), applies the policy of a new password to next, re-encrypts
	// the vault file in place (the old file stays when anything fails), removes the Touch ID binding of the old password and, when refresh is set,
	// writes the new file to the standing copy destinations. The caller wipes both slices.
	ChangePassword(current, next []byte, refresh bool) (ChangeOutcome, error)
}

// ChangePasswordInfo tells the page whether the open vault can change its password here, and what the dialog should offer.
func (a *App) ChangePasswordInfo() Response {
	c, e := a.store()
	if e != nil {
		return answer(e)
	}
	pc, can := c.(PasswordChanger)
	if !can {
		return ok(map[string]any{"available": false})
	}
	i := pc.PasswordInfo()
	return ok(map[string]any{"available": true, "destinations": i.Destinations, "touchid_on": i.TouchIDOn,
		"touchid_ready": a.o.Maker != nil && a.o.Maker.TouchIDReady(), "min": password.MinLength})
}

// ChangePassword answers {ok, file, touchid: on|off|unavailable|failed, was_touchid, kit: true, refreshed: [folders], stale: [files]}. Every refusal the
// page can decide alone (no current password, the two new ones differ, the policy, the same password) comes before the core is asked, so nothing is
// written. A wrong current password is delayed like a wrong unlock, and the fifth in a row locks the vault.
func (a *App) ChangePassword(current, pw, confirm string, touchID, refresh bool) Response {
	cur, pwb, cb := []byte(current), []byte(pw), []byte(confirm)
	defer wipe(cur)
	defer wipe(pwb)
	defer wipe(cb)
	core, e := a.store()
	if e != nil {
		return answer(e)
	}
	pc, can := core.(PasswordChanger)
	if !can {
		return fail(409, "change_unavailable")
	}
	if len(cur) == 0 || len(cur) > MaxPassword {
		return fail(400, "type_password")
	}
	if subtle.ConstantTimeCompare(pwb, cb) != 1 {
		return fail(400, "new_password_mismatch")
	}
	if s := password.Estimate(pwb); !s.OK {
		return answer(&Error{Status: 400, Code: s.Code, Params: map[string]any{"min": password.MinLength, "max": password.MaxLength, "reason": s.Reason}})
	}
	if subtle.ConstantTimeCompare(cur, pwb) == 1 {
		return fail(400, "change_same_password")
	}
	if !a.changing.TryLock() {
		return fail(409, "change_running")
	}
	defer a.changing.Unlock()
	out, err := pc.ChangePassword(cur, pwb, refresh)
	if err != nil {
		if errors.Is(err, ErrWrongPassword) {
			return a.wrongCurrent()
		}
		a.say("the master password could not be changed")
		return answer(err)
	}
	a.mu.Lock()
	a.changeWrong = 0
	path := a.vault
	a.mu.Unlock()
	a.say("the master password was changed")
	bound := "off"
	if touchID {
		switch {
		case a.o.Maker == nil || !a.o.Maker.TouchIDReady():
			bound = "unavailable"
		case a.o.Maker.TouchIDBind(path, pwb) != nil:
			bound = "failed"
			a.say("the Touch ID binding failed after the password change")
		default:
			bound = "on"
		}
	}
	a.refreshTouchID(path, out.TouchIDWasOn || bound == "on", bound == "on")
	a.dropKit()
	k := &recoveryKit{path: path, label: filepath.Base(path), created: a.o.Clock(), password: append([]byte(nil), pwb...)}
	k.stop = a.o.AfterFunc(kitKeep, func() { a.dropKitIf(k) })
	a.mu.Lock()
	a.kit = k
	a.mu.Unlock()
	return ok(map[string]any{"ok": true, "file": k.label, keyTouchID: bound, "was_touchid": out.TouchIDWasOn, "kit": true,
		"refreshed": nonNil(out.Refreshed), "stale": nonNil(out.Stale)})
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// wrongCurrent is the answer to a wrong current password: delayed, counted, and the fifth in a row locks the vault.
func (a *App) wrongCurrent() Response {
	a.mu.Lock()
	a.changeWrong++
	wrong := a.changeWrong
	a.mu.Unlock()
	a.o.Sleep(WrongDelay)
	if wrong >= MaxWrong {
		a.say("locked (5 wrong current passwords in a row)")
		a.mu.Lock()
		a.changeWrong = 0
		a.mu.Unlock()
		a.lock()
		return fail(423, "locked")
	}
	left := MaxWrong - wrong
	return Response{401, map[string]any{"left": left, keyCode: "change_wrong_password", keyParams: map[string]any{"left": left}}}
}

// refreshTouchID makes the lock screen offer Touch ID only when it opens the vault: the binding of the old password is gone (Binding false), and a new
// one is looked up again (Prepare reads the files).
func (a *App) refreshTouchID(path string, changed, rebound bool) {
	if !changed {
		return
	}
	a.mu.Lock()
	a.cur.Binding, a.cur.Confirm = false, nil
	a.mu.Unlock()
	if rebound && a.o.Vaults != nil {
		if t, err := a.o.Vaults.Prepare(path); err == nil {
			a.mu.Lock()
			a.cur = t
			a.mu.Unlock()
		}
	}
}

// canChangePassword says whether the open vault's core can change its password (the status tells the page to show the button). a.mu is held.
func (a *App) canChangePassword() bool {
	_, can := a.core.(PasswordChanger)
	return a.core != nil && can
}
