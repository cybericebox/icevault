package desktop

import (
	"crypto/subtle"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cybericebox/icevault/internal/password"
)

// A new vault, made from the lock screen. The page asks, step by step: a place (the system save dialog), a password (typed, with the live meter of
// PasswordStrength, or made by GeneratePassword) typed again to confirm, and the choices (Touch ID). CreateVault then makes the file under the policy of
// internal/password, the same one init-vault applies. The page never names a path: the place is the one the save dialog returned and stays here.
//
// The password is handled like the one of an unlock: it comes in by one call, the byte copy is wiped after use, it is never logged or put in an answer.
// One exception is the recovery kit: a text file the person may save to a place of their choice (the save dialog again), made from the password that
// created the vault. It is the only time the window writes the password anywhere. Until the kit is saved or dropped, this one password stays in
// memory (wiped when it is saved, dropped, the vault is locked, another vault is made, or after kitKeep).

// VaultMaker makes vault files and Touch ID bindings (internal/cli in the window program).
type VaultMaker interface {
	// Create makes the vault file at path (the file does not exist, the password passed the policy).
	Create(path string, password []byte) error
	// TouchIDReady says whether a Touch ID binding can be made here (the platform, and age and age-plugin-se installed).
	TouchIDReady() bool
	// TouchIDBind keeps the password of the vault just made behind Touch ID.
	TouchIDBind(path string, password []byte) error
}

// SavePicker shows the system save dialog with the title the page translated and a suggested file name; "" when the person cancelled.
type SavePicker func(title, name string) (string, error)

const (
	defaultVaultFile = "IceVault.kdbx"
	kitKeep          = 15 * time.Minute // how long the password waits for the recovery kit
	maxKitText       = 8 << 10
)

// recoveryKit is what the kit file is made from.
type recoveryKit struct {
	path     string // the vault file
	label    string // its name for the person: the file name
	created  time.Time
	password []byte
	stop     func() // the timer that drops it
}

func (k *recoveryKit) wipe() {
	if k.stop != nil {
		k.stop()
	}
	wipe(k.password)
}

// cancelledAnswer is the data of a dialog the person closed without choosing.
func cancelledAnswer() map[string]any { return map[string]any{"cancelled": true} }

func (a *App) canCreate() bool { return a.o.Maker != nil && a.o.PickSave != nil && a.o.Vaults != nil }

// dropKit forgets the pending recovery kit and wipes its password.
func (a *App) dropKit() {
	a.mu.Lock()
	k := a.kit
	a.kit = nil
	a.mu.Unlock()
	if k != nil {
		k.wipe()
	}
}

func strengthAnswer(s password.Strength) map[string]any {
	m := map[string]any{"level": s.Level, "ok": s.OK, "length": s.Length, "min": password.MinLength, "max_level": password.MaxLevel}
	if !s.OK {
		m[keyCode] = s.Code
		m["reason"] = s.Reason
	}
	return m
}

// PasswordStrength judges a password typed for a new vault, for the meter of the page: level 0 to max_level, ok when the policy accepts it, and the
// reason when it does not. It keeps nothing.
func (a *App) PasswordStrength(pw string) Response {
	b := []byte(pw)
	defer wipe(b)
	return ok(strengthAnswer(password.Estimate(b)))
}

// GeneratePassword makes a passphrase of six random words that the policy accepts (the page shows it in the field; the person types it again).
func (a *App) GeneratePassword() Response {
	p, err := password.Passphrase()
	if err != nil {
		return answer(&Error{Status: 500, Code: "new_failed"})
	}
	return ok(map[string]any{keyPassword: p})
}

// NewVaultPlace shows the save dialog for the new vault file and keeps the answer. {cancelled: true} when none was given.
func (a *App) NewVaultPlace(title string) Response {
	if !a.canCreate() {
		return fail(409, "new_unavailable")
	}
	p, err := a.o.PickSave(title, defaultVaultFile)
	if err != nil {
		return fail(500, "pick_failed")
	}
	if p == "" {
		return ok(cancelledAnswer())
	}
	if !filepath.IsAbs(p) {
		return fail(400, "bad_request")
	}
	p = filepath.Clean(p)
	if !strings.EqualFold(filepath.Ext(p), ".kdbx") {
		p += ".kdbx"
	}
	if _, err := os.Lstat(p); err == nil {
		return fail(409, "vault_exists") // never overwritten, whatever the dialog let the person choose
	}
	a.mu.Lock()
	a.newPath = p
	a.mu.Unlock()
	d := a.o.Vaults.Describe(p)
	return ok(map[string]any{"file": filepath.Base(p), "folder": d.Folder, "touchid": a.o.Maker.TouchIDReady()})
}

// CreateVault makes the vault at the chosen place. The password must be typed again (confirm) and pass the policy; nothing is written otherwise.
// touchID asks for the binding too. Then the new vault is chosen on the lock screen and listed first. Answer: {ok, file, touchid: on|off|unavailable|failed,
// kit: true}.
func (a *App) CreateVault(pw, confirm string, touchID bool) Response {
	pwb, cb := []byte(pw), []byte(confirm)
	defer wipe(pwb)
	defer wipe(cb)
	if !a.canCreate() {
		return fail(409, "new_unavailable")
	}
	a.mu.Lock()
	path := a.newPath
	a.mu.Unlock()
	if path == "" {
		return fail(409, "new_no_place")
	}
	if subtle.ConstantTimeCompare(pwb, cb) != 1 {
		return fail(400, "new_password_mismatch")
	}
	if s := password.Estimate(pwb); !s.OK {
		return answer(&Error{Status: 400, Code: s.Code, Params: map[string]any{"min": password.MinLength, "reason": s.Reason}})
	}
	if _, err := os.Lstat(path); err == nil {
		return fail(409, "vault_exists")
	}
	if err := a.o.Maker.Create(path, pwb); err != nil {
		a.say("the new vault could not be made")
		return fail(500, "new_failed")
	}
	a.say("a new vault was made")
	bound := "off"
	if touchID {
		switch {
		case !a.o.Maker.TouchIDReady():
			bound = "unavailable"
		case a.o.Maker.TouchIDBind(path, pwb) != nil:
			bound = "failed"
			a.say("the Touch ID binding of the new vault failed")
		default:
			bound = "on"
		}
	}
	a.dropKit()
	a.mu.Lock()
	a.newPath = ""
	a.mu.Unlock()
	// the new vault is the chosen one on the lock screen (a file it cannot prepare yet, for want of a checkout, shows what to do there)
	a.selectVault(path)
	if err := a.o.Vaults.Opened(path); err != nil {
		a.say("the list of vaults was not saved")
	}
	k := &recoveryKit{path: path, label: filepath.Base(path), created: a.o.Clock(), password: append([]byte(nil), pwb...)}
	k.stop = a.o.AfterFunc(kitKeep, func() { a.dropKitIf(k) })
	a.mu.Lock()
	a.kit = k
	a.mu.Unlock()
	return ok(map[string]any{"ok": true, "file": k.label, "touchid": bound, "kit": true})
}

func (a *App) dropKitIf(k *recoveryKit) {
	a.mu.Lock()
	same := a.kit == k
	if same {
		a.kit = nil
	}
	a.mu.Unlock()
	if same {
		wipe(k.password)
	}
}

// SaveRecoveryKit asks where (the save dialog) and writes the kit there, mode 0600: the vault's name and path, the date, the password and the line the
// page sends in template (its words are the page's, translated). The template names {name}, {path}, {created} and {password}. {cancelled: true} when no
// place was given: the kit stays pending. The answer says whether the file lies in the folder of the vault (the page warns then).
func (a *App) SaveRecoveryKit(title, template string) Response {
	a.mu.Lock()
	k := a.kit
	a.mu.Unlock()
	if k == nil {
		return fail(409, "kit_none")
	}
	if a.o.PickSave == nil {
		return fail(409, "pick_unavailable")
	}
	if len(template) > maxKitText || !strings.Contains(template, "{password}") {
		return fail(400, "bad_request")
	}
	p, err := a.o.PickSave(title, strings.TrimSuffix(k.label, filepath.Ext(k.label))+"-recovery.txt")
	if err != nil {
		return fail(500, "pick_failed")
	}
	if p == "" {
		return ok(cancelledAnswer())
	}
	if !filepath.IsAbs(p) {
		return fail(400, "bad_request")
	}
	p = filepath.Clean(p)
	if p == k.path {
		return fail(409, "kit_same_file")
	}
	body := strings.NewReplacer("{name}", k.label, "{path}", k.path, "{created}", k.created.Format("2006-01-02 15:04"), "{password}", string(k.password)).Replace(template)
	werr := writeKit(p, []byte(body))
	if werr != nil {
		a.say("the recovery kit could not be saved")
		return fail(500, "kit_not_saved")
	}
	a.say("the recovery kit was saved")
	same := filepath.Dir(p) == filepath.Dir(k.path)
	a.dropKit()
	return ok(map[string]any{"ok": true, "same_folder": same})
}

// writeKit writes the file with mode 0600 from the first byte (an existing file the person chose to replace gets the mode too).
func writeKit(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the place is the one the person chose in the save dialog
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	wipe(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(p, 0o600)
	}
	return err
}

// DiscardRecoveryKit drops the pending kit: the person does not want one.
func (a *App) DiscardRecoveryKit() Response {
	a.dropKit()
	return ok(map[string]any{"ok": true})
}
