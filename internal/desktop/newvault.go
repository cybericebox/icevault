package desktop

import (
	"crypto/subtle"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cybericebox/icevault/internal/password"
)

// A new vault, made from the lock screen. The page asks, step by step: the project folder (the folder with icevault-project.yaml, the system folder dialog),
// the place (the file the project description names, offered at once; the system save dialog to choose another), a password (typed, with the live meter of
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
	Create(path string, password []byte, noProject bool) error
	// TouchIDReady says whether a Touch ID binding can be made here (the platform, and age and age-plugin-se installed).
	TouchIDReady() bool
	// TouchIDBind keeps the password of the vault just made behind Touch ID.
	TouchIDBind(path string, password []byte) error
}

// SavePicker shows the system save dialog with the title the page translated, the folder it opens in ("" for the system's choice) and a suggested file
// name; "" when the person cancelled.
type SavePicker func(title, dir, name string) (string, error)

const (
	defaultVaultFile = "IceVault.kdbx"  // the name the save dialog suggests when no project names one
	kitKeep          = 15 * time.Minute // how long the password waits for the recovery kit
	maxKitText       = 8 << 10
)

// The password of the new vault reaches CreateVault as a Go string (the bridge's type), which cannot be wiped; the byte copies made here are wiped,
// and the kit keeps the password as bytes.

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
	m := map[string]any{"level": s.Level, "ok": s.OK, "length": s.Length, "min": password.MinLength, "max": password.MaxLength, "max_level": password.MaxLevel}
	if !s.OK {
		m[keyCode] = s.Code
		m["reason"] = s.Reason
	}
	return m
}

// PasswordStrength judges a password typed for a new vault, for the meter of the page: level 0 to max_level, ok when the policy accepts it, and the
// reason when it does not. It keeps nothing.
// One estimate runs at a time (the page also keeps one call in flight, latest wins). The password arrives as a Go string, which cannot be wiped; the
// byte copy made here is.
func (a *App) PasswordStrength(pw string) Response {
	a.strength.Lock()
	defer a.strength.Unlock()
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
	a.mu.Lock()
	root, loose, cur, def := a.newRoot, a.newNoProj, a.newPath, a.newDefault
	a.mu.Unlock()
	if root == "" && !loose {
		return fail(409, "new_no_project")
	}
	if cur == "" {
		cur = def
	}
	dir, name := "", defaultVaultFile // without a project the system's folder and a plain name
	if cur != "" {
		dir, name = nearestDir(filepath.Dir(cur)), filepath.Base(cur)
	}
	p, err := a.o.PickSave(title, dir, name)
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
	return ok(map[string]any{"file": filepath.Base(p), "folder": d.Folder, keyTouchID: a.o.Maker.TouchIDReady()})
}

// nearestDir is dir, or the nearest folder above it that exists: the save dialog opens there (the folder of the description may not be made yet).
func nearestDir(dir string) string {
	for d := dir; ; d = filepath.Dir(d) {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
		if filepath.Dir(d) == d {
			return ""
		}
	}
}

// NewVaultNoProject is the other first step: a vault without a project (no folder, no description; it has no environments, only the shared secrets, the
// connections and the other secrets). The place is then chosen with the save dialog. Answer: {touchid}.
func (a *App) NewVaultNoProject() Response {
	if !a.canCreate() {
		return fail(409, "new_unavailable")
	}
	a.mu.Lock()
	a.newRoot, a.newNoProj, a.newDefault, a.newPath = "", true, "", ""
	a.mu.Unlock()
	return ok(map[string]any{keyTouchID: a.o.Maker.TouchIDReady()})
}

// NewVaultProject is the first step: the system folder dialog for the project folder (the one with icevault-project.yaml). The vault file the
// description names becomes the place at once (the page shows it; NewVaultPlace chooses another). {cancelled: true} when no folder was chosen. The answer:
// {checkout, file, folder, exists, touchid}; exists says that the file of the description is there already (no place is set then).
func (a *App) NewVaultProject(title string) Response {
	if !a.canCreate() {
		return fail(409, "new_unavailable")
	}
	if a.o.Pick == nil {
		return fail(409, "pick_unavailable")
	}
	dir, err := a.o.Pick("folder", title)
	if err != nil {
		return fail(500, "pick_failed")
	}
	if dir == "" {
		return ok(cancelledAnswer())
	}
	if !filepath.IsAbs(dir) {
		return fail(400, "bad_request")
	}
	dir = filepath.Clean(dir)
	def, err := a.o.Vaults.DefaultVault(dir)
	if err != nil {
		return answer(err)
	}
	_, statErr := os.Lstat(def)
	exists := statErr == nil
	a.mu.Lock()
	a.newRoot, a.newNoProj, a.newDefault, a.newPath = dir, false, def, ""
	if !exists {
		a.newPath = def
	}
	a.mu.Unlock()
	d := a.o.Vaults.Describe(def)
	return ok(map[string]any{"checkout": d.Root, "file": filepath.Base(def), "folder": d.Folder, "exists": exists, keyTouchID: a.o.Maker.TouchIDReady()})
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
	path, root, loose := a.newPath, a.newRoot, a.newNoProj
	a.mu.Unlock()
	if root == "" && !loose {
		return fail(409, "new_no_project")
	}
	if path == "" {
		return fail(409, "new_no_place")
	}
	if subtle.ConstantTimeCompare(pwb, cb) != 1 {
		return fail(400, "new_password_mismatch")
	}
	if s := password.Estimate(pwb); !s.OK {
		return answer(&Error{Status: 400, Code: s.Code, Params: map[string]any{"min": password.MinLength, "max": password.MaxLength, "reason": s.Reason}})
	}
	if _, err := os.Lstat(path); err == nil {
		return fail(409, "vault_exists")
	}
	if err := a.o.Maker.Create(path, pwb, loose); err != nil {
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
	a.newPath, a.newRoot, a.newDefault, a.newNoProj = "", "", "", false
	a.mu.Unlock()
	// the vault opens with the project folder that was chosen, wherever the file was saved: no question about a checkout on the lock screen (a vault
	// made without a project was marked when it was made, and has no checkout)
	if root != "" {
		if err := a.o.Vaults.SetRoot(path, root); err != nil {
			a.say("the project folder of the new vault was not recorded")
		}
	}
	// the new vault is the chosen one on the lock screen (a file it cannot prepare yet, for want of a checkout, shows what to do there)
	a.selectVault(path)
	// the new vault is in the recent list at once, marked as not opened yet; its first unlock sets the time
	if err := a.o.Vaults.Added(path); err != nil {
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
	p, err := a.o.PickSave(title, "", strings.TrimSuffix(k.label, filepath.Ext(k.label))+"-recovery.txt")
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
	body := expandKit(template, map[string][]byte{"name": []byte(k.label), "path": []byte(k.path), "created": []byte(k.created.Format("2006-01-02 15:04")), "password": k.password})
	werr := writeKit(p, body) // wipes body
	if werr != nil {
		a.say("the recovery kit could not be saved")
		return fail(500, "kit_not_saved")
	}
	a.say("the recovery kit was saved")
	same := filepath.Dir(p) == filepath.Dir(k.path)
	a.dropKit()
	return ok(map[string]any{"ok": true, "same_folder": same})
}

// expandKit fills the {name}, {path}, {created} and {password} of the template in one pass over it, as bytes, so that a value that looks like a
// placeholder is never expanded again and the password is in no string made here. The exact size is computed first and the result allocated once:
// an append that outgrew its buffer would leave an old copy of the password on the heap that nothing can wipe. The caller wipes the result.
func expandKit(template string, vals map[string][]byte) []byte {
	size := 0
	kitWalk(template, vals, func(lit string, v []byte) { size += len(lit) + len(v) })
	out := make([]byte, 0, size)
	kitWalk(template, vals, func(lit string, v []byte) { out = append(append(out, lit...), v...) })
	return out
}

// kitWalk splits the template into runs of literal text, each followed by the value of the placeholder that ends it (nil at the end or for a
// brace that is no known placeholder, which stays literal).
func kitWalk(template string, vals map[string][]byte, emit func(lit string, v []byte)) {
	start := 0
	for i := 0; i < len(template); {
		if template[i] == '{' {
			if j := strings.IndexByte(template[i:], '}'); j > 0 {
				if v, found := vals[template[i+1:i+j]]; found {
					emit(template[start:i], v)
					i += j + 1
					start = i
					continue
				}
			}
		}
		i++
	}
	emit(template[start:], nil)
}

// writeKit writes the file with mode 0600 before the first byte goes in: an existing file the person chose to replace (a world readable one, say) is
// emptied and made 0600 first, and a symbolic link is refused (O_NOFOLLOW). A failed write leaves no partial file. It wipes b.
func writeKit(p string, b []byte) error { return writeKitWith(p, b, nil) }

// writeKitWith is writeKit with a hook that runs after the mode is set and before the first write (tests look at the file there).
func writeKitWith(p string, b []byte, beforeWrite func(f *os.File)) (err error) {
	defer wipe(b)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|noFollow, 0o600) // #nosec G304 -- the place is the one the person chose in the save dialog
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(p)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return err
	}
	if beforeWrite != nil {
		beforeWrite(f)
	}
	_, err = f.Write(b)
	return err
}

// DiscardRecoveryKit drops the pending kit: the person does not want one.
func (a *App) DiscardRecoveryKit() Response {
	a.dropKit()
	return ok(map[string]any{"ok": true})
}
