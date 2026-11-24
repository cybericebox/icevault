package desktop

import (
	"errors"
	"path/filepath"

	"github.com/cybericebox/icevault/internal/password"
)

// The choice of the vault. The window opens any vault of our kind: the lock screen lists the recent ones (Vaults), opens another through the system
// file dialog, and takes a file macOS hands over (Open With, a double click in Finder). Choosing a vault locks the one that is open first; unlocking a
// vault puts it first in the list. Nothing here reads a vault: a path, a label and a time are all the list holds.

// Target is what the window needs to unlock one vault file.
type Target struct {
	Unlocker Unlocker
	Binding  bool                     // a Touch ID binding exists for this file
	Confirm  func(reason string) bool // the extra Touch ID check; nil when Touch ID is not enabled for it
}

// VaultInfo is a vault as the lock screen shows it.
type VaultInfo struct {
	Path       string `json:"path"`
	Label      string `json:"label"`       // the file name unless the owner named it
	Folder     string `json:"folder"`      // the folder of the file, "~" for the home folder
	Root       string `json:"checkout"`    // the project checkout whose description it uses, "~" for the home folder; "" when not known
	LastOpened string `json:"last_opened"` // RFC 3339; "" when the window has not opened it yet
	Missing    bool   `json:"missing"`     // the file is not there (moved, or on a disk that is not mounted)
}

// Vaults is the list of vaults and what it takes to open one. The window program implements it on vaults.json; the demo keeps it in memory.
type Vaults interface {
	List() []VaultInfo
	// Describe is the VaultInfo of any file (one picked in the dialog is not in the list yet).
	Describe(path string) VaultInfo
	// Prepare finds the project checkout of the file, reads its settings model and makes the Target. Refusals are *Error with a code:
	// vault_missing, vault_needs_root (the page offers the folder dialog), setup_no_model.
	Prepare(path string) (Target, error)
	// DefaultVault is the vault file the project description in the folder root names (the place init-vault uses), for a new vault. Refusals are *Error
	// with a code: vault_bad_root (no description in the folder), setup_no_model (it cannot be read).
	DefaultVault(root string) (string, error)
	// SetNoProject records that the file is used without a project (the lock screen's "Open without a project"): no checkout is asked for any more.
	SetNoProject(path string) error
	// SetRoot names the checkout of a vault (the folder dialog); vault_bad_root when the folder has no project description.
	SetRoot(path, root string) error
	// Opened records that the file was unlocked: it goes first in the list.
	Opened(path string) error
	// Forget drops the file from the list. The file is never touched.
	Forget(path string) error
}

// Picker shows the system dialog: kind "file" (a .kdbx file) or "folder" (an project checkout), with the title the page translated. "" when
// the person cancelled.
type Picker func(kind, title string) (string, error)

// EventVaultSelected is the event the page gets when a vault was chosen from outside the page (Open With); its data is {"path": p}.
const EventVaultSelected = "vault-selected"

func (a *App) target() Target {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cur
}

// selectVault chooses path. The vault that is open is locked first, unless it is the same file. The problem (a checkout to name, a missing
// file) is kept for the lock screen; the choice stands either way, so the page can offer what fixes it.
func (a *App) selectVault(path string) Response {
	if a.o.Vaults == nil {
		return fail(409, "vaults_off")
	}
	if path == "" || !filepath.IsAbs(path) {
		return fail(400, "bad_request")
	}
	path = filepath.Clean(path)
	a.mu.Lock()
	same := a.vault == path && a.core != nil
	a.mu.Unlock()
	if same {
		return ok(map[string]any{"ok": true, "unlocked": true})
	}
	if !a.unlocking.TryLock() { // an unlock of the vault chosen before is on its way: it must not attach to this one
		return fail(409, "unlock_running")
	}
	defer a.unlocking.Unlock()
	a.lock()
	t, err := a.o.Vaults.Prepare(path)
	a.mu.Lock()
	a.vault = path
	if err != nil {
		a.cur, a.problem = Target{}, err
	} else {
		a.cur, a.problem = t, nil
	}
	a.mu.Unlock()
	if err != nil {
		r := answer(err)
		return Response{200, map[string]any{"ok": false, "problem": r.Data}}
	}
	return ok(map[string]any{"ok": true})
}

// SelectVault chooses a vault of the list (or any file the page names); the open one is locked first.
func (a *App) SelectVault(path string) Response { return a.selectVault(path) }

// OpenFile is the file macOS handed over (Open With, a double click): it is chosen on the lock screen and the page is told. A function, not a
// method: the page has SelectVault for its own choices.
func OpenFile(a *App, path string) {
	r := a.selectVault(path)
	if r.Status == 200 && a.o.Notify != nil {
		a.o.Notify(EventVaultSelected, map[string]any{"path": filepath.Clean(path)})
	}
}

// OpenVault shows the system file dialog (.kdbx) and chooses the file picked; {cancelled: true} when none was.
func (a *App) OpenVault(title string) Response {
	if a.o.Vaults == nil {
		return fail(409, "vaults_off")
	}
	if a.o.Pick == nil {
		return fail(409, "pick_unavailable")
	}
	p, err := a.o.Pick("file", title)
	if err != nil {
		return fail(500, "pick_failed")
	}
	if p == "" {
		return ok(cancelledAnswer())
	}
	return a.selectVault(p)
}

// UseWithoutProject is the answer to a vault that lies in no project: it is opened without one (no environments, only the shared secrets, the connections and
// the other secrets), and no checkout is asked for any more. The vault chosen is prepared again.
func (a *App) UseWithoutProject() Response {
	if a.o.Vaults == nil {
		return fail(409, "vaults_off")
	}
	a.mu.Lock()
	path, problem := a.vault, a.problem
	a.mu.Unlock()
	if path == "" {
		return fail(409, "no_vault_chosen")
	}
	// only the question about a checkout is answered this way: a vault that has its project, or one that fails for another reason, is left as it is
	var pe *Error
	if !errors.As(problem, &pe) || pe.Code != "vault_needs_root" {
		return fail(409, "no_project_refused")
	}
	if err := a.o.Vaults.SetNoProject(path); err != nil {
		return answer(err)
	}
	return a.selectVault(path)
}

// ChooseRoot shows the folder dialog for the project checkout of the chosen vault, saves it and prepares the vault again.
func (a *App) ChooseRoot(title string) Response {
	if a.o.Vaults == nil {
		return fail(409, "vaults_off")
	}
	a.mu.Lock()
	path := a.vault
	a.mu.Unlock()
	if path == "" {
		return fail(409, "no_vault_chosen")
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
	if err := a.o.Vaults.SetRoot(path, dir); err != nil {
		return answer(err)
	}
	return a.selectVault(path)
}

// ChooseProject shows the system file dialog for the project description (.yaml, .yml) and hands the file picked to the open vault's core, which
// reads it once and remembers its path (op m-project); {cancelled: true} when none was picked. The page never names the path itself.
func (a *App) ChooseProject(title string) Response {
	c, r := a.editing()
	if r != nil {
		return *r
	}
	if a.o.PickDescription == nil {
		return fail(409, "pick_unavailable")
	}
	p, err := a.o.PickDescription(title)
	if err != nil {
		return fail(500, "pick_failed")
	}
	if p == "" {
		return ok(cancelledAnswer())
	}
	data, err := c.Write("m-project", map[string]any{"path": p})
	if err != nil {
		return answer(err)
	}
	if data == nil {
		data = map[string]any{"ok": true}
	}
	return ok(data)
}

// ForgetVault removes a vault from the list (the page asked with its confirmation box first). The file stays where it is.
func (a *App) ForgetVault(path string) Response {
	if a.o.Vaults == nil {
		return fail(409, "vaults_off")
	}
	if err := a.o.Vaults.Forget(filepath.Clean(path)); err != nil {
		return answer(err)
	}
	return a.ListVaults()
}

// ListVaults answers the recent vaults (most recent first), the chosen one and what stops it from being unlocked.
func (a *App) ListVaults() Response {
	if a.o.Vaults == nil {
		return ok(map[string]any{"enabled": false, "vaults": []VaultInfo{}, "current": nil, "problem": nil, "can_pick": false, "can_create": false})
	}
	list := a.o.Vaults.List()
	if list == nil {
		list = []VaultInfo{}
	}
	a.mu.Lock()
	path, problem := a.vault, a.problem
	a.mu.Unlock()
	var cur any
	if path != "" {
		cur = a.o.Vaults.Describe(path)
	}
	var pr any
	if problem != nil {
		pr = answer(problem).Data
	}
	return ok(map[string]any{"enabled": true, "vaults": list, "current": cur, "problem": pr, "can_pick": a.o.Pick != nil, "can_create": a.canCreate(), "min_password": password.MinLength})
}

// opened records a successful unlock in the list; a list that cannot be saved does not stop the window.
func (a *App) opened() {
	if a.o.Vaults == nil {
		return
	}
	a.mu.Lock()
	path := a.vault
	a.mu.Unlock()
	if path == "" {
		return
	}
	if err := a.o.Vaults.Opened(path); err != nil {
		a.say("the list of vaults was not saved")
	}
}

// errNoVault is the answer to an unlock while no vault is chosen (or the chosen one cannot be opened: its problem is the answer then).
func (a *App) noTarget() (Response, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cur.Unlocker != nil {
		return Response{}, false
	}
	if a.problem != nil {
		return answer(a.problem), true
	}
	if a.o.Vaults != nil {
		return fail(409, "no_vault_chosen"), true
	}
	return fail(400, "bad_request"), true
}
