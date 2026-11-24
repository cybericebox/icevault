package desktop

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// fakeVaults is a list of vaults in memory; a file is opened by the Unlocker named for it (default: a MemoryUnlocker with password "pw").
type fakeVaults struct {
	mu                             sync.Mutex
	list                           []VaultInfo
	unlockers                      map[string]Unlocker
	roots                          map[string]string
	needRoot                       map[string]bool
	opened, added, forgotten       []string
	prepareErr, rootErr, forgetErr error
	defaultErr                     error
	noProject                      map[string]bool
	noProjectErr                   error
	defaults                       map[string]string
}

func (f *fakeVaults) List() []VaultInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]VaultInfo(nil), f.list...)
}
func (f *fakeVaults) Describe(p string) VaultInfo {
	return VaultInfo{Path: p, Label: filepath.Base(p), Folder: filepath.Dir(p)}
}
func (f *fakeVaults) Prepare(p string) (Target, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.prepareErr != nil {
		return Target{}, f.prepareErr
	}
	if f.needRoot[p] && f.roots[p] == "" && !f.noProject[p] {
		return Target{}, &Error{Status: 409, Code: "vault_needs_root"}
	}
	if u := f.unlockers[p]; u != nil {
		return Target{Unlocker: u}, nil
	}
	return Target{Unlocker: &MemoryUnlocker{Password: "pw"}}, nil
}

// SetNoProject marks the file as one used without a project: Prepare then no longer asks for a checkout.
func (f *fakeVaults) SetNoProject(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noProjectErr != nil {
		return f.noProjectErr
	}
	if f.noProject == nil {
		f.noProject = map[string]bool{}
	}
	f.noProject[p] = true
	return nil
}

// DefaultVault: <root>/plain/vault/v.kdbx unless a default is named for the root; defaultErr refuses.
func (f *fakeVaults) DefaultVault(root string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.defaultErr != nil {
		return "", f.defaultErr
	}
	if p := f.defaults[root]; p != "" {
		return p, nil
	}
	return filepath.Join(root, "plain", "vault", "v.kdbx"), nil
}
func (f *fakeVaults) SetRoot(p, root string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rootErr != nil {
		return f.rootErr
	}
	if f.roots == nil {
		f.roots = map[string]string{}
	}
	f.roots[p] = root
	return nil
}
func (f *fakeVaults) Added(p string) error {
	f.mu.Lock()
	f.added = append(f.added, p)
	f.mu.Unlock()
	return nil
}
func (f *fakeVaults) Opened(p string) error {
	f.mu.Lock()
	f.opened = append(f.opened, p)
	f.mu.Unlock()
	return nil
}
func (f *fakeVaults) Forget(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forgetErr != nil {
		return f.forgetErr
	}
	f.forgotten = append(f.forgotten, p)
	return nil
}

// foreignUnlocker opens with the right password but refuses the file: not a vault of ours.
type foreignUnlocker struct{}

func (foreignUnlocker) Open([]byte) (Core, error) {
	return nil, &Error{Status: 409, Code: "vault_foreign"}
}
func (foreignUnlocker) Touch() ([]byte, error) { return nil, nil }
func (foreignUnlocker) HasKeyFile() bool       { return false }

func statusOf(t *testing.T, a *App) map[string]any {
	t.Helper()
	return a.Status().Data.(map[string]any)
}

// The vault chosen at the start is unlocked and goes first in the list; choosing another one locks the open one first; the same one stays open.
func TestChoosingAVault(t *testing.T) {
	fv := &fakeVaults{}
	a := New(Options{Vaults: fv, Vault: "/v/a.kdbx"})
	if st := statusOf(t, a); st["vault"] != "/v/a.kdbx" || st["vaults"] != true || st["locked"] != true {
		t.Fatalf("status: %v", st)
	}
	if r := a.Unlock("password", "pw"); r.Status != 200 {
		t.Fatalf("unlock: %+v", r)
	}
	if len(fv.opened) != 1 || fv.opened[0] != "/v/a.kdbx" {
		t.Fatalf("opened: %v", fv.opened)
	}
	core := a.core.(*MemoryCore)
	if r := a.SelectVault("/v/a.kdbx"); r.Status != 200 || statusOf(t, a)["locked"] != false {
		t.Fatalf("the same vault again must stay open: %+v", r)
	}
	if r := a.SelectVault("/v/b.kdbx"); r.Status != 200 || r.Data.(map[string]any)["ok"] != true {
		t.Fatalf("select b: %+v", r)
	}
	if !core.Locked || statusOf(t, a)["locked"] != true || statusOf(t, a)["vault"] != "/v/b.kdbx" {
		t.Fatal("switching must lock the vault that was open")
	}
	if r := a.SelectVault("relative.kdbx"); r.Status != 400 {
		t.Fatalf("a relative path: %+v", r)
	}
	lv := a.ListVaults().Data.(map[string]any)
	if lv["enabled"] != true || lv["current"].(VaultInfo).Path != "/v/b.kdbx" || lv["problem"] != nil || lv["can_pick"] != false {
		t.Fatalf("list: %+v", lv)
	}
}

// A file that is not a vault of ours is refused after the unlock and never enters the list.
func TestForeignVaultIsNotListed(t *testing.T) {
	fv := &fakeVaults{unlockers: map[string]Unlocker{"/v/keepass.kdbx": foreignUnlocker{}}}
	a := New(Options{Vaults: fv, Vault: "/v/keepass.kdbx"})
	r := a.Unlock("password", "pw")
	if r.Status != 409 || r.Data.(map[string]any)["code"] != "vault_foreign" {
		t.Fatalf("foreign: %+v", r)
	}
	if len(fv.opened) != 0 || statusOf(t, a)["locked"] != true {
		t.Fatalf("a foreign vault was recorded: %v", fv.opened)
	}
}

// No vault chosen: the unlock says so. A vault whose checkout is not known: the problem is kept, the folder dialog names it, then it unlocks.
func TestVaultProblemsAndTheFolderDialog(t *testing.T) {
	fv := &fakeVaults{needRoot: map[string]bool{"/x/loose.kdbx": true}}
	picks := []string{}
	next := ""
	a := New(Options{Vaults: fv, Pick: func(kind, _ string) (string, error) { picks = append(picks, kind); return next, nil }})
	if r := a.Unlock("password", "pw"); r.Status != 409 || r.Data.(map[string]any)["code"] != "no_vault_chosen" {
		t.Fatalf("nothing chosen: %+v", r)
	}
	if r := a.OpenVault("t"); r.Status != 200 || r.Data.(map[string]any)["cancelled"] != true {
		t.Fatalf("cancelled dialog: %+v", r)
	}
	next = "/x/loose.kdbx"
	r := a.OpenVault("t")
	if r.Status != 200 || r.Data.(map[string]any)["ok"] != false {
		t.Fatalf("picked: %+v", r)
	}
	if p := r.Data.(map[string]any)["problem"].(map[string]any); p["code"] != "vault_needs_root" {
		t.Fatalf("problem: %+v", p)
	}
	if lv := a.ListVaults().Data.(map[string]any); lv["problem"].(map[string]any)["code"] != "vault_needs_root" {
		t.Fatalf("the list must carry the problem: %+v", lv)
	}
	if r := a.Unlock("password", "pw"); r.Data.(map[string]any)["code"] != "vault_needs_root" {
		t.Fatalf("unlock with the problem: %+v", r)
	}
	next = "/x/checkout"
	if r := a.ChooseRoot("t"); r.Status != 200 || r.Data.(map[string]any)["ok"] != true {
		t.Fatalf("choose root: %+v", r)
	}
	if fv.roots["/x/loose.kdbx"] != "/x/checkout" || len(picks) != 3 || picks[2] != "folder" || picks[0] != "file" {
		t.Fatalf("roots %v picks %v", fv.roots, picks)
	}
	if r := a.Unlock("password", "pw"); r.Status != 200 {
		t.Fatalf("unlock after the folder: %+v", r)
	}
	fv.rootErr = &Error{Status: 409, Code: "vault_bad_root"}
	if r := a.ChooseRoot("t"); r.Status != 409 || r.Data.(map[string]any)["code"] != "vault_bad_root" {
		t.Fatalf("a folder that is not a checkout: %+v", r)
	}
	if r := a.ForgetVault("/x/loose.kdbx"); r.Status != 200 || len(fv.forgotten) != 1 {
		t.Fatalf("forget: %+v %v", r, fv.forgotten)
	}
	if r := (New(Options{Vaults: fv})).OpenVault("t"); r.Status != 409 || r.Data.(map[string]any)["code"] != "pick_unavailable" {
		t.Fatalf("no dialogs: %+v", r)
	}
	if r := (New(Options{Vaults: fv, Pick: func(string, string) (string, error) { return "", errors.New("x") }})).OpenVault("t"); r.Data.(map[string]any)["code"] != "pick_failed" {
		t.Fatalf("a failing dialog: %+v", r)
	}
}

// A file macOS hands over is chosen on the lock screen (the open vault is locked) and the page is told.
func TestOpenFileFromTheSystem(t *testing.T) {
	var events []string
	fv := &fakeVaults{}
	a := New(Options{Vaults: fv, Vault: "/v/a.kdbx", Notify: func(ev string, data any) {
		p, _ := data.(map[string]any)["path"].(string)
		events = append(events, ev+" "+p)
	}})
	if r := a.Unlock("password", "pw"); r.Status != 200 {
		t.Fatal(r)
	}
	OpenFile(a, "/v/other.kdbx")
	if statusOf(t, a)["locked"] != true || statusOf(t, a)["vault"] != "/v/other.kdbx" {
		t.Fatal("the handed-over file must be chosen, locked")
	}
	if len(events) != 2 || events[0] != EventVaultLocked+" " || events[1] != EventVaultSelected+" /v/other.kdbx" {
		t.Fatalf("events: %v", events)
	}
	OpenFile(a, "not/absolute")
	if len(events) != 2 {
		t.Fatal("a bad path must not be announced")
	}
}
