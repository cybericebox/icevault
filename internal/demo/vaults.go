package demo

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/cybericebox/icevault/internal/desktop"
)

// Vaults is the list of recent vaults of the demo: made-up entries in memory (one of them on a disk that is not there), all opening the demo vault.
// It never reads or writes vaults.json.
type Vaults struct {
	mu   sync.Mutex
	u    desktop.Unlocker
	list []desktop.VaultInfo
	now  func() time.Time
}

// demoHome stands in for the home folder in the paths of the sample list.
const demoHome = "/Users/demo"

// NewVaults is the sample list; First is the vault chosen at the start.
func NewVaults(u desktop.Unlocker, now func() time.Time) *Vaults {
	t := now().UTC()
	at := func(d time.Duration) string { return t.Add(-d).Format(time.RFC3339) }
	return &Vaults{u: u, now: now, list: []desktop.VaultInfo{
		{Path: demoHome + "/Projects/lumen-notes/secrets/vault/lumen.kdbx", Label: "lumen.kdbx", Folder: "~/Projects/lumen-notes/secrets/vault",
			Root: "~/Projects/lumen-notes", LastOpened: at(2 * time.Hour)},
		{Path: demoHome + "/Backups/IceVault/lumen-copy.kdbx", Label: "lumen-copy.kdbx", Folder: "~/Backups/IceVault",
			Root: "~/Projects/lumen-notes", LastOpened: at(3 * 24 * time.Hour)},
		{Path: "/Volumes/Team/vaults/team.kdbx", Label: "team.kdbx", Folder: "/Volumes/Team/vaults", LastOpened: at(24 * 24 * time.Hour), Missing: true},
	}}
}

// First is the newest vault of the list.
func (v *Vaults) First() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.list) == 0 {
		return ""
	}
	return v.list[0].Path
}

func (v *Vaults) find(path string) int {
	for i, x := range v.list {
		if x.Path == path {
			return i
		}
	}
	return -1
}

func (v *Vaults) List() []desktop.VaultInfo {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]desktop.VaultInfo(nil), v.list...)
}

func (v *Vaults) Describe(path string) desktop.VaultInfo {
	v.mu.Lock()
	defer v.mu.Unlock()
	if i := v.find(path); i >= 0 {
		return v.list[i]
	}
	return desktop.VaultInfo{Path: path, Label: filepath.Base(path), Folder: filepath.Dir(path)}
}

func (v *Vaults) Prepare(path string) (desktop.Target, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.find(path)
	if i < 0 {
		return desktop.Target{}, &desktop.Error{Status: 409, Code: "demo_only"}
	}
	if v.list[i].Missing {
		return desktop.Target{}, &desktop.Error{Status: 409, Code: "vault_missing"}
	}
	return desktop.Target{Unlocker: v.u}, nil
}

func (v *Vaults) SetRoot(string, string) error { return nil }

func (v *Vaults) Opened(path string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.find(path)
	if i < 0 {
		return nil
	}
	e := v.list[i]
	e.LastOpened = v.now().UTC().Format(time.RFC3339)
	v.list = append([]desktop.VaultInfo{e}, append(v.list[:i:i], v.list[i+1:]...)...)
	return nil
}

func (v *Vaults) Forget(path string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if i := v.find(path); i >= 0 {
		v.list = append(v.list[:i:i], v.list[i+1:]...)
	}
	return nil
}

var _ desktop.Vaults = (*Vaults)(nil)
