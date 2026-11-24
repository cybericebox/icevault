package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// The recent vaults of the window: vaults.json in the configuration folder of the application, next to location.json. It holds paths and labels only,
// never a secret: [{path, checkout, label, last_opened}], the most recently opened first, at most MaxRecent. Only the window reads and writes it; the
// command line keeps its own rules (--vault, ICEVAULT_VAULT, ICEVAULT_ROOT, the saved location) and never reads this file.

const (
	vaultsName = "vaults.json"
	// MaxRecent is how many vaults the list keeps; the one opened longest ago drops out.
	MaxRecent = 10
)

// RecentVault is one entry of the list.
type RecentVault struct {
	Path  string `json:"path"`     // the vault file, absolute
	Root  string `json:"checkout"` // the project checkout whose description the vault uses; "" when not known yet
	Label string `json:"label"`    // what the list shows (the file name by default)
	// LastOpened is when the window last unlocked it (RFC 3339, UTC); "" for an entry the window has not opened yet (the migrated one).
	LastOpened string `json:"last_opened"`
}

// RecentFile is the path of vaults.json, or "" when the configuration folder of this user is unknown.
func RecentFile(getenv func(string) string) string {
	base := configBase(getenv)
	if base == "" {
		return ""
	}
	return filepath.Join(base, appDirName, vaultsName)
}

// LoadRecent reads the list. found is false when there is no file yet (the first start of the window: see MigrateRecent). Entries without an
// absolute path are dropped, a path seen twice is kept once (the first), and the list is cut to MaxRecent.
func LoadRecent(getenv func(string) string) (list []RecentVault, found bool, err error) {
	f := RecentFile(getenv)
	if f == "" {
		return nil, false, nil
	}
	data, err := os.ReadFile(f) // #nosec G304 -- the file of this application in the user's configuration folder
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, fail("the list of vaults cannot be read (%v)", pathErrText(err))
	}
	var raw []RecentVault
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, true, fail("the list of vaults %s is not valid JSON", f)
	}
	return cleanRecent(raw), true, nil
}

func cleanRecent(in []RecentVault) []RecentVault {
	out := []RecentVault{}
	seen := map[string]bool{}
	for _, v := range in {
		if !filepath.IsAbs(v.Path) {
			continue
		}
		v.Path = filepath.Clean(v.Path)
		if seen[v.Path] {
			continue
		}
		seen[v.Path] = true
		if v.Root != "" && !filepath.IsAbs(v.Root) {
			v.Root = ""
		}
		if v.Root != "" {
			v.Root = filepath.Clean(v.Root)
		}
		if v.Label == "" {
			v.Label = filepath.Base(v.Path)
		}
		out = append(out, v)
		if len(out) == MaxRecent {
			break
		}
	}
	return out
}

// SaveRecent writes the list (mode 0600 in a 0700 folder; written to a temporary file and renamed, so a reader never sees half a list).
func SaveRecent(getenv func(string) string, list []RecentVault) error {
	f := RecentFile(getenv)
	if f == "" {
		return fail("the configuration folder of this user is unknown: the list of vaults was not saved")
	}
	dir := filepath.Dir(f)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail("the list of vaults could not be saved (%v)", pathErrText(err))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fail("the list of vaults could not be saved (%v)", pathErrText(err))
	}
	data, err := json.MarshalIndent(cleanRecent(list), "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".vaults-*.tmp")
	if err != nil {
		return fail("the list of vaults could not be saved (%v)", pathErrText(err))
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // gone after the rename; left only by a failure
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fail("the list of vaults could not be saved (%v)", pathErrText(err))
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, f); err != nil {
		return fail("the list of vaults could not be saved (%v)", pathErrText(err))
	}
	return nil
}

// TouchRecent puts v first (it was just opened at now) and drops an older entry of the same file; an empty label or checkout keeps the old one.
func TouchRecent(list []RecentVault, v RecentVault, now time.Time) []RecentVault {
	v.Path = filepath.Clean(v.Path)
	v.LastOpened = now.UTC().Format(time.RFC3339)
	out := []RecentVault{v}
	for _, o := range list {
		if filepath.Clean(o.Path) == v.Path {
			if out[0].Label == "" {
				out[0].Label = o.Label
			}
			if out[0].Root == "" {
				out[0].Root = o.Root
			}
			continue
		}
		out = append(out, o)
	}
	return cleanRecent(out)
}

// AddRecent puts a vault that was never unlocked (a new one) first in the list, without a time: the lock screen says it was not opened yet. A vault
// the list has already keeps its entry.
func AddRecent(list []RecentVault, v RecentVault) []RecentVault {
	v.Path = filepath.Clean(v.Path)
	v.LastOpened = ""
	for _, o := range list {
		if filepath.Clean(o.Path) == v.Path {
			return list
		}
	}
	return cleanRecent(append([]RecentVault{v}, list...))
}

// ForgetRecent drops the entry of path from the list. The file itself is never touched.
func ForgetRecent(list []RecentVault, path string) []RecentVault {
	path = filepath.Clean(path)
	out := []RecentVault{}
	for _, o := range list {
		if filepath.Clean(o.Path) != path {
			out = append(out, o)
		}
	}
	return out
}

// MigrateRecent is the list at the start of the window. When vaults.json does not exist yet, the vault the window found before it had a list (ICEVAULT_VAULT,
// or the vault file of the project description of the checkout: ICEVAULT_ROOT, above the working directory, or the location saved by `where --remember`) becomes its first
// entry and the file is written. Only the existence of that file is looked at; nothing in it is read. With no such file nothing is written, so a
// later `where --remember` is still taken up.
func MigrateRecent(e *Env) ([]RecentVault, error) {
	list, found, err := LoadRecent(e.Getenv)
	if found || err != nil {
		return list, err
	}
	p, err := vaultPath(e)
	if err != nil {
		return []RecentVault{}, nil
	}
	if st, serr := os.Stat(p); serr != nil || !st.Mode().IsRegular() {
		return []RecentVault{}, nil
	}
	root := checkoutOfVault(p, e.Root)
	list = []RecentVault{{Path: filepath.Clean(p), Root: root, Label: filepath.Base(p)}}
	if err := SaveRecent(e.Getenv, list); err != nil {
		return list, err
	}
	return list, nil
}

// RootOf is the project checkout of a vault file: the nearest folder above it with a project description; else saved when it is a checkout;
// else "" (the window asks for the folder).
func RootOf(vaultFile, saved string) string { return checkoutOfVault(vaultFile, saved) }

// HasInfoFile says whether the info file that `icevault init` writes next to a vault (<vault>.info.json) exists. It is not read.
func HasInfoFile(vaultFile string) bool {
	st, err := os.Stat(infoPath(vaultFile))
	return err == nil && st.Mode().IsRegular()
}
