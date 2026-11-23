package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// The saved location: a program with no shell around it (the window opened from Finder: no environment variables, "/" as its directory) cannot find
// the project checkout by itself. `icevault where --remember` writes the checkout it found into one small file of the user's configuration
// folder; the command line and the window read it as the last resort, after ICEVAULT_ROOT and the folders above the working directory. No path is ever taken
// from the bundle of the application or the working directory.

const (
	configDirVar = "ICEVAULT_CONFIG_DIR" // replaces the user's configuration base folder (tests)
	locationName = "location.json"
	// appDirName is the folder of the application in the configuration base: the bundle identifier of IceVault.app.
	appDirName = "com.cybericebox.icevault"
)

type location struct {
	Root string `json:"checkout"`
	// Project is the project description file the window was given (when the checkout has none).
	Project string `json:"project,omitempty"`
}

func readLocationFile(f string) location {
	var l location
	if f == "" {
		return l
	}
	if data, err := os.ReadFile(f); err == nil {
		_ = json.Unmarshal(data, &l)
	}
	return l
}

func writeLocation(f string, l location) error {
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		return fail("the location could not be saved (%v)", pathErrText(err))
	}
	data, _ := json.Marshal(l)
	if err := os.WriteFile(f, append(data, '\n'), 0o600); err != nil {
		return fail("the location could not be saved (%v)", pathErrText(err))
	}
	return nil
}

// SavedProject is the project description file remembered for the window, or "" (none, or it is gone).
func SavedProject(getenv func(string) string) string {
	p := readLocationFile(locationFile(getenv)).Project
	if !filepath.IsAbs(p) {
		return ""
	}
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		return ""
	}
	return p
}

// RememberProject saves the project description file the window was given (an absolute path of a file), next to the saved checkout.
func RememberProject(getenv func(string) string, p string) error {
	f := locationFile(getenv)
	if f == "" {
		return fail("the configuration folder of this user is unknown: nothing was saved")
	}
	if st, err := os.Stat(p); err != nil || st.IsDir() || !filepath.IsAbs(p) {
		return fail("%s is not a file", p)
	}
	l := readLocationFile(f)
	l.Project = filepath.Clean(p)
	return writeLocation(f, l)
}

func configBase(getenv func(string) string) string {
	if dir := getenv(configDirVar); dir != "" {
		return dir
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return base
}

func locationFile(getenv func(string) string) string {
	base := configBase(getenv)
	if base == "" {
		return ""
	}
	return filepath.Join(base, appDirName, locationName)
}

// readLocation reads one location file: an absolute path of a directory that exists, or "".
func readLocation(f string) string {
	if f == "" {
		return ""
	}
	data, err := os.ReadFile(f)
	if err != nil {
		return ""
	}
	var l location
	if json.Unmarshal(data, &l) != nil || !filepath.IsAbs(l.Root) {
		return ""
	}
	if st, err := os.Stat(l.Root); err != nil || !st.IsDir() {
		return ""
	}
	return filepath.Clean(l.Root)
}

// savedRoot is the remembered project checkout, or "" when none is saved or it is gone; nothing secret is in it, only a path.
func savedRoot(getenv func(string) string) string {
	return readLocation(locationFile(getenv))
}

// rememberRoot saves root (mode 0600 in a 0700 folder) and returns the file.
func rememberRoot(getenv func(string) string, root string) (string, error) {
	f := locationFile(getenv)
	if f == "" {
		return "", fail("the configuration folder of this user is unknown: nothing was saved")
	}
	l := readLocationFile(f)
	l.Root = root
	if err := writeLocation(f, l); err != nil {
		return "", err
	}
	return f, nil
}
