package cli

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
)

// `icevault ui [--env E] [--demo]` starts the settings window: the program inside IceVault.app. There is no loose window program anywhere else.

const (
	windowExe = "icevault-desktop"
	appName   = "IceVault.app"
)

// installedApps are the folders where an installed IceVault.app is looked for when none belongs to the command itself: /Applications and the
// user's ~/Applications. Replaced in tests.
var installedApps = func() []string {
	dirs := []string{"/Applications"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	return dirs
}

// findWindow is the window program for the command line program exe: the one beside it when exe is inside the bundle
// (IceVault.app/Contents/MacOS/icevault), else the one inside an IceVault.app next to it (bin/icevault and bin/IceVault.app of a build), else the
// installed application (/Applications, then ~/Applications) for a command installed on its own (mise, the tar.gz of a release). "" when there is none.
func findWindow(exe string) string {
	dir := filepath.Dir(exe)
	cands := []string{
		filepath.Join(dir, windowExe),
		filepath.Join(dir, appName, "Contents", "MacOS", windowExe),
	}
	for _, d := range installedApps() {
		cands = append(cands, filepath.Join(d, appName, "Contents", "MacOS", windowExe))
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return c
		}
	}
	return ""
}

// windowEnv is the environment of the window: the process environment, with the vault of --vault when one was given.
func windowEnv(e *Env) []string {
	env := os.Environ()
	if v := e.Getenv("ICEVAULT_VAULT"); v != "" {
		out := env[:0:0]
		for _, kv := range env {
			if !strings.HasPrefix(kv, "ICEVAULT_VAULT=") {
				out = append(out, kv)
			}
		}
		env = append(out, "ICEVAULT_VAULT="+v)
	}
	return env
}

func cmdUI(args []string, e *Env) error {
	if _, err := parse("ui", args, e, 0, func(fs *flag.FlagSet) {
		fs.String("env", "", "the environment to open first")
		fs.Bool("demo", false, "a throwaway in-memory vault")
	}); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fail("the program's own place is unknown")
	}
	w := findWindow(exe)
	if w == "" {
		return fail("the settings window is the application %s: install it into /Applications from the release (the zip of the version of this command), or build it with `mise run desktop-app` in tools/icevault (macOS)", appName)
	}
	start := e.StartWindow
	if start == nil {
		start = execWindow
	}
	return start(w, append([]string{windowExe}, args...), windowEnv(e))
}
