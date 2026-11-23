//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mkExe(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// noInstalledApps keeps the test away from the applications of this machine.
func noInstalledApps(t *testing.T) {
	t.Helper()
	old := installedApps
	installedApps = func() []string { return nil }
	t.Cleanup(func() { installedApps = old })
}

func TestFindWindowInTheBundleAndBesideIt(t *testing.T) {
	noInstalledApps(t)
	root := t.TempDir()
	// the command line next to the application: bin/icevault and bin/IceVault.app
	bin := filepath.Join(root, "bin")
	mkExe(t, filepath.Join(bin, "icevault"))
	if got := findWindow(filepath.Join(bin, "icevault")); got != "" {
		t.Fatalf("a window was found with no application: %q", got)
	}
	win := filepath.Join(bin, appName, "Contents", "MacOS", windowExe)
	mkExe(t, win)
	if got := findWindow(filepath.Join(bin, "icevault")); got != win {
		t.Fatalf("got %q, want %q", got, win)
	}
	// the command inside the bundle
	if got := findWindow(filepath.Join(bin, appName, "Contents", "MacOS", "icevault")); got != win {
		t.Fatalf("inside the bundle: %q", got)
	}
	// a loose window program next to the command is NOT looked for in other places, and a file that cannot run is not taken
	if err := os.Chmod(win, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := findWindow(filepath.Join(bin, "icevault")); got != "" {
		t.Fatalf("a file that cannot run was taken: %q", got)
	}
}

// A command installed on its own (mise, the tar.gz of a release) finds the installed application: /Applications first, then ~/Applications.
func TestFindWindowOfAnInstalledApplication(t *testing.T) {
	root := t.TempDir()
	sys, user := filepath.Join(root, "Applications"), filepath.Join(root, "home", "Applications")
	old := installedApps
	installedApps = func() []string { return []string{sys, user} }
	t.Cleanup(func() { installedApps = old })
	cmd := filepath.Join(root, "mise", "installs", "icevault", "0.1.0", "icevault")
	mkExe(t, cmd)
	if got := findWindow(cmd); got != "" {
		t.Fatalf("a window was found with no application installed: %q", got)
	}
	inUser := filepath.Join(user, appName, "Contents", "MacOS", windowExe)
	mkExe(t, inUser)
	if got := findWindow(cmd); got != inUser {
		t.Fatalf("got %q, want the one in ~/Applications", got)
	}
	inSys := filepath.Join(sys, appName, "Contents", "MacOS", windowExe)
	mkExe(t, inSys)
	if got := findWindow(cmd); got != inSys {
		t.Fatalf("got %q, want the one in /Applications", got)
	}
	// a window that belongs to the command itself wins over an installed one
	own := filepath.Join(filepath.Dir(cmd), appName, "Contents", "MacOS", windowExe)
	mkExe(t, own)
	if got := findWindow(cmd); got != own {
		t.Fatalf("got %q, want the window next to the command", got)
	}
}

func TestUIStartsTheWindowWithTheFlagsAndTheVault(t *testing.T) {
	h := newHarness(t)
	var gotPath string
	var gotArgv, gotEnv []string
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	win := filepath.Join(filepath.Dir(exe), windowExe) // beside the test binary: findWindow's first candidate
	mkExe(t, win)
	t.Cleanup(func() { _ = os.Remove(win) })
	e := &Env{Getenv: func(k string) string { return h.env[k] }, Out: &h.out, Err: &h.errb, StartWindow: func(p string, argv, env []string) error {
		gotPath, gotArgv, gotEnv = p, argv, env
		return nil
	}}
	if rc := Run([]string{"ui", "--env", "staging", "--demo", "--vault", "/x/y.kdbx"}, e); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if gotPath != win || strings.Join(gotArgv, " ") != "icevault-desktop --env staging --demo" {
		t.Fatalf("path %q argv %v", gotPath, gotArgv)
	}
	found := ""
	for _, kv := range gotEnv {
		if strings.HasPrefix(kv, "ICEVAULT_VAULT=") {
			found = kv
		}
	}
	if found != "ICEVAULT_VAULT=/x/y.kdbx" {
		t.Fatalf("the vault of --vault did not reach the window: %q", found)
	}
}

func TestUIWithoutAnApplicationSaysHowToGetIt(t *testing.T) {
	noInstalledApps(t)
	h := newHarness(t)
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	if findWindow(exe) != "" {
		t.Skip("a window program is next to the test binary")
	}
	e := &Env{Getenv: func(k string) string { return h.env[k] }, Out: &h.out, Err: &h.errb, StartWindow: func(string, []string, []string) error {
		t.Fatal("started with no window")
		return nil
	}}
	if rc := Run([]string{"ui"}, e); rc != 1 || !strings.Contains(h.errb.String(), "install it into /Applications") || !strings.Contains(h.errb.String(), "mise run desktop-app") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
}
