//go:build !windows

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A program started from Finder has no environment and "/" as its directory: the vault is found through the place `where --remember` saved.
func TestWhereRememberAndTheWindowFindsTheCheckout(t *testing.T) {
	h := newHarness(t)
	cfg := filepath.Join(t.TempDir(), "config")
	h.env[configDirVar] = cfg
	if rc := h.run("where", "--remember"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if h.out.Len() != 0 {
		t.Fatalf("--remember printed %q: it must not read or show anything of the vault", h.out.String())
	}
	f := filepath.Join(cfg, appDirName, locationName)
	st, err := os.Stat(f)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the location file: %v %v", st, err)
	}
	var l location
	b, _ := os.ReadFile(f)
	if json.Unmarshal(b, &l) != nil || l.Root != h.root {
		t.Fatalf("saved %s, want %s", b, h.root)
	}
	if got := savedRoot(func(k string) string { return h.env[k] }); got != h.root {
		t.Fatalf("savedRoot = %q", got)
	}
	// the window's environment: nothing in the process environment, a working directory that is not the checkout
	t.Chdir(t.TempDir())
	empty := func(k string) string {
		if k == configDirVar {
			return cfg
		}
		return ""
	}
	if got := findRoot(empty); got != h.root {
		t.Fatalf("findRoot with no environment = %q, want the saved %q", got, h.root)
	}
	// a checkout that is gone is not used
	if err := os.RemoveAll(h.root); err != nil {
		t.Fatal(err)
	}
	if got := findRoot(empty); got != "" {
		t.Fatalf("a removed checkout was used: %q", got)
	}
}

func TestWhereRememberNeedsACheckout(t *testing.T) {
	h := newHarness(t)
	h.root = ""
	h.env[configDirVar] = t.TempDir()
	if rc := h.run("where", "--remember"); rc == 0 || !strings.Contains(h.errb.String(), "not found") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
}

func fakeTool(t *testing.T, dir, name, body string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// The window starts the Touch ID programs from known absolute folders only, never from PATH, and only when nobody else can have changed them.
func TestWindowRunnerTakesOnlyTrustedProgramsFromKnownFolders(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	r := execRunner{dirs: []string{dir}}
	t.Setenv("PATH", other+":/usr/bin:/bin") // a program on PATH is not found by the window runner
	fakeTool(t, other, "age", "echo path-age", 0o755)
	if r.Has("age") {
		t.Fatal("a program on PATH was found")
	}
	if _, _, err := r.Run("age", nil, nil, time.Second); err == nil {
		t.Fatal("a missing program ran")
	}
	fakeTool(t, dir, "age", "echo $PATH", 0o755)
	if !r.Has("age") {
		t.Fatal("a trusted program was not found")
	}
	out, code, err := r.Run("age", nil, nil, 5*time.Second)
	if err != nil || code != 0 || !strings.HasPrefix(strings.TrimSpace(string(out)), dir+":") {
		t.Fatalf("run: %q %d %v (the child's PATH must start with the known folder, so age finds age-plugin-se beside itself)", out, code, err)
	}
	if strings.Contains(string(out), other) {
		t.Fatalf("the child inherited the process PATH: %s", out)
	}
	for name, mode := range map[string]os.FileMode{"age-w": 0o757, "age-g": 0o775, "age-x": 0o644} {
		fakeTool(t, dir, name, "true", mode)
		if r.Has(name) {
			t.Errorf("%s with mode %v was trusted", name, mode)
		}
	}
	if r.Has("../age") || r.Has(filepath.Join(dir, "age")) {
		t.Error("a name with a path was accepted")
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if r.Has("age") {
		t.Error("a program in a world-writable folder was trusted")
	}
	// a link into a folder that is fine is followed, and its target is what is checked (Homebrew links its programs)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	real := t.TempDir()
	fakeTool(t, real, "age-plugin-se", "true", 0o755)
	if err := os.Symlink(filepath.Join(real, "age-plugin-se"), filepath.Join(dir, "age-plugin-se")); err != nil {
		t.Fatal(err)
	}
	if !r.Has("age-plugin-se") {
		t.Error("a link to a trusted program was refused")
	}
}

func TestTouchIDMissingToolsNamesWhatIsNotInstalled(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	e := &Env{Exec: execRunner{dirs: []string{dir}}}
	if got := strings.Join(e.TouchIDMissingTools(), ","); got != "age,age-plugin-se" {
		t.Fatalf("missing = %q", got)
	}
	fakeTool(t, dir, "age", "true", 0o755)
	if got := strings.Join(e.TouchIDMissingTools(), ","); got != "age-plugin-se" {
		t.Fatalf("missing = %q", got)
	}
}
