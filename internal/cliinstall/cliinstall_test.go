package cliinstall

import (
	"os"
	"path/filepath"
	"testing"
)

// fixture: a bundle with the program, two candidate directories (the first one not writable), a home.
type fixture struct {
	home, bundle, src, sys, user string
	in                           *Installer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{home: filepath.Join(root, "home"), bundle: filepath.Join(root, "IceVault.app", "Contents", "MacOS")}
	f.sys, f.user = filepath.Join(root, "usr-local-bin"), filepath.Join(f.home, ".local", "bin")
	for _, d := range []string{f.home, f.bundle, f.sys} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.src = filepath.Join(f.bundle, Name)
	if err := os.WriteFile(f.src, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if real, err := filepath.EvalSymlinks(f.src); err == nil { // the link points to the resolved path (/var is /private/var on macOS)
		f.src = real
	}
	f.in = &Installer{Source: f.src, Dirs: []string{f.sys, f.user}, Home: f.home, PathDirs: func() []string { return []string{"/usr/bin", f.user} }}
	return f
}

func (f *fixture) lockSystemDir(t *testing.T) {
	t.Helper()
	if err := os.Chmod(f.sys, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.sys, 0o755) })
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
}

func TestInstallsIntoTheSystemDirWhenItIsWritable(t *testing.T) {
	f := newFixture(t)
	if st := f.in.Status(); st.State != NotInstalled || st.Dir != f.sys {
		t.Fatalf("before: %+v", st)
	}
	st, err := f.in.Install(false)
	if err != nil || st.State != Installed || st.Dir != f.sys {
		t.Fatalf("install: %+v %v", st, err)
	}
	if got, _ := os.Readlink(filepath.Join(f.sys, Name)); got != f.src {
		t.Fatalf("the link points to %q, want %q", got, f.src)
	}
	if _, err := os.Stat(f.user); err == nil {
		t.Error("the user directory was made although the system one was writable")
	}
}

func TestFallsBackToTheUserDirAndMakesIt(t *testing.T) {
	f := newFixture(t)
	f.lockSystemDir(t)
	st, err := f.in.Install(false)
	if err != nil || st.State != Installed || st.Dir != f.user {
		t.Fatalf("install: %+v %v", st, err)
	}
	if !st.PathKnown || !st.OnPath {
		t.Errorf("PATH: %+v", st)
	}
	d, err := os.Stat(f.user)
	if err != nil || d.Mode().Perm() != 0o755 {
		t.Fatalf("the user directory: %v %v", d, err)
	}
	// the second install changes nothing
	if st2, err := f.in.Install(false); err != nil || st2.State != Installed {
		t.Fatalf("again: %+v %v", st2, err)
	}
}

func TestSaysWhenThePathLacksTheDirectory(t *testing.T) {
	f := newFixture(t)
	f.lockSystemDir(t)
	f.in.PathDirs = func() []string { return []string{"/usr/bin"} }
	st, err := f.in.Install(false)
	if err != nil || !st.PathKnown || st.OnPath {
		t.Fatalf("%+v %v", st, err)
	}
	f.in.PathDirs = func() []string { return nil } // unknown: not claimed missing
	if st := f.in.Status(); st.PathKnown || st.OnPath {
		t.Fatalf("%+v", st)
	}
}

func TestALinkToAnotherProgramIsReplacedOnlyOnRequest(t *testing.T) {
	f := newFixture(t)
	other := filepath.Join(t.TempDir(), "dev-icevault")
	if err := os.WriteFile(other, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.sys, Name)
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if st := f.in.Status(); st.State != Elsewhere || st.Target != other {
		t.Fatalf("status: %+v", st)
	}
	_, err := f.in.Install(false)
	if e, ok := IsRefusal(err); !ok || e.Code != "cli_elsewhere" || e.Params["target"] != other {
		t.Fatalf("install without replace: %v", err)
	}
	if got, _ := os.Readlink(link); got != other {
		t.Fatal("the link was changed without a request")
	}
	if st, err := f.in.Install(true); err != nil || st.State != Installed {
		t.Fatalf("replace: %+v %v", st, err)
	}
	if got, _ := os.Readlink(link); got != f.src {
		t.Fatalf("the link points to %q", got)
	}
	if b, _ := os.ReadFile(other); string(b) != "x" {
		t.Fatal("the other program was written through the link")
	}
	if ents, _ := os.ReadDir(f.sys); len(ents) != 1 {
		t.Fatalf("a temporary link was left: %v", ents)
	}
}

func TestADanglingLinkIsElsewhere(t *testing.T) {
	f := newFixture(t)
	if err := os.Symlink(filepath.Join(f.home, "gone"), filepath.Join(f.sys, Name)); err != nil {
		t.Fatal(err)
	}
	if st := f.in.Status(); st.State != Elsewhere {
		t.Fatalf("%+v", st)
	}
}

func TestAFileThatIsNotALinkIsNeverTouched(t *testing.T) {
	f := newFixture(t)
	file := filepath.Join(f.sys, Name)
	if err := os.WriteFile(file, []byte("mine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if st := f.in.Status(); st.State != Blocked {
		t.Fatalf("%+v", st)
	}
	for _, replace := range []bool{false, true} {
		_, err := f.in.Install(replace)
		if e, ok := IsRefusal(err); !ok || e.Code != "cli_blocked" {
			t.Fatalf("replace=%v: %v", replace, err)
		}
	}
	if b, _ := os.ReadFile(file); string(b) != "mine" {
		t.Fatal("the file was changed")
	}
}

func TestNoBundleAndTranslocatedCopies(t *testing.T) {
	f := newFixture(t)
	f.in.Source = ""
	if st := f.in.Status(); st.State != Unavailable || st.Code != "cli_unavailable" {
		t.Fatalf("%+v", st)
	}
	if _, err := f.in.Install(false); err == nil {
		t.Fatal("installed without a program")
	}
	tr := filepath.Join(t.TempDir(), "AppTranslocation", "ID", "d", "IceVault.app", "Contents", "MacOS")
	if err := os.MkdirAll(tr, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tr, Name), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.in.Source = filepath.Join(tr, Name)
	_, err := f.in.Install(false)
	if e, ok := IsRefusal(err); !ok || e.Code != "cli_translocated" {
		t.Fatalf("translocated: %v", err)
	}
	if _, serr := os.Lstat(filepath.Join(f.sys, Name)); serr == nil {
		t.Fatal("a link to a translocated copy was made")
	}
}

func TestNoWritableDirectory(t *testing.T) {
	f := newFixture(t)
	f.lockSystemDir(t)
	f.in.Dirs = []string{f.sys, "/nonexistent-root/x/bin"} // not under the home: never made
	_, err := f.in.Install(false)
	if e, ok := IsRefusal(err); !ok || e.Code != "cli_no_dir" {
		t.Fatalf("%v", err)
	}
}

func TestANonExecutableProgramIsRefused(t *testing.T) {
	f := newFixture(t)
	if err := os.Chmod(f.src, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.in.Install(false); err == nil {
		t.Fatal("a file that cannot run was linked")
	}
}
