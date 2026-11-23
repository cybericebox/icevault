package appbundle

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The postinstall script of the installer package (pkg/postinstall), run on a throwaway volume: a temporary folder stands for "/" (Installer's $3).
func TestPostinstall(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the installer package and its script are macOS only (ln -h)")
	}
	script, err := filepath.Abs(filepath.Join("pkg", "postinstall"))
	if err != nil {
		t.Fatal(err)
	}
	const target = "/Applications/IceVault.app/Contents/MacOS/icevault"
	type setup func(t *testing.T, vol, link string)
	app := func(t *testing.T, vol string) {
		p := filepath.Join(vol, target)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a test program
			t.Fatal(err)
		}
	}
	mkdir := func(t *testing.T, link string) {
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name   string
		setup  setup
		link   string // what is at the link afterwards: "->X" a link to X, "file", "" nothing
		saying string
	}{
		{"no bin folder yet", func(t *testing.T, vol, link string) { app(t, vol) }, "->" + target, "-> " + target},
		{"nothing there", func(t *testing.T, vol, link string) { app(t, vol); mkdir(t, link) }, "->" + target, "-> " + target},
		{"already ours", func(t *testing.T, vol, link string) {
			app(t, vol)
			mkdir(t, link)
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
		}, "->" + target, "already points"},
		{"another IceVault (a build, an older copy)", func(t *testing.T, vol, link string) {
			app(t, vol)
			mkdir(t, link)
			if err := os.Symlink("/Users/someone/src/icevault/bin/IceVault.app/Contents/MacOS/icevault", link); err != nil {
				t.Fatal(err)
			}
		}, "->" + target, "-> " + target},
		{"a link to another program stays", func(t *testing.T, vol, link string) {
			app(t, vol)
			mkdir(t, link)
			if err := os.Symlink("/opt/other/icevault", link); err != nil {
				t.Fatal(err)
			}
		}, "->/opt/other/icevault", "left as it is"},
		{"a file stays", func(t *testing.T, vol, link string) {
			app(t, vol)
			mkdir(t, link)
			if err := os.WriteFile(link, []byte("mine"), 0o755); err != nil { // #nosec G306 -- a test program
				t.Fatal(err)
			}
		}, "file", "is a file"},
		{"no application: nothing", func(t *testing.T, vol, link string) {}, "", "is missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vol := t.TempDir()
			link := filepath.Join(vol, "usr", "local", "bin", "icevault")
			c.setup(t, vol, link)
			out, err := exec.Command("/bin/sh", script, "/tmp/IceVault.pkg", "/", vol).CombinedOutput() // #nosec G204 -- the script of this package
			if err != nil {
				t.Fatalf("the script failed (Installer would report the installation as failed): %v %s", err, out)
			}
			if !strings.Contains(string(out), c.saying) {
				t.Fatalf("log line %q lacks %q", out, c.saying)
			}
			st, err := os.Lstat(link)
			switch c.link {
			case "":
				if err == nil {
					t.Fatal("a link was made without the application")
				}
			case "file":
				if err != nil || st.Mode()&os.ModeSymlink != 0 {
					t.Fatal("the file was replaced")
				}
				if b, _ := os.ReadFile(link); string(b) != "mine" {
					t.Fatal("the file was written")
				}
			default:
				got, err := os.Readlink(link)
				if err != nil || "->"+got != c.link {
					t.Fatalf("link %q, want %q (%v)", got, c.link, err)
				}
			}
		})
	}
}
