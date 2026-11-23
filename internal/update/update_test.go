package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.3.0", "v0.3.1", true}, {"v0.3.0", "v0.4.0", true}, {"v0.9.0", "v0.10.0", true}, {"v1.0.0", "v0.9.9", false},
		{"v0.3.0", "v0.3.0", false}, {"dev", "v9.0.0", false}, {"v0.3.0-2-gabc", "v0.4.0", false}, {"v0.3.0", "v0.4.0-rc.1", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestBundleOf(t *testing.T) {
	if got := BundleOf("/Applications/IceVault.app/Contents/MacOS/icevault-desktop"); got != "/Applications/IceVault.app" {
		t.Errorf("got %q", got)
	}
	if got := BundleOf("/usr/local/bin/icevault-desktop"); got != "" {
		t.Errorf("got %q", got)
	}
}

// fakeApp makes an application folder with an Info.plist of the version (no signature: the fake Run answers codesign).
func fakeApp(t *testing.T, dir, version, id string) string {
	t.Helper()
	app := filepath.Join(dir, "IceVault.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := "id=" + id + "\nversion=" + version + "\n"
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "MacOS", "icevault-desktop"), []byte("v"+version), 0o755); err != nil {
		t.Fatal(err)
	}
	return app
}

// fakeTools stands in for hdiutil (an "image" is a folder path written into the file), ditto, plutil (the key=value file of fakeApp) and codesign.
type fakeTools struct {
	mu       sync.Mutex
	unsigned map[string]bool
	calls    []string
}

func (f *fakeTools) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, filepath.Base(name))
	f.mu.Unlock()
	switch filepath.Base(name) {
	case "hdiutil":
		if args[0] == "detach" {
			mnt := args[len(args)-1]
			return nil, os.Remove(mnt)
		}
		dmg, mnt := args[len(args)-1], args[len(args)-2]
		src, err := os.ReadFile(dmg) // #nosec G304
		if err != nil {
			return nil, err
		}
		if err := os.Remove(mnt); err != nil {
			return nil, err
		}
		return nil, os.Symlink(strings.TrimSpace(string(src)), mnt)
	case "ditto":
		return exec.Command("cp", "-R", args[0]+"/", args[1]).CombinedOutput()
	case "plutil":
		data, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return nil, err
		}
		key := map[string]string{"CFBundleIdentifier": "id", "CFBundleShortVersionString": "version"}[args[1]]
		for _, ln := range strings.Split(string(data), "\n") {
			if k, v, ok := strings.Cut(ln, "="); ok && k == key {
				return []byte(v + "\n"), nil
			}
		}
		return nil, fmt.Errorf("no key")
	case "codesign":
		app := args[len(args)-1]
		real, _ := filepath.EvalSymlinks(app)
		if f.unsigned[real] {
			return nil, fmt.Errorf("invalid signature")
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected tool %s", name)
}

type fixture struct {
	u        *Updater
	tools    *fakeTools
	app      string
	newApp   string
	srv      *httptest.Server
	started  []string
	image    []byte
	sumsBody string
	tag      string
	draft    bool
	apiCode  int
}

func newFixture(t *testing.T, current, latest string) *fixture {
	t.Helper()
	root := t.TempDir()
	installed := filepath.Join(root, "Applications")
	release := filepath.Join(root, "release")
	for _, d := range []string{installed, release} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f := &fixture{tools: &fakeTools{unsigned: map[string]bool{}}, tag: latest, apiCode: 200}
	f.app = fakeApp(t, installed, strings.TrimPrefix(current, "v"), "com.cybericebox.icevault")
	f.newApp = fakeApp(t, release, strings.TrimPrefix(latest, "v"), "com.cybericebox.icevault")
	f.image = []byte(release + "\n")
	sum := sha256.Sum256(f.image)
	name := "IceVault-" + latest + "-macos.dmg"
	f.sumsBody = hex.EncodeToString(sum[:]) + "  " + name + "\n" + strings.Repeat("0", 64) + "  other.tar.gz\n"
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	dl := f.srv.URL + "/dl/"
	mux.HandleFunc("/repos/"+Repo+"/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		if f.apiCode != 200 {
			w.WriteHeader(f.apiCode)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": f.tag, "html_url": "https://example.invalid/rel/" + f.tag, "draft": f.draft,
			"assets": []map[string]any{
				{"name": name, "browser_download_url": dl + f.tag + "/" + name, "size": len(f.image)},
				{"name": "SHA256SUMS", "browser_download_url": dl + f.tag + "/SHA256SUMS", "size": len(f.sumsBody)},
			}})
	})
	mux.HandleFunc("/dl/"+latest+"/"+name, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(f.image) })
	mux.HandleFunc("/dl/"+latest+"/SHA256SUMS", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(f.sumsBody)) })
	f.u = &Updater{Current: current, App: f.app, API: f.srv.URL, Download: dl, Client: f.srv.Client(), Settings: filepath.Join(root, "config", "update.json"),
		Image: "IceVault-{v}-macos.dmg", Clock: time.Now, Run: f.tools.run,
		Start: func(_ int, app string) error { f.started = append(f.started, app); return nil }}
	return f
}

func (f *fixture) wait(t *testing.T) Status {
	t.Helper()
	for i := 0; i < 500; i++ {
		st := f.u.Status()
		if st.State != Downloading {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the download did not end")
	return Status{}
}

func version(t *testing.T, app string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(app, "Contents", "MacOS", "icevault-desktop")) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestUpdateEndToEnd(t *testing.T) {
	f := newFixture(t, "v0.3.0", "v0.4.0")
	if st := f.u.Status(); st.State != Idle || !st.Auto {
		t.Fatalf("start: %+v", st)
	}
	if !f.u.Due() {
		t.Fatal("a first start is due a check")
	}
	st := f.u.Check(context.Background())
	if st.State != Available || st.Latest != "v0.4.0" || st.URL == "" || st.Checked == "" {
		t.Fatalf("check: %+v", st)
	}
	if err := f.u.Apply(); code(err, "") != "update_not_ready" {
		t.Fatalf("apply before fetch: %v", err)
	}
	if _, err := f.u.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := f.wait(t); st.State != Ready {
		t.Fatalf("fetch: %+v", st)
	}
	if v := version(t, f.app); v != "v0.3.0" {
		t.Fatalf("the running copy changed before Apply: %s", v)
	}
	if err := f.u.Apply(); err != nil {
		t.Fatal(err)
	}
	if v := version(t, f.app); v != "v0.4.0" {
		t.Fatalf("after Apply: %s", v)
	}
	if len(f.started) != 1 || f.started[0] != f.app {
		t.Fatalf("restart: %v", f.started)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(f.app), ".IceVault-*"))
	if len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	// the time of the check is kept: the next start within a day does not ask again
	u2 := &Updater{Current: "v0.3.0", App: f.app, Settings: f.u.Settings, Clock: time.Now}
	if u2.Due() {
		t.Fatal("a check an hour ago is not due again")
	}
	u3 := &Updater{Current: "v0.3.0", App: f.app, Settings: f.u.Settings, Clock: func() time.Time { return time.Now().Add(25 * time.Hour) }}
	if !u3.Due() {
		t.Fatal("a check a day ago is due")
	}
}

func TestCurrentAndAuto(t *testing.T) {
	f := newFixture(t, "v0.4.0", "v0.4.0")
	if st := f.u.Check(context.Background()); st.State != Current {
		t.Fatalf("%+v", st)
	}
	if _, err := f.u.Fetch(context.Background()); code(err, "") != "update_none" {
		t.Fatalf("fetch with nothing new: %v", err)
	}
	f.u.SetAuto(false)
	u2 := &Updater{Current: "v0.4.0", App: f.app, Settings: f.u.Settings, Clock: time.Now}
	if u2.Status().Auto || u2.Due() {
		t.Fatal("auto off is kept")
	}
}

func TestUnavailable(t *testing.T) {
	for _, c := range []struct{ current, app, code string }{{"dev", "/x/IceVault.app", "update_dev_build"}, {"v0.3.0-4-gabcdef", "/x/IceVault.app", "update_dev_build"}, {"v0.3.0", "", "update_no_bundle"}} {
		u := &Updater{Current: c.current, App: c.app, Clock: time.Now}
		if st := u.Check(context.Background()); st.State != Unavailable || st.Code != c.code || u.Due() {
			t.Errorf("%+v: %+v", c, st)
		}
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]func(f *fixture){
		"update_bad_sum":       func(f *fixture) { b := append([]byte{}, f.image...); b[0] ^= 1; f.image = b }, // the same size, other bytes
		"update_bad_signature": func(f *fixture) { r, _ := filepath.EvalSymlinks(f.newApp); f.tools.unsigned[r] = true },
		"update_bad_image": func(f *fixture) {
			_ = os.WriteFile(filepath.Join(f.newApp, "Contents", "Info.plist"), []byte("id=com.other.app\nversion=0.4.0\n"), 0o644)
		},
		"update_no_image": func(f *fixture) { f.u.Download = "https://github.com/" + Repo + "/releases/download/" },
	}
	for want, spoil := range cases {
		t.Run(want, func(t *testing.T) {
			f := newFixture(t, "v0.3.0", "v0.4.0")
			if st := f.u.Check(context.Background()); st.State != Available {
				t.Fatalf("%+v", st)
			}
			spoil(f)
			if _, err := f.u.Fetch(context.Background()); err != nil {
				t.Fatal(err)
			}
			if st := f.wait(t); st.State != Failed || st.Code != want {
				t.Fatalf("got %+v", st)
			}
			if v := version(t, f.app); v != "v0.3.0" {
				t.Fatalf("the running copy changed: %s", v)
			}
			left, _ := filepath.Glob(filepath.Join(filepath.Dir(f.app), ".IceVault-*"))
			if len(left) != 0 {
				t.Fatalf("left behind: %v", left)
			}
		})
	}
}

func TestCheckFailures(t *testing.T) {
	f := newFixture(t, "v0.3.0", "v0.4.0")
	f.apiCode = 500
	if st := f.u.Check(context.Background()); st.State != Failed || st.Code != "update_check_failed" {
		t.Fatalf("%+v", st)
	}
	f.apiCode, f.draft = 200, true
	if st := f.u.Check(context.Background()); st.State != Failed {
		t.Fatalf("a draft: %+v", st)
	}
	f.draft = false
	f.srv.Close()
	if st := f.u.Check(context.Background()); st.State != Failed || st.Code != "update_offline" {
		t.Fatalf("offline: %+v", st)
	}
}

func TestNotWritable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permissions")
	}
	f := newFixture(t, "v0.3.0", "v0.4.0")
	contents := filepath.Join(f.app, "Contents")
	if err := os.Chmod(contents, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(contents, 0o755) })
	if st := f.u.Check(context.Background()); st.State != Manual || st.Code != "update_not_writable" {
		t.Fatalf("%+v", st)
	}
	f.u.App = "/private/var/folders/x/AppTranslocation/ABC/d/IceVault.app"
	if c := f.u.replaceable(); c != "update_translocated" {
		t.Fatalf("%s", c)
	}
}
