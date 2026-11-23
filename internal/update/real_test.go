package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// realApp makes a small application folder with a real Info.plist and an ad hoc signature.
func realApp(t *testing.T, dir, version string) string {
	t.Helper()
	app := filepath.Join(dir, "IceVault.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.cybericebox.icevault.test</string>
<key>CFBundleExecutable</key><string>run</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>` + version + `</string>
</dict></plist>
`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "MacOS", "run"), []byte("#!/bin/sh\necho "+version+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--deep", "-s", "-", app).CombinedOutput(); err != nil {
		t.Fatalf("codesign: %v %s", err, out)
	}
	return app
}

// TestRealTools runs the whole update with the real hdiutil, ditto, plutil and codesign of macOS on a disk image made here; the release is served
// locally (no network).
func TestRealTools(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS tools")
	}
	if _, err := os.Stat("/usr/bin/hdiutil"); err != nil {
		t.Skip("no hdiutil")
	}
	root := t.TempDir()
	installed, src := filepath.Join(root, "Applications"), filepath.Join(root, "src")
	for _, d := range []string{installed, src} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	app := realApp(t, installed, "0.3.0")
	realApp(t, src, "0.4.0")
	dmg := filepath.Join(root, "IceVault-v0.4.0-macos.dmg")
	if out, err := exec.Command("/usr/bin/hdiutil", "create", "-quiet", "-volname", "IceVault", "-srcfolder", src, "-format", "UDZO", "-ov", dmg).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create is not possible here: %v %s", err, out)
	}
	image, err := os.ReadFile(dmg) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(image)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	dl := srv.URL + "/dl/"
	mux.HandleFunc("/repos/"+Repo+"/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v0.4.0", "html_url": "https://example.invalid/v0.4.0", "assets": []map[string]any{
			{"name": filepath.Base(dmg), "browser_download_url": dl + "v0.4.0/" + filepath.Base(dmg), "size": len(image)},
			{"name": "SHA256SUMS", "browser_download_url": dl + "v0.4.0/SHA256SUMS", "size": 1}}})
	})
	mux.HandleFunc("/dl/v0.4.0/"+filepath.Base(dmg), func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(image) })
	mux.HandleFunc("/dl/v0.4.0/SHA256SUMS", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(hex.EncodeToString(sum[:]) + "  " + filepath.Base(dmg) + "\n"))
	})
	var started string
	u := &Updater{Current: "v0.3.0", App: app, API: srv.URL, Download: dl, Client: srv.Client(), Image: "IceVault-{v}-macos.dmg", Clock: time.Now, Run: run,
		Start: func(_ int, a string) error { started = a; return nil }}
	if st := u.Check(context.Background()); st.State != Available {
		t.Fatalf("%+v", st)
	}
	if _, err := u.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	var st Status
	for i := 0; i < 600; i++ {
		if st = u.Status(); st.State != Downloading {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if st.State != Ready {
		t.Fatalf("%+v", st)
	}
	if err := u.Apply(); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(filepath.Join(app, "Contents", "MacOS", "run")).Output()
	if err != nil || string(out) != "0.4.0\n" || started != app {
		t.Fatalf("after Apply: %q %v %q", out, err, started)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--verify", "--deep", "--strict", app).CombinedOutput(); err != nil {
		t.Fatalf("the swapped copy: %v %s", err, out)
	}
	left, _ := filepath.Glob(filepath.Join(installed, ".IceVault-*"))
	if len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
}
