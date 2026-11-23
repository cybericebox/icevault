// Package update keeps the macOS application up to date from the releases of its GitHub repository.
//
// It asks the GitHub API for the latest release (never a draft or a pre-release), downloads the disk image of the application and the SHA256SUMS of the
// same release, checks the image against the sum, mounts it read-only, checks the application inside (bundle identifier, version, code signature), and
// copies it next to the running application under a hidden name. Apply then swaps the two folders with renames and starts the new copy when this
// program has ended. Nothing is changed before Apply; an update that fails at any step leaves the running application as it was.
//
// The application is signed ad hoc (no Developer ID), so the signature proves only that the copy is whole: the origin is the HTTPS download from the
// repository's own release, which is immutable once published. An application that this user cannot replace (installed by the .pkg as root, or run
// from a translocated or read-only place) gets the state Manual: the window links the release page instead.
package update

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Repo is the repository whose releases are the updates.
const Repo = "cybericebox/icevault"

// The states of the updater.
const (
	Unavailable = "unavailable" // not a release build in an application bundle: no update is looked for
	Idle        = "idle"        // not checked yet
	Checking    = "checking"
	Current     = "current"     // this is the latest release
	Available   = "available"   // a newer release exists and can be installed here
	Manual      = "manual"      // a newer release exists; this copy cannot be replaced by this user (the window links the release page)
	Downloading = "downloading" // fetching and checking the new copy (Progress)
	Ready       = "ready"       // the new copy is checked and staged; Apply swaps it in
	Failed      = "failed"      // the last step failed (Code)
)

// MaxImage bounds the download of the disk image.
const MaxImage = 512 << 20

// Status is what the window shows.
type Status struct {
	State    string `json:"state"`
	Current  string `json:"current"`
	Latest   string `json:"latest,omitempty"`
	URL      string `json:"url,omitempty"`      // the release page of Latest
	Progress int    `json:"progress,omitempty"` // percent of the download, while Downloading
	Code     string `json:"code,omitempty"`     // why Unavailable, Manual or Failed (srv.<code> in the window)
	Auto     bool   `json:"auto"`               // look for an update when the window starts (at most once a day)
	Checked  string `json:"checked,omitempty"`  // RFC 3339 time of the last check that got an answer
}

// Error is a refusal with a code the window translates.
type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

func refuse(code string) *Error { return &Error{Code: code} }

// Updater does the work. The fields are set by New and replaced in tests.
type Updater struct {
	Current  string       // the version of this build (internal/version)
	App      string       // the application bundle this program runs from ("" when it does not)
	API      string       // the GitHub API base
	Download string       // the only prefix a download URL may have
	Client   *http.Client // for the API and the downloads
	Settings string       // the file of the settings (auto, last check)
	Image    string       // the name of the disk image in a release: {v} is the tag
	Clock    func() time.Time
	// Run runs a system tool (hdiutil, ditto, codesign, plutil) and returns what it printed.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Start starts the program that waits for this one to end and then opens the new copy.
	Start func(pid int, app string) error

	mu     sync.Mutex
	st     Status
	rel    *release
	staged string // the checked new copy next to App
	busy   bool
	loaded bool
}

// New is the updater of the running window: the bundle of this executable, the public GitHub API, the settings in the configuration folder.
func New(current, settings string) *Updater {
	u := &Updater{Current: current, API: "https://api.github.com", Download: "https://github.com/" + Repo + "/releases/download/",
		Client: &http.Client{Timeout: 10 * time.Minute}, Settings: settings, Image: "IceVault-{v}-macos.dmg", Clock: time.Now, Run: run, Start: relaunch}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			u.App = BundleOf(real)
		}
	}
	return u
}

// BundleOf is the .app folder that holds the executable at Contents/MacOS, or "".
func BundleOf(exe string) string {
	macos := filepath.Dir(exe)
	contents := filepath.Dir(macos)
	app := filepath.Dir(contents)
	if filepath.Base(macos) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(app, ".app") {
		return ""
	}
	return app
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- fixed system tools with paths this package made
}

var versionRE = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// parse reads vX.Y.Z; ok is false for anything else (a development build, a pre-release, a describe with commits after the tag).
func parse(v string) ([3]int, bool) {
	m := versionRE.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// Newer says whether b is a later release than a.
func Newer(a, b string) bool {
	x, ok1 := parse(a)
	y, ok2 := parse(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return y[i] > x[i]
		}
	}
	return false
}

type settings struct {
	Auto    *bool  `json:"auto,omitempty"`
	Checked string `json:"checked,omitempty"`
}

func (u *Updater) readSettings() settings {
	var s settings
	if u.Settings == "" {
		return s
	}
	if data, err := os.ReadFile(u.Settings); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	return s
}

func (u *Updater) writeSettings() {
	if u.Settings == "" {
		return
	}
	auto := u.st.Auto
	data, err := json.Marshal(settings{Auto: &auto, Checked: u.st.Checked})
	if err != nil || os.MkdirAll(filepath.Dir(u.Settings), 0o700) != nil {
		return
	}
	tmp := u.Settings + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, u.Settings)
	}
}

// init reads the settings once and sets the first state; u.mu is held.
func (u *Updater) init() {
	if u.loaded {
		return
	}
	u.loaded = true
	s := u.readSettings()
	u.st = Status{State: Idle, Current: u.Current, Auto: s.Auto == nil || *s.Auto, Checked: s.Checked}
	switch {
	case u.App == "":
		u.st.State, u.st.Code = Unavailable, "update_no_bundle"
	case !versionRE.MatchString(u.Current):
		u.st.State, u.st.Code = Unavailable, "update_dev_build"
	}
}

// Status is the state now; it changes nothing.
func (u *Updater) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.init()
	return u.st
}

// SetAuto turns the check at the start on or off.
func (u *Updater) SetAuto(on bool) Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.init()
	u.st.Auto = on
	u.writeSettings()
	return u.st
}

// Due says whether the check at the start should run: on, a release build in a bundle, and no answer in the last day.
func (u *Updater) Due() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.init()
	if !u.st.Auto || u.st.State != Idle {
		return false
	}
	t, err := time.Parse(time.RFC3339, u.st.Checked)
	now := u.Clock()
	return err != nil || now.Sub(t) >= 24*time.Hour || now.Before(t)
}

type asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type release struct {
	Tag        string  `json:"tag_name"`
	Page       string  `json:"html_url"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []asset `json:"assets"`
}

func (r *release) asset(name string) *asset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

// Check asks for the latest release. It needs no unlock and changes nothing on disk but the time of the check.
func (u *Updater) Check(ctx context.Context) Status {
	u.mu.Lock()
	u.init()
	if u.st.State == Unavailable || u.st.State == Ready || u.busy {
		st := u.st
		u.mu.Unlock()
		return st
	}
	u.busy = true
	u.st.State, u.st.Code, u.st.Progress = Checking, "", 0
	u.mu.Unlock()

	rel, err := u.latest(ctx)

	u.mu.Lock()
	defer u.mu.Unlock()
	u.busy = false
	if err != nil {
		u.st.State, u.st.Code = Failed, code(err, "update_check_failed")
		return u.st
	}
	u.st.Checked = u.Clock().UTC().Format(time.RFC3339)
	u.writeSettings()
	u.rel = rel
	u.st.Latest, u.st.URL = rel.Tag, rel.Page
	switch {
	case !Newer(u.Current, rel.Tag):
		u.st.State = Current
	default:
		if c := u.replaceable(); c != "" {
			u.st.State, u.st.Code = Manual, c
		} else {
			u.st.State = Available
		}
	}
	return u.st
}

func code(err error, fallback string) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fallback
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (u *Updater) request(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, refuse("update_failed")
	}
	req.Header.Set("User-Agent", "IceVault/"+u.Current)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, refuse("update_offline")
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, refuse("update_failed")
	}
	return resp, nil
}

func (u *Updater) latest(ctx context.Context) (*release, error) {
	resp, err := u.request(ctx, u.API+"/repos/"+Repo+"/releases/latest")
	if err != nil {
		if code(err, "") == "update_failed" {
			return nil, refuse("update_check_failed")
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, refuse("update_check_failed")
	}
	if _, ok := parse(rel.Tag); !ok || rel.Draft || rel.Prerelease {
		return nil, refuse("update_check_failed")
	}
	return &rel, nil
}

// replaceable is "" when this user can swap the application folder, else the code of why not.
func (u *Updater) replaceable() string {
	if strings.Contains(u.App, "/AppTranslocation/") {
		return "update_translocated"
	}
	for _, d := range []string{filepath.Dir(u.App), u.App, filepath.Join(u.App, "Contents")} {
		if !writable(d) {
			return "update_not_writable"
		}
	}
	return ""
}

// Fetch starts downloading, checking and staging the new copy in the background; Status shows the progress and then Ready or Failed.
func (u *Updater) Fetch(ctx context.Context) (Status, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.init()
	if u.busy || u.st.State == Ready {
		return u.st, nil
	}
	if u.rel == nil || !Newer(u.Current, u.rel.Tag) || (u.st.State != Available && u.st.State != Failed) {
		return Status{}, refuse("update_none")
	}
	if c := u.replaceable(); c != "" {
		u.st.State, u.st.Code = Manual, c
		return u.st, nil
	}
	u.busy = true
	rel := u.rel
	u.st.State, u.st.Code, u.st.Progress, u.st.Latest, u.st.URL = Downloading, "", 0, rel.Tag, rel.Page
	go func() {
		staged, err := u.fetch(ctx, rel)
		u.mu.Lock()
		defer u.mu.Unlock()
		u.busy = false
		if err != nil {
			u.st.State, u.st.Code, u.st.Progress = Failed, code(err, "update_failed"), 0
			return
		}
		u.staged = staged
		u.st.State, u.st.Progress = Ready, 100
	}()
	return u.st, nil
}

func (u *Updater) progress(p int) {
	u.mu.Lock()
	if u.st.State == Downloading {
		u.st.Progress = p
	}
	u.mu.Unlock()
}

func (u *Updater) fetch(ctx context.Context, rel *release) (string, error) {
	name := strings.ReplaceAll(u.Image, "{v}", rel.Tag)
	img, sums := rel.asset(name), rel.asset("SHA256SUMS")
	if img == nil || sums == nil {
		return "", refuse("update_no_image")
	}
	prefix := u.Download + rel.Tag + "/"
	if img.URL != prefix+name || sums.URL != prefix+"SHA256SUMS" || img.Size <= 0 || img.Size > MaxImage {
		return "", refuse("update_no_image")
	}
	tmp, err := os.MkdirTemp("", "icevault-update-")
	if err != nil {
		return "", refuse("update_failed")
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	want, err := u.sum(ctx, sums.URL, name)
	if err != nil {
		return "", err
	}
	dmg := filepath.Join(tmp, name)
	got, err := u.get(ctx, img.URL, dmg, img.Size)
	if err != nil {
		return "", err
	}
	if got != want {
		return "", refuse("update_bad_sum")
	}

	mnt := filepath.Join(tmp, "mnt")
	if err := os.Mkdir(mnt, 0o700); err != nil {
		return "", refuse("update_failed")
	}
	if _, err := u.Run(ctx, "/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mnt, dmg); err != nil {
		return "", refuse("update_bad_image")
	}
	defer func() { _, _ = u.Run(context.Background(), "/usr/bin/hdiutil", "detach", "-force", "-quiet", mnt) }()
	src := filepath.Join(mnt, "IceVault.app")
	if err := u.verify(ctx, src, rel.Tag); err != nil {
		return "", err
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", refuse("update_failed")
	}
	staged := filepath.Join(filepath.Dir(u.App), ".IceVault-"+rel.Tag+"-"+hex.EncodeToString(rnd[:])+".app")
	if _, err := u.Run(ctx, "/usr/bin/ditto", src, staged); err != nil {
		_ = os.RemoveAll(staged)
		return "", refuse("update_not_writable")
	}
	if err := u.verify(ctx, staged, rel.Tag); err != nil {
		_ = os.RemoveAll(staged)
		return "", err
	}
	return staged, nil
}

// sum reads the line of name from the SHA256SUMS of the release.
func (u *Updater) sum(ctx context.Context, url, name string) (string, error) {
	resp, err := u.request(ctx, url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", refuse("update_bad_sum")
}

// get downloads url into path (exactly size bytes) and returns its SHA-256.
func (u *Updater) get(ctx context.Context, url, path string, size int64) (string, error) {
	resp, err := u.request(ctx, url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- a file in this package's temporary folder
	if err != nil {
		return "", refuse("update_failed")
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	buf := make([]byte, 256<<10)
	var n int64
	last := -1
	for {
		k, rerr := resp.Body.Read(buf)
		if k > 0 {
			n += int64(k)
			if n > size {
				return "", refuse("update_bad_image")
			}
			if _, err := f.Write(buf[:k]); err != nil {
				return "", refuse("update_failed")
			}
			h.Write(buf[:k])
			if p := int(n * 99 / size); p != last {
				last = p
				u.progress(p)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", refuse("update_offline")
		}
	}
	if n != size {
		return "", refuse("update_bad_image")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verify checks an application folder: the bundle identifier of the running application, the version of the release, a whole code signature.
func (u *Updater) verify(ctx context.Context, app, tag string) error {
	read := func(plist, key string) string {
		out, err := u.Run(ctx, "/usr/bin/plutil", "-extract", key, "raw", "-o", "-", plist)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	plist := filepath.Join(app, "Contents", "Info.plist")
	want := read(filepath.Join(u.App, "Contents", "Info.plist"), "CFBundleIdentifier")
	if want == "" || read(plist, "CFBundleIdentifier") != want || read(plist, "CFBundleShortVersionString") != strings.TrimPrefix(tag, "v") {
		return refuse("update_bad_image")
	}
	if _, err := u.Run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", app); err != nil {
		return refuse("update_bad_signature")
	}
	return nil
}

// Apply swaps the staged copy in (two renames; the first is undone when the second fails), removes the old copy and starts the new one once this
// program has ended. The caller quits right after a nil answer.
func (u *Updater) Apply() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.init()
	if u.st.State != Ready || u.staged == "" || !exists(u.staged) {
		return refuse("update_not_ready")
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return refuse("update_failed")
	}
	old := filepath.Join(filepath.Dir(u.App), ".IceVault-old-"+hex.EncodeToString(rnd[:])+".app")
	if err := os.Rename(u.App, old); err != nil {
		return refuse("update_not_writable")
	}
	if err := os.Rename(u.staged, u.App); err != nil {
		if rerr := os.Rename(old, u.App); rerr != nil {
			return fmt.Errorf("the application folder could not be put back: %w", rerr)
		}
		return refuse("update_not_writable")
	}
	u.staged = ""
	_ = os.RemoveAll(old) // the running program keeps its open files; the folder goes now
	if err := u.Start(os.Getpid(), u.App); err != nil {
		return refuse("update_restart")
	}
	return nil
}

// Discard removes a staged copy that was not applied (the window ends without Apply).
func (u *Updater) Discard() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.staged != "" {
		_ = os.RemoveAll(u.staged)
		u.staged = ""
	}
}
