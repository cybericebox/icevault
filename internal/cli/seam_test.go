//go:build !windows

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/vmodel"
)

// The seam commands on the example project: the guards, the token file, the session directory, settings and the session itself.

// writeHCPCredentials makes a credentials file the way a session does, in a directory of its own (mode 0700).
func writeHCPCredentials(base, token string) (dir, path string, err error) {
	dir, err = os.MkdirTemp(base, "lumen-tf-"+itoa(os.Getuid())+"-")
	if err != nil {
		return "", "", err
	}
	path, err = writeCredentials(dir, token)
	return dir, path, err
}

func (h *harness) env0() *Env {
	return &Env{Getenv: func(k string) string { return h.env[k] }, Root: h.root}
}

func (h *harness) vaultOfCheckout() string {
	return filepath.Join(h.root, "plain", "vault", "lumen.kdbx")
}

func infoWith(t *testing.T, vaultFile string, sealed map[string]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(vaultFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if sealed != nil {
		if err := writeInfo(vaultFile, info{"sealed": sealed, "copies": []any{}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGuardSealed(t *testing.T) {
	h := newHarness(t)
	priv := filepath.Join(h.root, "plain", "staging")
	h.env["ICEVAULT_VAULT"] = ""
	vf := h.vaultOfCheckout()
	// no vault: no refusal
	if rc := h.run("guard", "sealed", "--private", priv); rc != 0 {
		t.Fatalf("no vault: %s", h.errb.String())
	}
	held := map[string]any{"staging": map[string]any{"files": 3, "guards": map[string]any{"release": true}, "at": "T"}}
	infoWith(t, vf, held)
	if rc := h.run("guard", "sealed", "--private", priv); rc != 1 || !strings.Contains(h.errb.String(), "holds the secrets of 'staging'") ||
		!strings.Contains(h.errb.String(), "to make new secrets here") {
		t.Fatalf("holds: rc=%d %s", rc, h.errb.String())
	}
	if rc := h.run("guard", "sealed", "--private", priv, "--what", "generate new secrets"); rc != 1 || !strings.Contains(h.errb.String(), "to generate new secrets here") {
		t.Fatal(h.errb.String())
	}
	// a vault run and the no-vault switch are exempt
	for _, v := range []string{"LUMEN_SESSION", noVaultVar} {
		h.env[v] = "1"
		if rc := h.run("guard", "sealed", "--private", priv); rc != 0 {
			t.Fatalf("%s: %s", v, h.errb.String())
		}
		delete(h.env, v)
	}
	// another environment, an empty info file
	infoWith(t, vf, nil)
	_ = os.Remove(vf)
	infoWith(t, vf, map[string]any{"prod": map[string]any{"files": 3, "guards": map[string]any{"release": true}, "at": "T"}})
	if rc := h.run("guard", "sealed", "--private", priv); rc != 0 {
		t.Fatal(h.errb.String())
	}
	_ = os.Remove(vf)
	infoWith(t, vf, map[string]any{})
	if rc := h.run("guard", "sealed", "--private", priv); rc != 0 {
		t.Fatal(h.errb.String())
	}
	// a vault without an info file: it may hold
	_ = os.Remove(infoPath(vf))
	if rc := h.run("guard", "sealed", "--private", priv); rc != 1 || !strings.Contains(h.errb.String(), "may hold") {
		t.Fatalf("%d %s", rc, h.errb.String())
	}
	// a directory that is not a plaintext tree of the checkout is not guarded
	if rc := h.run("guard", "sealed", "--private", filepath.Join(h.dir, "elsewhere")); rc != 0 {
		t.Fatal(h.errb.String())
	}
}

// The guard word of a kept-files rule (signing in the example): refused when the vault holds a file of that rule for the environment.
func TestGuardWord(t *testing.T) {
	h := newHarness(t)
	h.env["ICEVAULT_VAULT"] = ""
	vf := h.vaultOfCheckout()
	dir := filepath.Join(h.root, "plain", "staging", "keys", "compose", "release")
	infoWith(t, vf, map[string]any{"staging": map[string]any{"files": 3, "guards": map[string]any{"release": true}, "at": "T"}})
	if rc := h.run("guard", "release", "--dir", dir); rc != 1 || !strings.Contains(h.errb.String(), "to make release keys here") {
		t.Fatalf("%d %s", rc, h.errb.String())
	}
	_ = os.Remove(vf)
	infoWith(t, vf, map[string]any{"staging": map[string]any{"files": 3, "guards": map[string]any{"release": false}, "at": "T"}})
	if rc := h.run("guard", "release", "--dir", dir); rc != 0 {
		t.Fatal(h.errb.String())
	}
	// an info file of an earlier version (no guards recorded): it may hold
	_ = os.Remove(vf)
	infoWith(t, vf, map[string]any{"staging": map[string]any{"files": 3, "at": "T"}})
	if rc := h.run("guard", "release", "--dir", dir); rc != 1 || !strings.Contains(h.errb.String(), "may hold") {
		t.Fatalf("%d %s", rc, h.errb.String())
	}
	if rc := h.run("guard", "release", "--dir", filepath.Join(h.dir, "other", "keys", "a", "release")); rc != 0 {
		t.Fatal("a folder of the rule outside the plaintext trees of the project")
	}
	if rc := h.run("guard", "release", "--dir", filepath.Join(h.dir, "elsewhere")); rc != 1 || !strings.Contains(h.errb.String(), "is not a folder of release keys") {
		t.Fatalf("a path that is not a folder of the rule is refused: %d %s", rc, h.errb.String())
	}
	// the same folder through a link to the checkout: the paths are compared with their links resolved
	_ = os.Remove(vf)
	infoWith(t, vf, map[string]any{"staging": map[string]any{"files": 3, "guards": map[string]any{"release": true}, "at": "T"}})
	link := filepath.Join(h.dir, "link-to-checkout")
	if err := os.Symlink(h.root, link); err != nil {
		t.Fatal(err)
	}
	if rc := h.run("guard", "release", "--dir", filepath.Join(link, "plain", "staging", "keys", "compose", "release")); rc != 1 || !strings.Contains(h.errb.String(), "release keys") {
		t.Fatalf("a linked path slipped through: %d %s", rc, h.errb.String())
	}
	if rc := h.run("guard", "sealed", "--private", filepath.Join(link, "plain", "staging")); rc != 1 || !strings.Contains(h.errb.String(), "holds the secrets of 'staging'") {
		t.Fatalf("guard sealed through a link: %d %s", rc, h.errb.String())
	}
	if rc := h.run("guard", "nope", "--dir", dir); rc != 2 {
		t.Fatal("a word the description does not have")
	}
}

func TestGuardPlaintext(t *testing.T) {
	h := newHarness(t)
	priv := filepath.Join(h.root, "plain", "prod")
	if rc := h.run("guard", "plaintext", "--private", priv); rc != 0 || !strings.Contains(h.out.String(), "services/portal.env") || strings.Contains(h.out.String(), "notes.txt") {
		t.Fatalf("%s", h.out.String())
	}
}

func TestGuardTokenFile(t *testing.T) {
	h := newHarness(t)
	base := t.TempDir()
	dir, path, err := writeHCPCredentials(base, "tok-throwaway")
	if err != nil {
		t.Fatal(err)
	}
	if rc := h.run("guard", "token-file", path); rc != 0 {
		t.Fatal(h.errb.String())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "app.terraform.io") {
		t.Fatal("credentials block")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := h.run("guard", "token-file", path); rc != 1 || !strings.Contains(h.errb.String(), "mode 0600") {
		t.Fatal("a wrong mode was accepted")
	}
	_ = os.Chmod(path, 0o600)
	_ = os.Chmod(dir, 0o755)
	if rc := h.run("guard", "token-file", path); rc != 1 || !strings.Contains(h.errb.String(), "mode 0700") {
		t.Fatal("a loose directory was accepted")
	}
	_ = os.Chmod(dir, 0o700)
	link := filepath.Join(base, "linked")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if rc := h.run("guard", "token-file", filepath.Join(link, "credentials.tfrc.json")); rc != 1 {
		t.Fatal("a symlinked directory was accepted")
	}
	if rc := h.run("guard", "token-file", filepath.Join(base, "nothing", "credentials.tfrc.json")); rc != 1 || !strings.Contains(h.errb.String(), "cannot be checked") {
		t.Fatal(h.errb.String())
	}
	if strings.Contains(h.errb.String(), "tok-throwaway") {
		t.Fatal("the token is in an error")
	}
}

func TestStaleTokenDirectories(t *testing.T) {
	base := t.TempDir()
	stale, _, err := writeHCPCredentials(base, "t")
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "keep-me")
	target := filepath.Join(base, "target")
	_ = os.Mkdir(other, 0o700)
	_ = os.Mkdir(target, 0o700)
	link := filepath.Join(base, "lumen-tf-"+itoa(os.Getuid())+"-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	cleanStaleTF(h.env0(), base)
	if isDir(stale) {
		t.Fatal("the stale directory stays")
	}
	if !isDir(other) || !isDir(target) {
		t.Fatal("something that is not ours was removed")
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("a link was followed")
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestSessionDirIsOnePerPair(t *testing.T) {
	e := newHarness(t).env0()
	if !strings.HasSuffix(sessionDir(e, "/t", "prod", ""), "-prod") || !strings.HasSuffix(sessionDir(e, "/t", "prod", "aws-main"), "-prod-aws-main") ||
		sessionDir(e, "/t", "prod", "aws-main") == sessionDir(e, "/t", "prod", "aws-eu") || !strings.HasPrefix(filepath.Base(sessionDir(e, "/t", "prod", "")), "lumen-") {
		t.Fatal("the session directory is one per pair, named with the description's prefix")
	}
}

func TestWhereAndSettings(t *testing.T) {
	h := goldenHarness(t)
	if rc := h.run("where"); rc != 0 {
		t.Fatal(h.errb.String())
	}
	var w map[string]any
	if err := json.Unmarshal(h.out.Bytes(), &w); err != nil || w["exists"] != true || w["enabled"] != true || w["vault"] != h.env["ICEVAULT_VAULT"] {
		t.Fatalf("%v %v", w, err)
	}
	h.env["ICEVAULT_NO_VAULT"] = "1"
	h.run("where")
	_ = json.Unmarshal(h.out.Bytes(), &w)
	if w["enabled"] != false {
		t.Fatal("ICEVAULT_NO_VAULT must disable")
	}
	delete(h.env, "ICEVAULT_NO_VAULT")
	// settings go to a named file, never to stdout by default
	if rc := h.run("settings", "--all"); rc != 2 {
		t.Fatalf("rc=%d", rc)
	}
	out := filepath.Join(h.dir, "s.json")
	if rc := h.run("settings", "--all", "--out", out); rc != 0 || h.out.Len() != 0 {
		t.Fatalf("rc=%d %s %q", rc, h.errb.String(), h.out.String())
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("the settings file")
	}
	if rc := h.run("settings", "--env", "prod", "--out", "-"); rc != 0 || !strings.HasPrefix(strings.TrimSpace(h.out.String()), "{") {
		t.Fatalf("%s", h.errb.String())
	}
	// the unlock recorded what the vault holds, so the guards know without the password
	in := readInfo(h.env["ICEVAULT_VAULT"])
	if _, ok := in["sealed"].(map[string]any)["prod"]; !ok {
		t.Fatalf("info: %v", in)
	}
}

// hcpVault: the state connection of the prod site (kind hcp) has its token.
func hcpVault(t *testing.T) *harness {
	h := goldenHarness(t)
	h.editModel(func(m *vmodel.Vault) {
		s := m.Env("prod").Sites[0]
		if s.State == nil {
			t.Fatal("no state connection")
		}
		s.State.Set("token", "hcp-token-throwaway", true)
	})
	return h
}

func TestSessionOpenCloseAndRun(t *testing.T) {
	h := hcpVault(t)
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	if rc := h.run("session", "open", "--env", "prod", "--base", base); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	var s struct {
		Path, Env   string
		TFConfig    string `json:"tf_config"`
		RealPrivate string `json:"real_private"`
		TFDir       string `json:"tf_dir"`
		Manifest    map[string]string
		Vars        map[string]string
	}
	if err := json.Unmarshal(h.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.out.String(), "hcp-token-throwaway") || strings.Contains(h.out.String(), "example-cookie-key") {
		t.Fatal("a secret value in the output of session open")
	}
	if s.Path != sessionDir(h.env0(), base, "prod", "") || len(s.Manifest) != 9 || s.Vars["LUMEN_SESSION"] != "1" || s.Vars["LUMEN_FILES"] != s.Path || s.Vars["LUMEN_STAGE"] != "prod" {
		t.Fatalf("%+v", s)
	}
	st, _ := os.Stat(s.Path)
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", st.Mode())
	}
	if st, err := os.Stat(filepath.Join(s.Path, "services", "portal.env")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("settings file mode")
	}
	if st, err := os.Stat(filepath.Join(s.Path, "keys", "gcp", "release", "r1.key")); err != nil || st.Mode().Perm() != 0o400 {
		t.Fatal("release key mode")
	}
	if fi, err := os.Lstat(filepath.Join(s.Path, "dumps")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("persisted directory is not linked")
	}
	if !isDir(filepath.Join(s.RealPrivate, "dumps")) {
		t.Fatal("the real persisted directory was not made")
	}
	sf := s.Vars["ICEVAULT_SETTINGS_FILE"]
	if st, err := os.Stat(sf); err != nil || st.Mode().Perm() != 0o600 || filepath.Dir(sf) != s.TFDir {
		t.Fatalf("the settings file of the session: %v", err)
	}
	if data, _ := os.ReadFile(sf); !strings.Contains(string(data), `"all"`) || !strings.Contains(string(data), `"pair"`) || !strings.Contains(string(data), `"site_type"`) {
		t.Fatalf("settings file: %s", data)
	}
	if s.TFConfig == "" || s.Vars["TF_CLI_CONFIG_FILE"] != s.TFConfig {
		t.Fatal("no token file for terraform")
	}
	if tok, _ := os.ReadFile(s.TFConfig); !strings.Contains(string(tok), "hcp-token-throwaway") {
		t.Fatal("token file content")
	}
	// a second open is refused: a left-over is never reused
	killOwner(t, s.Path)
	if rc := h.run("session", "open", "--env", "prod", "--base", base); rc != 1 || !strings.Contains(h.errb.String(), "is left over from a run that was killed") {
		t.Fatalf("%s", h.errb.String())
	}
	// a file made by the run that is not on the list is noted and dropped; a new file on the list is written back
	_ = os.WriteFile(filepath.Join(s.Path, "scratch.txt"), []byte("x"), 0o600)
	if err := os.MkdirAll(filepath.Join(s.Path, "keys", "gcp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Path, "keys", "gcp", "made-by-a-step"), []byte("fresh"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := h.run("session", "close", "--env", "prod", "--base", base); rc != 0 || !strings.Contains(h.out.String(), "vault: written back after the run: 1 new,") ||
		!strings.Contains(h.out.String(), "1 file(s) made in the session are not kept") {
		t.Fatalf("rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	if isDir(s.Path) || isDir(s.TFDir) {
		t.Fatal("the tree and the token directory must be gone")
	}
}

func TestSessionCloseWithoutChangesAndRun(t *testing.T) {
	h := goldenHarness(t)
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	if rc := h.run("session", "open", "--env", "prod", "--base", base); rc != 0 {
		t.Fatal(h.errb.String())
	}
	dir := sessionDir(h.env0(), base, "prod", "")
	_ = os.WriteFile(filepath.Join(dir, "scratch.txt"), []byte("x"), 0o600)
	if rc := h.run("session", "close", "--env", "prod", "--base", base); rc != 0 || !strings.Contains(h.out.String(), "1 file(s) made in the session are not kept") {
		t.Fatalf("rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	if isDir(dir) {
		t.Fatal("the tree was not removed")
	}
	if rc := h.run("session", "close", "--env", "prod", "--base", base); rc != 1 || !strings.Contains(h.errb.String(), "no session directory") {
		t.Fatal(h.errb.String())
	}
	// run: the child sees the session, its exit code is ours, the tree is gone afterwards
	script := `test "$LUMEN_SESSION" = 1 && test "$LUMEN_STAGE" = prod && test -f "$LUMEN_FILES/services/portal.env" && exit 7`
	if rc := h.run("session", "run", "--env", "prod", "--base", base, "--", "sh", "-c", script); rc != 7 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if isDir(dir) {
		t.Fatal("run left the tree")
	}
	if rc := h.run("session", "run", "--env", "prod", "--base", base, "--", "sh", "-c", "exit 0"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if rc := h.run("session", "run", "--env", "prod", "--base", base); rc != 2 {
		t.Fatal("run without a command")
	}
	if rc := h.run("session", "open", "--env", "dev", "--base", base); rc != 1 || !strings.Contains(h.errb.String(), "the vault holds nothing for 'dev'") {
		t.Fatal(h.errb.String())
	}
}

// A session directory that is a link, or that others can read or write, is never read back into the vault (a predictable name in a shared temp directory).
func TestSessionCloseAndRecoverRefuseUnsafeDirectories(t *testing.T) {
	h := goldenHarness(t)
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	dir := sessionDir(h.env0(), base, "prod", "")
	// an open-to-others directory
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(dir, "shop"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "services", "portal.env"), []byte("COOKIE_KEY=planted\n"), 0o644)
	for _, args := range [][]string{{"session", "close", "--env", "prod", "--base", base}, {"recover", "--env", "prod", "--base", base}} {
		if rc := h.run(args...); rc != 1 || !strings.Contains(h.errb.String(), "is not a real directory of this user with mode 0700") {
			t.Fatalf("%v: rc=%d %s", args, rc, h.errb.String())
		}
		h.errb.Reset()
	}
	if !isDir(dir) {
		t.Fatal("an unsafe directory was removed instead of being left for a look")
	}
	// a link
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(h.dir, "elsewhere")
	_ = os.Mkdir(target, 0o700)
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"session", "close", "--env", "prod", "--base", base}, {"recover", "--env", "prod", "--base", base}} {
		if rc := h.run(args...); rc != 1 || !strings.Contains(h.errb.String(), "is not a real directory of this user") {
			t.Fatalf("link %v: rc=%d %s", args, rc, h.errb.String())
		}
		h.errb.Reset()
	}
}

// The templates folder may be a link (a checkout that shares its samples): the project loads through it.
func TestLoadProjectThroughSymlinkedTemplates(t *testing.T) {
	h := newHarness(t)
	moved := filepath.Join(h.dir, "samples-elsewhere")
	if err := os.Rename(filepath.Join(h.root, "templates"), moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, filepath.Join(h.root, "templates")); err != nil {
		t.Fatal(err)
	}
	p, err := LoadProject(h.root)
	if err != nil || len(p.Manifest("services/portal.env")) == 0 || p.Manifest("services/portal.env")[0].Key != "PUBLIC_HOST" {
		t.Fatalf("%v", err)
	}
}

// A file of the vault that is not on the list (one the owner added in the window) is rendered into the session by the session itself: closing it
// must not call it "made in the session"; a change the run made to it is said to be not written back, and the vault keeps the owner's copy.
func TestSessionVaultFileNotOnTheList(t *testing.T) {
	h := goldenHarness(t)
	h.editModel(func(m *vmodel.Vault) {
		e := m.Env("prod")
		e.Files = append(e.Files, &vmodel.File{Rel: "notes/runbook.md", Data: []byte("# runbook\n"), Mode: 0o600, Managed: vmodel.ManagedOwner, Vis: vmodel.VisSecret})
	})
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	dir := sessionDir(h.env0(), base, "prod", "")
	open := func() {
		t.Helper()
		if rc := h.run("session", "open", "--env", "prod", "--base", base); rc != 0 {
			t.Fatal(h.errb.String())
		}
		if b, err := os.ReadFile(filepath.Join(dir, "notes", "runbook.md")); err != nil || string(b) != "# runbook\n" {
			t.Fatalf("the vault file is not in the session: %v", err)
		}
	}
	open()
	if rc := h.run("session", "close", "--env", "prod", "--base", base); rc != 0 || strings.Contains(h.out.String(), "made in the session") || strings.Contains(h.out.String(), "NOT written back") {
		t.Fatalf("rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	open()
	_ = os.WriteFile(filepath.Join(dir, "notes", "runbook.md"), []byte("changed by a step\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "scratch.txt"), []byte("x"), 0o600)
	out := ""
	if rc := h.run("session", "close", "--env", "prod", "--base", base); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	out = h.out.String()
	if !strings.Contains(out, "1 file(s) of the vault the run changed were NOT written back (not on the list; change them in the app): notes/runbook.md") ||
		!strings.Contains(out, "1 file(s) made in the session are not kept (no rule of the project description keeps them): scratch.txt") {
		t.Fatalf("%s", out)
	}
	open() // the vault still holds the owner's copy
	if rc := h.run("session", "close", "--env", "prod", "--base", base); rc != 0 {
		t.Fatal(h.errb.String())
	}
}

// A guard that cannot read the project description refuses: it never lets a run through on a guess.
func TestGuardsRefuseWithoutTheDescription(t *testing.T) {
	h := newHarness(t)
	h.env["ICEVAULT_VAULT"] = ""
	vf := h.vaultOfCheckout()
	infoWith(t, vf, map[string]any{"staging": map[string]any{"files": 3, "guards": map[string]any{"release": false}, "at": "T"}})
	if err := os.WriteFile(filepath.Join(h.root, "icevault-project.yaml"), []byte("format: 2\nname: [broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := h.run("guard", "sealed", "--private", filepath.Join(h.root, "plain", "staging")); rc != 1 || !strings.Contains(h.errb.String(), "so this run is refused") {
		t.Fatalf("guard sealed: %d %s", rc, h.errb.String())
	}
	if rc := h.run("guard", "release", "--dir", filepath.Join(h.root, "plain", "staging", "keys", "compose", "release")); rc != 1 || !strings.Contains(h.errb.String(), "so this run is refused") {
		t.Fatalf("guard word: %d %s", rc, h.errb.String())
	}
	// the switch that says there is no vault still lets a run through
	h.env[noVaultVar] = "1"
	if rc := h.run("guard", "sealed", "--private", filepath.Join(h.root, "plain", "staging")); rc != 0 {
		t.Fatalf("no vault: %d %s", rc, h.errb.String())
	}
}
