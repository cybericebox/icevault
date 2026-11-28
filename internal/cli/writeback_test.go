//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The write-back of a session and the commands on top of the sync of a tree: a secret made by a step is in the vault afterwards, a failing step still
// writes back and wipes, a key ring travels through sessions, recover, import-hcp, import --file.

func exported(t *testing.T, h *harness, to string) bool {
	t.Helper()
	if rc := h.run("export", "--env", "prod", "--to", to); rc != 0 {
		t.Fatal(h.errb.String())
	}
	return true
}

func TestASecretMadeByAStepIsInTheVaultAfterwards(t *testing.T) {
	h := goldenHarness(t)
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	script := `mkdir -p "$LUMEN_FILES/keys/gcp" && printf fresh > "$LUMEN_FILES/keys/gcp/made-by-a-step"`
	if rc := h.run("session", "run", "--env", "prod", "--base", base, "--", "sh", "-c", script); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if !strings.Contains(h.out.String(), "vault: written back after the run: 1 new") {
		t.Fatal(h.out.String())
	}
	if isDir(sessionDir(h.env0(), base, "prod", "")) {
		t.Fatal("the tree was not wiped")
	}
	to := filepath.Join(h.dir, "out")
	exported(t, h, to)
	if got, err := os.ReadFile(filepath.Join(to, "keys", "gcp", "made-by-a-step")); err != nil || string(got) != "fresh" {
		t.Fatalf("the file is not in the vault: %v", err)
	}
	// the info file knows (the guards need it)
	if in := readInfo(h.env["ICEVAULT_VAULT"]); in == nil {
		t.Fatal("no info")
	}
}

func TestAFailingStepStillWritesBackAndWipes(t *testing.T) {
	h := goldenHarness(t)
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	script := `mkdir -p "$LUMEN_FILES/keys/gcp" && printf before > "$LUMEN_FILES/keys/gcp/made-before-the-failure"; exit 3`
	if rc := h.run("session", "run", "--env", "prod", "--base", base, "--", "sh", "-c", script); rc != 3 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if isDir(sessionDir(h.env0(), base, "prod", "")) {
		t.Fatal("not wiped")
	}
	to := filepath.Join(h.dir, "out")
	exported(t, h, to)
	if _, err := os.Stat(filepath.Join(to, "keys", "gcp", "made-before-the-failure")); err != nil {
		t.Fatal("a failing step lost its file")
	}
}

func TestRecoverWritesALeftOverSessionIntoTheVault(t *testing.T) {
	h := goldenHarness(t)
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	if rc := h.run("session", "open", "--env", "prod", "--base", base); rc != 0 {
		t.Fatal(h.errb.String())
	}
	dir := sessionDir(h.env0(), base, "prod", "")
	_ = os.MkdirAll(filepath.Join(dir, "keys", "gcp"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "keys", "gcp", "from-a-killed-run"), []byte("kept"), 0o600)
	killOwner(t, dir)
	// the run was killed: no close. A new open is refused, recover writes the files and removes the directory
	if rc := h.run("recover", "--env", "prod", "--base", filepath.Join(h.dir, "nowhere")); rc != 1 || !strings.Contains(h.errb.String(), "no left-over session directory") {
		t.Fatal(h.errb.String())
	}
	if rc := h.run("recover", "--env", "prod", "--base", base); rc != 0 || !strings.Contains(h.out.String(), "recovered into the vault: 1 new,") {
		t.Fatalf("rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	if isDir(dir) {
		t.Fatal("the directory was not removed")
	}
	to := filepath.Join(h.dir, "out")
	exported(t, h, to)
	if _, err := os.Stat(filepath.Join(to, "keys", "gcp", "from-a-killed-run")); err != nil {
		t.Fatal("not recovered")
	}
}

func TestAKeyRingTravelsThroughSessions(t *testing.T) {
	h := goldenHarness(t)
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	ring := filepath.Join("keys", "gcp", "ring")
	put := func(dir, rel, text string) {
		p := filepath.Join(dir, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	session := func(f func(dir string)) {
		t.Helper()
		if rc := h.run("session", "open", "--env", "prod", "--base", base); rc != 0 {
			t.Fatalf("open: %s", h.errb.String())
		}
		dir := sessionDir(h.env0(), base, "prod", "")
		f(dir)
		if rc := h.run("session", "close", "--env", "prod", "--base", base); rc != 0 {
			t.Fatalf("close: rc=%d %s %s", rc, h.out.String(), h.errb.String())
		}
	}
	oldKey, newKey := strings.Repeat("A", 43)+"=\n", strings.Repeat("B", 43)+"=\n"
	session(func(dir string) { // the first run makes the ring
		put(dir, filepath.Join(ring, "order"), "key1 aescbc\n")
		put(dir, filepath.Join(ring, "key1.key"), oldKey)
	})
	session(func(dir string) { // a rotation: the ring came back from the vault, the phases change `order`, a new key appears
		if b, err := os.ReadFile(filepath.Join(dir, ring, "order")); err != nil || string(b) != "key1 aescbc\n" {
			t.Fatalf("the ring did not come back: %v %q", err, b)
		}
		put(dir, filepath.Join(ring, "order"), "# rotation phase=added old=key1 new=key2\nkey1 aescbc\nkey2 secretbox\n")
		put(dir, filepath.Join(ring, "key2.key"), newKey)
	})
	session(func(dir string) { // the end: the old key moves to retired/ on disk
		_ = os.MkdirAll(filepath.Join(dir, ring, "retired"), 0o700)
		if err := os.Rename(filepath.Join(dir, ring, "key1.key"), filepath.Join(dir, ring, "retired", "key1.key")); err != nil {
			t.Fatal(err)
		}
		put(dir, filepath.Join(ring, "order"), "key2 secretbox\n")
	})
	to := filepath.Join(h.dir, "out")
	exported(t, h, to)
	if _, err := os.Stat(filepath.Join(to, ring, "key1.key")); err == nil {
		t.Fatal("the old key stays in the ring")
	}
	for _, rel := range []string{filepath.Join(ring, "retired", "key1.key"), filepath.Join(ring, "key2.key"), filepath.Join(ring, "order")} {
		if _, err := os.Stat(filepath.Join(to, rel)); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
	}
}

func TestImportHCPAndImportFile(t *testing.T) {
	h := goldenHarness(t)
	home := filepath.Join(h.dir, "home")
	h.env["HOME"] = home
	if rc := h.run("import-hcp"); rc != 1 || !strings.Contains(h.errb.String(), "terraform login") {
		t.Fatalf("%s", h.errb.String())
	}
	cred := filepath.Join(home, ".terraform.d", "credentials.tfrc.json")
	_ = os.MkdirAll(filepath.Dir(cred), 0o700)
	_ = os.WriteFile(cred, []byte(`{"credentials":{"app.terraform.io":{"token":"hcp-secret-throwaway"}}}`), 0o600)
	if rc := h.run("import-hcp"); rc != 0 || !strings.Contains(h.out.String(), "token imported into the connection Terraform Cloud (20 characters)") {
		t.Fatalf("%s %s", h.out.String(), h.errb.String())
	}
	if strings.Contains(h.out.String()+h.errb.String(), "hcp-secret-throwaway") {
		t.Fatal("the token was printed")
	}
	if rc := h.run("import-hcp"); rc != 0 || !strings.Contains(h.out.String(), "the token of the connection Terraform Cloud exists already (the same as the file)") {
		t.Fatal(h.out.String())
	}
	_ = os.WriteFile(cred, []byte(`{"credentials":{"app.terraform.io":{"token":"another-token"}}}`), 0o600)
	if rc := h.run("import-hcp"); rc != 0 || !strings.Contains(h.out.String(), "DIFFERS from the file: the vault wins, nothing changed") {
		t.Fatal(h.out.String())
	}
	// the token is the one a session hands to terraform
	if tok := mustSessionToken(t, h); tok != "hcp-secret-throwaway" {
		t.Fatalf("token %q", tok)
	}
}

func mustSessionToken(t *testing.T, h *harness) string {
	t.Helper()
	base := filepath.Join(h.dir, "tmp2")
	_ = os.Mkdir(base, 0o700)
	var got string
	if rc := h.run("session", "open", "--env", "prod", "--base", base); rc != 0 {
		t.Fatal(h.errb.String())
	}
	out := h.out.String()
	i := strings.Index(out, "\"tf_config\": \"")
	if i < 0 {
		t.Fatalf("no token file in %s", out)
	}
	rest := out[i+len("\"tf_config\": \""):]
	path := rest[:strings.Index(rest, "\"")]
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "hcp-secret-throwaway") {
		got = "hcp-secret-throwaway"
	}
	if rc := h.run("session", "close", "--env", "prod", "--base", base); rc != 0 {
		t.Fatal(h.errb.String())
	}
	return got
}

// The report of the import of the example's prod tree into a new vault, the view after it, a second import that changes nothing, and the info
// file that records the guarded files.
func TestGoldenImport(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	if rc := h.importEnv("prod"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	golden(t, "import-report.txt", h.out.String())
	if rc := h.importEnv("prod"); rc != 0 || !strings.Contains(h.out.String(), "imported: 0 new, 0 changed; 10 unchanged") {
		t.Fatalf("%s", h.out.String())
	}
	in := readInfo(h.env["ICEVAULT_VAULT"])
	sealed, _ := in["sealed"].(map[string]any)
	d, _ := sealed["prod"].(map[string]any)
	g, _ := d["guards"].(map[string]any)
	if g["release"] != true {
		t.Fatalf("info %v", in)
	}
}
