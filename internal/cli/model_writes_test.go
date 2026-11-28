//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The commands that write the vault, on the vault model: a session run, a killed run and recover, an import that changes a tree, and the token
// of the state connection a session hands over.

func TestSessionRunAndRecoverChangeTheModel(t *testing.T) {
	h := goldenHarness(t)
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	script := `mkdir -p "$LUMEN_FILES/keys/gcp" && printf fresh > "$LUMEN_FILES/keys/gcp/made-by-a-step" && sed -i.bak 's/^EXPORT_BUCKET=.*/EXPORT_BUCKET=made-by-the-run/' "$LUMEN_FILES/targets/gcp.env" && rm "$LUMEN_FILES/targets/gcp.env.bak"`
	if rc := h.run("session", "run", "--env", "prod", "--base", base, "--", "sh", "-c", script); rc != 0 {
		t.Fatalf("session run: %s %s", h.out.String(), h.errb.String())
	}
	to := filepath.Join(h.dir, "after-run")
	exported(t, h, to)
	if b, _ := os.ReadFile(filepath.Join(to, "targets", "gcp.env")); !strings.Contains(string(b), "EXPORT_BUCKET=made-by-the-run") || !strings.Contains(string(b), "GCP_ZONE=europe-north1-a") {
		t.Fatalf("the system value the run changed is not in the vault:\n%s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(to, "keys", "gcp", "made-by-a-step")); string(b) != "fresh" {
		t.Fatal("the file the run made is not in the vault")
	}
	if rc := h.run("session", "open", "--env", "prod", "--base", base); rc != 0 {
		t.Fatal(h.errb.String())
	}
	dir := sessionDir(h.env0(), base, "prod", "")
	_ = os.WriteFile(filepath.Join(dir, "keys", "gcp", "from-a-killed-run"), []byte("kept"), 0o600)
	killOwner(t, dir)
	if rc := h.run("recover", "--env", "prod", "--base", base); rc != 0 {
		t.Fatalf("recover: %s %s", h.out.String(), h.errb.String())
	}
	to = filepath.Join(h.dir, "after-recover")
	exported(t, h, to)
	if b, _ := os.ReadFile(filepath.Join(to, "keys", "gcp", "from-a-killed-run")); string(b) != "kept" {
		t.Fatal("not recovered")
	}
}

// An import of a changed tree: a system value changes, an owner value that is set is left as it is, a new key goes to the file it came from.
func TestImportOfAChangedTree(t *testing.T) {
	h := goldenHarness(t)
	private := filepath.Join(h.root, "plain", "prod")
	pf := filepath.Join(private, "services", "engine.env")
	data, _ := os.ReadFile(pf)
	data = []byte(strings.Replace(strings.Replace(string(data), "ENGINE_PROFILE_DIR=/srv/lumen/engine/profile", "ENGINE_PROFILE_DIR=/srv/chart", 1), "ENGINE_THREADS=8", "ENGINE_THREADS=9", 1) + "NEW_ONE=added\n")
	if err := os.WriteFile(pf, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := h.importEnv("prod"); rc != 0 {
		t.Fatalf("%s %s", h.out.String(), h.errb.String())
	}
	if !strings.Contains(h.out.String(), "1 owner entry(ies) differ from the file and were left as they are") || !strings.Contains(h.out.String(), "services/engine.env/ENGINE_THREADS") {
		t.Fatalf("%s", h.out.String())
	}
	to := filepath.Join(h.dir, "out")
	exported(t, h, to)
	got, _ := os.ReadFile(filepath.Join(to, "services", "engine.env"))
	if !strings.Contains(string(got), "ENGINE_PROFILE_DIR=/srv/chart") || !strings.Contains(string(got), "ENGINE_THREADS=8") || !strings.Contains(string(got), "NEW_ONE=added") {
		t.Fatalf("%s", got)
	}
}

func TestImportHCPGoesToTheStateConnection(t *testing.T) {
	h := goldenHarness(t)
	home := filepath.Join(h.dir, "home")
	h.env["HOME"] = home
	cred := filepath.Join(home, ".terraform.d", "credentials.tfrc.json")
	_ = os.MkdirAll(filepath.Dir(cred), 0o700)
	_ = os.WriteFile(cred, []byte(`{"credentials":{"app.terraform.io":{"token":"hcp-secret-throwaway"}}}`), 0o600)
	if rc := h.run("import-hcp"); rc != 0 {
		t.Fatalf("%s %s", h.out.String(), h.errb.String())
	}
	if tok := mustSessionToken(t, h); tok != "hcp-secret-throwaway" {
		t.Fatalf("the session hands over %q", tok)
	}
}

// A vault that has no connection for a served name gets one on the first put.
func TestExternalServeMakesTheConnection(t *testing.T) {
	h := goldenHarness(t)
	if rc, out := runExternal(h, extOpen, `{"op":"put","group":"monitoring","key":"MONITOR_KEY","value":"tok-3"}`, `{"op":"close"}`); rc != 0 || out[1]["ok"] != true {
		t.Fatalf("%v %s", out, h.errb.String())
	}
	if rc, out := runExternal(h, extOpen, `{"op":"get","group":"monitoring","key":"MONITOR_KEY"}`, `{"op":"close"}`); rc != 0 || out[1]["value"] != "tok-3" {
		t.Fatalf("%v %s", out, h.errb.String())
	}
}
