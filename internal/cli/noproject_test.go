package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/example"
)

func TestInitVaultNoProjectMakesAVaultAnywhere(t *testing.T) {
	h := newHarness(t)
	h.root = "" // outside any project
	h.pw = []string{"k7Qm2xVb9RtZ", "k7Qm2xVb9RtZ"}
	rc := h.run("init-vault", "--no-project", "--decryption-time", "100")
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	p := h.env["ICEVAULT_VAULT"]
	if !vaultOpens(t, h, "k7Qm2xVb9RtZ") || !IsNoProject(p) {
		t.Fatal("the vault is not made, or not marked as one without a project")
	}
	if !strings.Contains(h.out.String(), "no project") {
		t.Fatalf("the next steps do not say that the vault has no project: %s", h.out.String())
	}
}

// The marker is in the info file only: the project description is never written.
func TestNoProjectWritesNoDescription(t *testing.T) {
	h := newHarness(t)
	h.root = ""
	h.pw = []string{"k7Qm2xVb9RtZ", "k7Qm2xVb9RtZ"}
	if rc := h.run("init-vault", "--no-project", "--decryption-time", "100"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	entries, err := os.ReadDir(filepath.Dir(h.env["ICEVAULT_VAULT"]))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
			t.Fatalf("a description was written: %s", e.Name())
		}
	}
}

func TestInitVaultNoProjectNeedsAPath(t *testing.T) {
	h := newHarness(t)
	h.root = ""
	delete(h.env, "ICEVAULT_VAULT")
	h.pw = []string{"k7Qm2xVb9RtZ", "k7Qm2xVb9RtZ"}
	rc := h.run("init-vault", "--no-project")
	if rc != 1 || !strings.Contains(h.errb.String(), "--vault PATH") || h.asked != 0 {
		t.Fatalf("rc=%d asked=%d %q", rc, h.asked, h.errb.String())
	}
	// without --no-project the refusal points to it
	h.run("init-vault")
	if !strings.Contains(h.errb.String(), "--no-project") {
		t.Fatalf("the refusal does not mention --no-project: %q", h.errb.String())
	}
}

// A command that needs environments says that this vault has none, before it asks for the password.
func TestCommandsThatNeedEnvironmentsSayTheVaultHasNoProject(t *testing.T) {
	h := newHarness(t)
	h.root = ""
	h.pw = []string{"k7Qm2xVb9RtZ", "k7Qm2xVb9RtZ"}
	if rc := h.run("init-vault", "--no-project", "--decryption-time", "100"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	for _, args := range [][]string{{"status", "--env", "prod"}, {"view", "--env", "prod"}, {"export", "--env", "prod", "--to", filepath.Join(h.dir, "o")},
		{"env", "adopt-connections", "--env", "qa"}} {
		h.asked = 0
		rc := h.run(args...)
		if rc != 1 || !strings.Contains(h.errb.String(), "this vault has no project") || h.asked != 0 {
			t.Errorf("%v: rc=%d asked=%d %q", args, rc, h.asked, h.errb.String())
		}
	}
	// a vault that is not marked keeps the old, longer refusal
	h2 := newHarness(t)
	h2.initVault()
	h2.root = ""
	rc := h2.run("status", "--env", "prod")
	if rc != 1 || strings.Contains(h2.errb.String(), "this vault has no project") {
		t.Fatalf("rc=%d %q", rc, h2.errb.String())
	}
}

// The mark is honoured only when no project is found: with a description the commands work on the vault as before.
func TestTheMarkIsIgnoredWhenAProjectIsFound(t *testing.T) {
	h := newHarness(t)
	h.root = ""
	h.pw = []string{"k7Qm2xVb9RtZ", "k7Qm2xVb9RtZ"}
	if rc := h.run("init-vault", "--no-project", "--decryption-time", "100"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	h.root = filepath.Join(h.dir, "project") // a checkout with its description
	if err := example.Write(h.root); err != nil {
		t.Fatal(err)
	}
	h.pw = []string{"k7Qm2xVb9RtZ"}
	h.asked = 0
	h.run("status", "--env", "prod")
	if strings.Contains(h.errb.String(), "this vault has no project") || h.asked == 0 {
		t.Fatalf("a marked vault was refused although a project is found: asked=%d %q", h.asked, h.errb.String())
	}
}

func TestMarkNoProjectKeepsTheRestOfTheInfoFile(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	p := h.env["ICEVAULT_VAULT"]
	inf := readInfo(p)
	inf["sealed"] = map[string]any{"prod": map[string]any{"at": "2026-01-01T00:00:00Z"}}
	if err := writeInfo(p, inf); err != nil {
		t.Fatal(err)
	}
	if IsNoProject(p) {
		t.Fatal("marked before it was")
	}
	if err := MarkNoProject(p); err != nil || !IsNoProject(p) {
		t.Fatalf("%v", err)
	}
	if _, ok := readInfo(p)["sealed"].(map[string]any)["prod"]; !ok {
		t.Fatal("the info file lost what it held")
	}
	// a vault with no info file at all gets a fresh one with the marker
	loose := filepath.Join(h.dir, "loose.kdbx")
	if err := MarkNoProject(loose); err != nil || !IsNoProject(loose) {
		t.Fatalf("%v", err)
	}
}
