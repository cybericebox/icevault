package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Nothing that the arguments, the files or the info file alone can refuse or answer may ask for the vault password first. Every case below has a vault that
// exists (so "no vault" is not the reason) and a password prompt that counts: it must not be reached.
func TestRefusalsAndAnswersComeBeforeThePasswordPrompt(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	mustMkdir := func(p string) {
		t.Helper()
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.RemoveAll(filepath.Join(h.root, "plain", "staging")) // a known environment with no plaintext tree and no committed settings
	_ = os.Remove(filepath.Join(h.root, "deploy", "staging", "core.env"))
	nonEmpty := filepath.Join(h.dir, "full")
	mustMkdir(nonEmpty)
	if err := os.WriteFile(filepath.Join(nonEmpty, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyApp := filepath.Join(h.dir, "app")
	mustMkdir(emptyApp)
	noHome := filepath.Join(h.dir, "home")
	mustMkdir(noHome)
	h.env["HOME"] = noHome
	app := "web-client"
	// the info file says the vault holds prod (as after an import)
	inf := readInfo(h.env["ICEVAULT_VAULT"])
	if inf == nil {
		inf = freshInfo()
	}
	inf["sealed"] = map[string]any{"prod": map[string]any{"at": "2026-01-01T00:00:00Z"}}
	if err := writeInfo(h.env["ICEVAULT_VAULT"], inf); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		rc   int
		want string // in stderr, or in stdout for rc 0
	}{
		{"import: bad name", []string{"import", "--env", "Bad Name"}, 1, "is not an environment name"},
		{"import: unknown environment", []string{"import", "--env", "nothing-here"}, 1, "is not an environment here"},
		{"import: known environment, no plaintext tree", []string{"import", "--env", "staging"}, 0, "nothing to import:"},
		{"import: bad --site", []string{"import", "--env", "staging", "--site", "Bad Site"}, 1, ""},
		{"import: file outside the plaintext folder", []string{"import", "--env", "prod", "--file", "/etc/hosts"}, 1, "is not under"},
		{"import: missing file", []string{"import", "--env", "prod", "--file", "nope.sql"}, 1, "does not exist"},
		{"view: bad item", []string{"view", "--item", "nonsense"}, 1, "--item is SECTION/ITEM"},
		{"view: no environment", []string{"view"}, 1, "is not an environment name"},
		{"view: reserved name", []string{"view", "--env", "files"}, 1, "reserved"},
		{"export: no --to", []string{"export", "--env", "prod"}, 2, "export needs --to DIR"},
		{"export: bad name", []string{"export", "--env", "Bad", "--to", filepath.Join(h.dir, "o")}, 1, "is not an environment name"},
		{"export: target not empty", []string{"export", "--env", "prod", "--to", nonEmpty}, 1, "is not empty"},
		{"export --batches: no selection", []string{"export", "--env", "prod", "--batches", "--to", filepath.Join(h.dir, "o")}, 2, "names one of --site S, --product P, --all"},
		{"export --batches: two selections", []string{"export", "--env", "prod", "--batches", "--all", "--product", "portal", "--to", filepath.Join(h.dir, "o")}, 2, "names one of"},
		{"export --batches: --file", []string{"export", "--env", "prod", "--batches", "--all", "--file", "x", "--to", filepath.Join(h.dir, "o")}, 2, "--file is a file"},
		{"export --batches: target not empty", []string{"export", "--env", "prod", "--batches", "--all", "--to", nonEmpty}, 1, "is not empty"},
		{"export --batches: bad name", []string{"export", "--env", "Bad", "--batches", "--all", "--to", filepath.Join(h.dir, "o")}, 1, "is not an environment name"},
		{"export: --product without --batches", []string{"export", "--env", "prod", "--product", "portal", "--to", filepath.Join(h.dir, "o")}, 2, "add --batches"},
		{"export-app: no app", []string{"export-app", "--env", "prod"}, 2, "export-app needs --app"},
		{"export-app: unknown app", []string{"export-app", "--env", "prod", "--app", "nope"}, 2, "unknown app"},
		{"export-app: no directory", []string{"export-app", "--env", "prod", "--app", "worker-cli", "--to", filepath.Join(h.dir, "missing")}, 1, "is not a directory"},
		{"export-app: no example", []string{"export-app", "--env", "prod", "--app", app, "--to", emptyApp}, 1, "does not exist"},
		{"status: bad name", []string{"status", "--env", "Bad"}, 1, "is not an environment name"},
		{"visibility: bad name", []string{"visibility", "--env", "Bad"}, 1, "is not an environment name"},
		{"recover: bad name", []string{"recover", "--env", "Bad"}, 1, "is not an environment name"},
		{"purge: bad name", []string{"purge-plaintext", "--env", "Bad"}, 1, "is not an environment name"},
		{"purge --yes: no copy elsewhere", []string{"purge-plaintext", "--env", "staging", "--yes"}, 1, "ANOTHER volume"},
		{"purge: nothing on disk", []string{"purge-plaintext", "--env", "staging"}, 0, "would delete: 0; kept: 0"},
		{"import-hcp: no token file", []string{"import-hcp"}, 1, "has no token for app.terraform.io"},
		{"session: unknown action", []string{"session", "bogus", "--env", "prod"}, 2, "session: unknown bogus"},
		{"session run: no command", []string{"session", "run", "--env", "prod"}, 2, "session run needs -- COMMAND"},
		{"session: bad name", []string{"session", "open", "--env", "Bad"}, 1, "is not an environment name"},
		{"settings: no --out", []string{"settings", "--all"}, 2, "settings needs --out"},
		{"copy: no --to", []string{"copy"}, 2, "copy needs --to DIR"},
		{"init-vault: exists", []string{"init-vault"}, 1, "already exists"},
		{"init-vault --generate: exists", []string{"init-vault", "--generate"}, 1, "already exists"},
		{"env: no action", []string{"env", "--env", "qa"}, 2, "env needs create or fill-missing"},
		{"env create: no --env", []string{"env", "create", "--site", "compose"}, 2, "needs --env E"},
		{"env create: bad name", []string{"env", "create", "--env", "Bad", "--site", "compose", "--products", "portal"}, 1, "is not an environment name"},
		{"env create: no site", []string{"env", "create", "--env", "qa", "--products", "portal"}, 2, "needs --site KIND"},
		{"env create: no products", []string{"env", "create", "--env", "qa", "--site", "compose"}, 2, "needs --products"},
		{"env create: unknown site kind", []string{"env", "create", "--env", "qa", "--site", "moon", "--products", "portal"}, 1, "has no site kind \"moon\""},
		{"env create: unknown product", []string{"env", "create", "--env", "qa", "--site", "compose", "--products", "portal,shop"}, 1, "has no product \"shop\""},
		{"env create: product off by default", []string{"env", "create", "--env", "qa", "--site", "compose", "--products", "indexer"}, 1, "runs nowhere by default (INDEXER=none)"},
		{"env create: exists in the info file", []string{"env", "create", "--env", "prod", "--site", "google-cluster", "--products", "portal"}, 1, "holds the environment prod already"},
		{"env create: --from-checkout without settings", []string{"env", "create", "--env", "qa", "--from-checkout"}, 1, "cannot be read"},
		{"env fill-missing: extra flags", []string{"env", "fill-missing", "--env", "prod", "--site", "compose"}, 2, "takes only --env E"},
		{"guard: a folder that is not one of the rule", []string{"guard", "release", "--dir", filepath.Join(h.dir, "elsewhere")}, 1, "is not a folder of release keys"},
		{"touchid enable: not here", []string{"touchid", "enable"}, 1, "not available"},
	}
	for _, c := range cases {
		h.asked = 0
		rc := h.run(c.args...)
		got := h.errb.String()
		if c.rc == 0 {
			got = h.out.String()
		}
		if rc != c.rc || !strings.Contains(got, c.want) {
			t.Errorf("%s: rc=%d (want %d), %q lacks %q", c.name, rc, c.rc, got, c.want)
		}
		if h.asked != 0 {
			t.Errorf("%s: the password was asked for %d time(s) before the refusal", c.name, h.asked)
		}
	}
}

// Without a vault file no command that needs one asks for a password either.
func TestNoVaultFileNoPrompt(t *testing.T) {
	h := newHarness(t) // no initVault: the vault does not exist
	for _, args := range [][]string{{"import", "--env", "staging"}, {"status", "--env", "staging"}, {"view", "--env", "staging"}, {"export", "--env", "staging", "--to", filepath.Join(h.dir, "o")},
		{"visibility", "--env", "staging"}, {"recover", "--env", "staging"}, {"settings", "--all", "--out", "-"}, {"session", "open", "--env", "staging"}, {"external", "serve"}} {
		h.asked = 0
		if rc := h.run(args...); rc == 0 || !strings.Contains(h.errb.String(), "no vault at") && !strings.Contains(h.errb.String(), "needs") && !strings.Contains(h.errb.String(), "first message") {
			t.Errorf("%v: rc=%d %q", args, rc, h.errb.String())
		}
		if h.asked != 0 {
			t.Errorf("%v: asked for the password with no vault file", args)
		}
	}
}

// A known environment whose plaintext tree has files still goes on to the password (the check does not swallow real work).
func TestImportWithFilesStillUnlocks(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	h.asked = 0
	h.run("import", "--env", "staging")
	if h.asked == 0 {
		t.Fatal("an environment with files to import did not reach the password")
	}
}
