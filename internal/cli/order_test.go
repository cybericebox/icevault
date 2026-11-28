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
	noHome := filepath.Join(h.dir, "home")
	mustMkdir(noHome)
	h.env["HOME"] = noHome
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
		{"view: bad item", []string{"view", "--item", "nonsense"}, 1, "--item is SECTION/ITEM"},
		{"view: no environment", []string{"view"}, 1, "is not an environment name"},
		{"view: reserved name", []string{"view", "--env", "files"}, 1, "reserved"},
		{"export: no --to", []string{"export", "--env", "prod"}, 2, "export needs --to DIR"},
		{"export: bad name", []string{"export", "--env", "Bad", "--to", filepath.Join(h.dir, "o")}, 1, "is not an environment name"},
		{"export: target not empty", []string{"export", "--env", "prod", "--to", nonEmpty}, 1, "is not empty"},
		{"status: bad name", []string{"status", "--env", "Bad"}, 1, "is not an environment name"},
		{"visibility: bad name", []string{"visibility", "--env", "Bad"}, 1, "is not an environment name"},
		{"recover: bad name", []string{"recover", "--env", "Bad"}, 1, "is not an environment name"},
		{"import-hcp: no token file", []string{"import-hcp"}, 1, "has no token for app.terraform.io"},
		{"session: unknown action", []string{"session", "bogus", "--env", "prod"}, 2, "session: unknown bogus"},
		{"session run: no command", []string{"session", "run", "--env", "prod"}, 2, "session run needs -- COMMAND"},
		{"settings: no --out", []string{"settings", "--all"}, 2, "settings needs --out"},
		{"copies now: no folder", []string{"copies", "now"}, 1, "copies now needs a folder"},
		{"removed: copy", []string{"copy", "--to", "x"}, 2, "unknown command"},
		{"removed: import", []string{"import", "--env", "prod"}, 2, "unknown command"},
		{"removed: purge-plaintext", []string{"purge-plaintext", "--env", "prod"}, 2, "unknown command"},
		{"removed: keyfile", []string{"keyfile", "new", "x"}, 2, "unknown command"},
		{"env create: gone", []string{"env", "create", "--env", "qa"}, 2, "env needs adopt-connections"},
		{"env fill-missing: gone", []string{"env", "fill-missing", "--env", "prod"}, 2, "env needs adopt-connections"},
		{"visibility: no --apply", []string{"visibility", "--env", "prod", "--apply"}, 2, ""},
		{"init-vault: exists", []string{"init-vault"}, 1, "already exists"},
		{"init-vault --generate: exists", []string{"init-vault", "--generate"}, 1, "already exists"},
		{"init-vault --no-project: exists", []string{"init-vault", "--no-project"}, 1, "already exists"},
		{"env: no action", []string{"env", "--env", "qa"}, 2, "env needs adopt-connections"},
		{"set: no --env", []string{"set", "A=1"}, 2, "set needs --env E"},
		{"set: no assignment", []string{"set", "--env", "prod"}, 2, "needs at least one KEY=VALUE"},
		{"set: not KEY=VALUE", []string{"set", "--env", "prod", "ENGINE_THREADS"}, 2, "is not KEY=VALUE"},
		{"set: bad key", []string{"set", "--env", "prod", "1BAD=2"}, 2, "is not a variable name"},
		{"set: key twice", []string{"set", "--env", "prod", "A=1", "A=2"}, 2, "is given twice"},
		{"set: bad env name", []string{"set", "--env", "Bad", "A=1"}, 1, "is not an environment name"},
		{"set: bad scope", []string{"set", "--env", "prod", "--scope", "nonsense", "A=1"}, 1, "is not a scope"},
		{"set: scope of another environment", []string{"set", "--env", "prod", "--scope", "env/staging/general", "A=1"}, 1, "is not in the environment prod"},
		{"set: a reference", []string{"set", "--env", "prod", "A=${{x}}"}, 1, "holds a reference"},
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
	for _, args := range [][]string{{"status", "--env", "staging"}, {"view", "--env", "staging"}, {"export", "--env", "staging", "--to", filepath.Join(h.dir, "o")},
		{"visibility", "--env", "staging"}, {"recover", "--env", "staging"}, {"settings", "--all", "--out", "-"}, {"external", "serve"}} {
		h.asked = 0
		if rc := h.run(args...); rc == 0 || !strings.Contains(h.errb.String(), "no vault at") && !strings.Contains(h.errb.String(), "needs") && !strings.Contains(h.errb.String(), "first message") {
			t.Errorf("%v: rc=%d %q", args, rc, h.errb.String())
		}
		if h.asked != 0 {
			t.Errorf("%v: asked for the password with no vault file", args)
		}
	}
}
