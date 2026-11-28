package cli

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// The commands on the example project (internal/example, Lumen Notes): a throwaway vault made by init-vault and filled by the import of the
// example's plaintext trees of prod and staging. The expected output is in testdata/golden; `go test ./internal/cli -run Golden -update` writes it
// again (only when the behaviour is meant to change).

var update = flag.Bool("update", false, "write the golden files of testdata/golden")

func goldenHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.initVault()
	h.trust()
	for _, env := range []string{"prod", "staging"} {
		if rc := h.importEnv(env); rc != 0 {
			t.Fatalf("import %s: rc=%d %s %s", env, rc, h.out.String(), h.errb.String())
		}
	}
	return h
}

// editModel changes the model of the harness's vault and saves it.
func (h *harness) editModel(fn func(m *vmodel.Vault)) {
	h.t.Helper()
	v, err := vault.Open(h.env["ICEVAULT_VAULT"], vault.Credentials{Password: []byte(pw)})
	if err != nil {
		h.t.Fatal(err)
	}
	defer v.Close()
	m, err := vmodel.Load(v)
	if err != nil {
		h.t.Fatal(err)
	}
	fn(m)
	if err := vmodel.Sync(v, m); err != nil {
		h.t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		h.t.Fatal(err)
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != got {
		t.Fatalf("%s differs\n--- got\n%s--- want\n%s", name, got, b)
	}
}

var stampRE = regexp.MustCompile(`\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ`)

// stamps: the vault stamps entries with the time they were made; only that column is normalised.
func stamps(s string) string { return stampRE.ReplaceAllString(s, "2026-01-02T03:04:05Z") }

// paths: the temp folders of a run are normalised.
func (h *harness) paths(s string) string { return strings.ReplaceAll(s, h.dir, "<tmp>") }

func TestGoldenView(t *testing.T) {
	h := goldenHarness(t)
	if rc := h.run("view", "--env", "prod"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	golden(t, "view-prod.txt", stamps(h.out.String()))
	if rc := h.run("view", "--env", "staging"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	golden(t, "view-staging.txt", stamps(h.out.String()))
	if rc := h.run("visibility", "--env", "prod"); rc != 0 {
		t.Fatalf("visibility: rc=%d %s", rc, h.errb.String())
	}
	golden(t, "visibility-prod.txt", h.out.String())
	for _, secret := range []string{"example-secret-access-key", "example-blob-secret", "example-cookie-key"} {
		if strings.Contains(h.out.String(), secret) {
			t.Fatal("a value in the output")
		}
	}
}

// The export gives the project's files back byte for byte as they were imported (the layouts keep comments, order and quoting).
func TestGoldenExport(t *testing.T) {
	h := goldenHarness(t)
	to := filepath.Join(h.dir, "out")
	if rc := h.run("export", "--env", "prod", "--to", to); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	golden(t, "export-prod.txt", h.paths(h.out.String()))
	src := filepath.Join(h.root, "plain", "prod")
	var seen int
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "readme.txt" { // not a file of the project: never imported
			return nil
		}
		want, _ := os.ReadFile(p)
		got, err := os.ReadFile(filepath.Join(to, rel))
		if err != nil {
			t.Errorf("%s: not written", rel)
			return nil
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from the imported file\n--- export\n%s--- imported\n%s", rel, got, want)
		}
		st, _ := os.Stat(filepath.Join(to, rel))
		wantMode := os.FileMode(0o600)
		if strings.Contains(rel, "/release/") {
			wantMode = 0o400 // the mode of the rule of kept-files
		}
		if st.Mode().Perm() != wantMode {
			t.Errorf("%s: mode %v", rel, st.Mode().Perm())
		}
		seen++
		return nil
	})
	if err != nil || seen != 9 {
		t.Fatalf("seen %d %v", seen, err)
	}
	if rc := h.run("export", "--env", "prod", "--to", to); rc != 1 || !strings.Contains(h.errb.String(), "is not empty") {
		t.Fatalf("%s", h.errb.String())
	}
	if rc := h.run("export", "--env", "dev", "--to", filepath.Join(h.dir, "o2")); rc != 1 || !strings.Contains(h.errb.String(), "the vault holds nothing for 'dev'") {
		t.Fatalf("%s", h.errb.String())
	}
	if rc := h.run("export", "--env", "Bad_Name", "--to", filepath.Join(h.dir, "o3")); rc != 1 || !strings.Contains(h.errb.String(), "is not an environment name") {
		t.Fatalf("%s", h.errb.String())
	}
}

func TestStatusGolden(t *testing.T) {
	h := goldenHarness(t)
	oldHook := runHook
	defer func() { runHook = oldHook }()
	runHook = func(string, []string) ([]byte, int, error) { return []byte("Values still to set\n"), 0, nil }
	if rc := h.run("status", "--env", "prod"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	out := h.out.String()
	golden(t, "status-prod.txt", h.paths(stamps(out)))
	if strings.Contains(out, "example-cookie-key") || strings.Contains(out, "example-blob-secret") {
		t.Fatal("status shows a value")
	}
}

func TestVisibilityListsAndChangesNothing(t *testing.T) {
	h := goldenHarness(t)
	// a variable the description marks secret, stored as plain (as an import before the description gave it), is listed with the visibility it
	// would get; --apply is gone: the window changes visibility
	h.editModel(func(m *vmodel.Vault) {
		for _, p := range m.Env("prod").Products {
			for _, x := range p.Vars {
				if x.Key == "BILLING_ACCOUNT" || x.Key == "INVITE_SALT" {
					x.Vis = vmodel.VisPlain
				}
			}
		}
	})
	if rc := h.run("visibility", "--env", "prod"); rc != 0 || !strings.Contains(h.out.String(), "BILLING_ACCOUNT") || !strings.Contains(h.out.String(), "kept-differs") {
		t.Fatalf("%s %s", h.out.String(), h.errb.String())
	}
	before := h.out.String()
	if rc := h.run("visibility", "--env", "prod", "--apply"); rc != 2 {
		t.Fatalf("--apply is not a flag any more: rc=%d", rc)
	}
	if rc := h.run("visibility", "--env", "prod"); rc != 0 || h.out.String() != before {
		t.Fatalf("the listing changed: %s", h.out.String())
	}
}

func TestStatusRequiredCheck(t *testing.T) {
	h := goldenHarness(t)
	var seen []string
	var dir string
	oldHook := runHook
	defer func() { runHook = oldHook }()
	runHook = func(d string, argv []string) ([]byte, int, error) {
		seen, dir = argv, d
		return []byte("Values still to set (target gcp):\n  services/portal.env  CDN_PURGE_KEY\n  targets/gcp.env  GKE_POOL\n\nother text\n"), 1, nil
	}
	if rc := h.run("status", "--env", "prod"); rc != 0 || !strings.Contains(h.out.String(), "required values: still to fill in (file name): services/portal.env CDN_PURGE_KEY; targets/gcp.env GKE_POOL") {
		t.Fatalf("%s", h.out.String())
	}
	if len(seen) != 4 || filepath.Base(seen[0]) != "sh" || filepath.Base(seen[1]) != "check-required.sh" || strings.HasPrefix(seen[1], h.root) || seen[3] != "gcp" || dir != h.root {
		t.Fatalf("%v %s", seen, dir)
	}
	runHook = func(_ string, argv []string) ([]byte, int, error) {
		seen = argv
		return []byte("Values still to set\nall fine\n"), 0, nil
	}
	if rc := h.run("status", "--env", "prod"); rc != 0 || !strings.Contains(h.out.String(), "required values: all set") {
		t.Fatalf("%s", h.out.String())
	}
	// the check's condition (HOSTING=gcp) does not hold on staging (compose): the check does not run
	seen = nil
	if rc := h.run("status", "--env", "staging"); rc != 0 || seen != nil || strings.Contains(h.out.String(), "required values") {
		t.Fatalf("staging is on compose: the check must not run (%v) %s", seen, h.out.String())
	}
}

// The real check script of the example, on a materialised tree: it runs in the checkout.
func TestStatusRequiredCheckScript(t *testing.T) {
	h := goldenHarness(t)
	if rc := h.run("status", "--env", "prod"); rc != 0 || !strings.Contains(h.out.String(), "required values: all set") {
		t.Fatalf("%s %s", h.out.String(), h.errb.String())
	}
}
