//go:build !windows

package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/vmodel"
	"golang.org/x/sys/unix"
)

// set changes plain values of the vault model without the window. Throwaway vault, the example project.

func valueIn(t *testing.T, h *harness, env, key string) (string, bool) {
	t.Helper()
	m := h.model()
	pl := placesIn(m.Env(env), key)
	if len(pl) == 0 {
		return "", false
	}
	return pl[0].v.Value, true
}

func vaultSum(t *testing.T, h *harness) string {
	t.Helper()
	s, err := sha256File(h.env["ICEVAULT_VAULT"])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSetExistingPlainValue(t *testing.T) {
	h := goldenHarness(t)
	if rc := h.run("set", "--env", "prod", "ENGINE_THREADS=12", "THEME_COLOR="); rc != 0 {
		t.Fatalf("rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "env/prod/product/engine ENGINE_THREADS: 8 -> 12") || !strings.Contains(out, "env/prod/product/portal THEME_COLOR: ") || !strings.Contains(out, "-> (empty)") {
		t.Fatalf("%s", out)
	}
	if v, _ := valueIn(t, h, "prod", "ENGINE_THREADS"); v != "12" {
		t.Fatalf("ENGINE_THREADS=%q", v)
	}
	if v, _ := valueIn(t, h, "prod", "THEME_COLOR"); v != "" {
		t.Fatalf("THEME_COLOR=%q", v)
	}
}

func TestSetCreatesADescribedKeyWhereTheDescriptionPlacesIt(t *testing.T) {
	h := goldenHarness(t)
	h.editModel(func(m *vmodel.Vault) {
		p := m.Env("prod").Product("portal")
		var keep []*vmodel.Var
		for _, v := range p.Vars {
			if v.Key != "ANALYTICS_ID" {
				keep = append(keep, v)
			}
		}
		p.Vars = keep
	})
	if rc := h.run("set", "--env", "prod", "ANALYTICS_ID=an-1"); rc != 0 {
		t.Fatalf("rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	if !strings.Contains(h.out.String(), "env/prod/product/portal ANALYTICS_ID: (new) -> an-1") {
		t.Fatalf("%s", h.out.String())
	}
	pl := placesIn(h.model().Env("prod"), "ANALYTICS_ID")
	if len(pl) != 1 || pl[0].scope != "env/prod/product/portal" || pl[0].v.Vis != vmodel.VisPlain || pl[0].v.Value != "an-1" {
		t.Fatalf("%+v", pl)
	}
}

func TestSetUnknownKeyNeedsAScope(t *testing.T) {
	h := goldenHarness(t)
	before := vaultSum(t, h)
	if rc := h.run("set", "--env", "prod", "NOT_DESCRIBED=1"); rc != 1 || !strings.Contains(h.errb.String(), "NOT_DESCRIBED: is not in the vault and not in the project description: give --scope") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if vaultSum(t, h) != before {
		t.Fatal("the vault changed")
	}
	if rc := h.run("set", "--env", "prod", "--scope", "env/prod/general", "NOT_DESCRIBED=1"); rc != 0 {
		t.Fatalf("rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	if v, ok := valueIn(t, h, "prod", "NOT_DESCRIBED"); !ok || v != "1" {
		t.Fatalf("%q %v", v, ok)
	}
}

func TestSetRefusals(t *testing.T) {
	h := goldenHarness(t)
	cases := []struct{ name, arg, want string }{
		{"secret", "BILLING_ACCOUNT=x", "BILLING_ACCOUNT: is a secret variable"},
		{"generated", "COOKIE_KEY=x", "COOKIE_KEY: is a secret variable"},
		{"system", "ENGINE_PROFILE_DIR=/x", "ENGINE_PROFILE_DIR: is managed by the system"},
		{"range", "ENGINE_THREADS=999", "ENGINE_THREADS: the value breaks the type"},
		{"enum", "SIGNUP_MODE=maybe", "SIGNUP_MODE: the value breaks the type"},
	}
	for _, c := range cases {
		before := vaultSum(t, h)
		if rc := h.run("set", "--env", "prod", c.arg); rc != 1 || !strings.Contains(h.errb.String(), c.want) || !strings.Contains(h.errb.String(), "nothing was written") {
			t.Errorf("%s: rc=%d %s", c.name, rc, h.errb.String())
		}
		if strings.Contains(h.errb.String(), "=x") || strings.Contains(h.out.String(), "x") && c.name == "secret" {
			t.Errorf("%s: a value was echoed", c.name)
		}
		if vaultSum(t, h) != before {
			t.Errorf("%s: the vault changed", c.name)
		}
	}
	if rc := h.run("set", "--env", "nothere", "ENGINE_THREADS=3"); rc != 1 {
		t.Fatalf("unknown env rc=%d", rc)
	}
}

func TestSetReferenceIsRefusedBeforeThePassword(t *testing.T) {
	h := goldenHarness(t)
	h.asked = 0
	if rc := h.run("set", "--env", "prod", "ENGINE_TAG=${{shared.X}}"); rc != 1 || !strings.Contains(h.errb.String(), "holds a reference") || h.asked != 0 {
		t.Fatalf("rc=%d asked=%d %s", rc, h.asked, h.errb.String())
	}
}

func TestSetAmbiguousKeyListsTheScopes(t *testing.T) {
	h := goldenHarness(t)
	h.editModel(func(m *vmodel.Vault) {
		e := m.Env("prod")
		e.General = append(e.General, &vmodel.Var{Key: "ENGINE_TAG", Value: "g", Managed: vmodel.ManagedOwner, Vis: vmodel.VisPlain})
	})
	before := vaultSum(t, h)
	if rc := h.run("set", "--env", "prod", "ENGINE_TAG=v2"); rc != 1 || !strings.Contains(h.errb.String(), "is in several scopes (env/prod/general, env/prod/product/engine)") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if vaultSum(t, h) != before {
		t.Fatal("the vault changed")
	}
	if rc := h.run("set", "--env", "prod", "--scope", "env/prod/general", "ENGINE_TAG=v2"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	pl := placesIn(h.model().Env("prod"), "ENGINE_TAG")
	if len(pl) != 2 || pl[0].v.Value != "v2" || pl[1].v.Value == "v2" {
		t.Fatalf("only the general one must change: %+v", pl)
	}
}

func TestSetAllOrNothing(t *testing.T) {
	h := goldenHarness(t)
	before := vaultSum(t, h)
	if rc := h.run("set", "--env", "prod", "ENGINE_THREADS=5", "BILLING_ACCOUNT=x"); rc != 1 {
		t.Fatalf("rc=%d", rc)
	}
	if vaultSum(t, h) != before {
		t.Fatal("the vault changed although one key was refused")
	}
	if v, _ := valueIn(t, h, "prod", "ENGINE_THREADS"); v != "8" {
		t.Fatalf("ENGINE_THREADS=%q", v)
	}
}

func TestSetDryRunWritesNothing(t *testing.T) {
	h := goldenHarness(t)
	before := vaultSum(t, h)
	if rc := h.run("set", "--env", "prod", "--dry-run", "ENGINE_THREADS=5"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if !strings.Contains(h.out.String(), "ENGINE_THREADS: 8 -> 5") || !strings.Contains(h.out.String(), "(dry run: nothing was written)") {
		t.Fatalf("%s", h.out.String())
	}
	if vaultSum(t, h) != before {
		t.Fatal("a dry run wrote")
	}
}

// Another writer holds the vault's write lock: set is refused and writes nothing.
func TestSetRefusedWhileAnotherWriterHoldsTheLock(t *testing.T) {
	h := goldenHarness(t)
	f, err := os.OpenFile(h.env["ICEVAULT_VAULT"]+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	before := vaultSum(t, h)
	if rc := h.run("set", "--env", "prod", "ENGINE_THREADS=5"); rc != 1 || !strings.Contains(h.errb.String(), "another process is writing") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if vaultSum(t, h) != before {
		t.Fatal("the vault changed")
	}
}
