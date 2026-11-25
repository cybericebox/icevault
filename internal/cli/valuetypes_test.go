//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// setVar changes one product variable of the vault of the harness (the way a hand edit or an older tool could).
func setVar(t *testing.T, h *harness, env, product, key, value string) {
	t.Helper()
	v, err := vault.Open(h.env["ICEVAULT_VAULT"], vault.Credentials{Password: []byte(pw)})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	m, err := vmodel.Load(v)
	if err != nil {
		t.Fatal(err)
	}
	x := hasKey(m.Env(env).Product(product).Vars, key)
	if x == nil {
		t.Fatalf("no %s", key)
	}
	x.Value = value
	if err := vmodel.Sync(v, m); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
}

// A filled value that does not fit its type: status reports it and export and session refuse, naming the variable and never the value.
func TestAValueThatDoesNotFitItsTypeIsReportedAndStopsTheRender(t *testing.T) {
	h := goldenHarness(t)
	const bad = "eight-threads-secret-looking"
	setVar(t, h, "prod", "engine", "ENGINE_THREADS", bad)
	if rc := h.run("status", "--env", "prod"); rc != 0 {
		t.Fatalf("status: %s %s", h.out.String(), h.errb.String())
	}
	if !strings.Contains(h.out.String(), "TYPE PROBLEM: services/engine.env/ENGINE_THREADS must be a whole number") {
		t.Fatalf("status does not report it:\n%s", h.out.String())
	}
	to := filepath.Join(h.dir, "never")
	h.out.Reset()
	h.errb.Reset()
	if rc := h.run("export", "--env", "prod", "--to", to); rc == 0 {
		t.Fatal("export went on")
	}
	if msg := h.out.String() + h.errb.String(); !strings.Contains(msg, "ENGINE_THREADS") || strings.Contains(msg, bad) {
		t.Fatalf("the message names the variable and never the value:\n%s", msg)
	}
	if _, err := os.Stat(filepath.Join(to, "services", "engine.env")); err == nil {
		t.Fatal("a file was written")
	}
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	h.out.Reset()
	h.errb.Reset()
	if rc := h.run("session", "run", "--env", "prod", "--base", base, "--", "true"); rc == 0 {
		t.Fatal("the session went on")
	}
	if msg := h.out.String() + h.errb.String(); !strings.Contains(msg, "ENGINE_THREADS") || strings.Contains(msg, bad) {
		t.Fatalf("session:\n%s", msg)
	}
	setVar(t, h, "prod", "engine", "ENGINE_THREADS", "12")
	h.out.Reset()
	h.errb.Reset()
	if rc := h.run("export", "--env", "prod", "--to", filepath.Join(h.dir, "fine")); rc != 0 {
		t.Fatalf("a fitting value: %s %s", h.out.String(), h.errb.String())
	}
}

// setPlace moves a product of the vault of the harness (the ENGINE / INDEXER word of the project) and sets some of its variables.
func setPlace(t *testing.T, h *harness, env, product, place string, vars map[string]string) {
	t.Helper()
	v, err := vault.Open(h.env["ICEVAULT_VAULT"], vault.Credentials{Password: []byte(pw)})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	m, err := vmodel.Load(v)
	if err != nil {
		t.Fatal(err)
	}
	p := m.Env(env).Product(product)
	p.Place = place
	for k, val := range vars {
		x := hasKey(p.Vars, k)
		if x == nil {
			x = &vmodel.Var{Key: k, Managed: vmodel.ManagedOwner, Vis: vmodel.VisPlain}
			p.Vars = append(p.Vars, x)
		}
		x.Value = val
	}
	if err := vmodel.Sync(v, m); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
}

// A variable the description needs for one place only (required-when: INDEXER=cluster, INDEXER in [host, cluster]) is listed as missing exactly
// while the place says so: the rule is the project's, never fixed in the tool.
func TestMissingFollowsThePlaceOfAProduct(t *testing.T) {
	h := goldenHarness(t)
	missing := func() string {
		h.out.Reset()
		h.errb.Reset()
		if rc := h.run("view", "--env", "prod"); rc != 0 {
			t.Fatalf("view: %s %s", h.out.String(), h.errb.String())
		}
		out := h.out.String()
		if i := strings.Index(out, "missing:"); i >= 0 {
			return out[i:]
		}
		return ""
	}
	setPlace(t, h, "prod", "indexer", "cluster", map[string]string{"BROKER_URL": "", "BROKER_PASSWORD": ""})
	if m := missing(); !strings.Contains(m, "BROKER_URL") || !strings.Contains(m, "BROKER_PASSWORD") {
		t.Fatalf("on the cluster both are listed:\n%s", m)
	}
	setPlace(t, h, "prod", "indexer", "host", nil)
	if m := missing(); strings.Contains(m, "BROKER_URL") || !strings.Contains(m, "BROKER_PASSWORD") {
		t.Fatalf("on a host only the password:\n%s", m)
	}
	setPlace(t, h, "prod", "indexer", "none", nil)
	if m := missing(); strings.Contains(m, "BROKER_") {
		t.Fatalf("not run: nothing:\n%s", m)
	}
}
