package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/vmodel"
)

// a project that declares a connection kind moves the own values of an environment into connections: --dry-run names them and changes nothing;
// the run moves them, prints no value, and a second run has nothing to move.
func TestEnvAdoptConnections(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(filepath.Join(h.root, project.FileName), example.DescriptionDeclaringKind(), 0o600); err != nil {
		t.Fatal(err)
	}
	h.initVault()
	h.editModel(func(m *vmodel.Vault) {
		site := &vmodel.Site{Name: "main", Kind: "compose"}
		p := &vmodel.Product{Name: "portal", Enabled: true, Site: site, Sub: map[string][]*vmodel.Var{}}
		m.Envs = append(m.Envs, &vmodel.Environment{Name: "qa", Layouts: map[string][]byte{}, Sites: []*vmodel.Site{site}, Products: []*vmodel.Product{p}})
		p.Vars = append(p.Vars, &vmodel.Var{Key: "ANALYTICS_ID", Value: "site-secret-77", Vis: vmodel.VisPlain}, &vmodel.Var{Key: "BILLING_ACCOUNT", Value: "bill-secret-88", Vis: vmodel.VisSecret})
	})
	if rc := h.run("env", "adopt-connections", "--env", "qa", "--dry-run"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "ANALYTICS_ID, BILLING_ACCOUNT") || !strings.Contains(out, "dry run") || strings.Contains(out, "secret-") {
		t.Fatalf("a dry run names the variables and never a value: %s", out)
	}
	if m := h.model(); m.Connection("Stats") != nil || hasKey(m.Env("qa").Product("portal").Vars, "ANALYTICS_ID") == nil {
		t.Fatal("a dry run changed the vault")
	}
	if rc := h.run("env", "adopt-connections", "--env", "qa"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if strings.Contains(h.out.String()+h.errb.String(), "secret-") {
		t.Fatal("a value was printed")
	}
	m := h.model()
	p := m.Env("qa").Product("portal")
	c := m.Connection("Stats")
	if c == nil || c.Kind != "stats" || c.Field("site_id").Value != "site-secret-77" || c.Field("token").Value != "bill-secret-88" || !c.Field("token").Secret {
		t.Fatalf("%+v", c)
	}
	if hasKey(p.Vars, "ANALYTICS_ID") != nil || hasKey(p.Vars, "BILLING_ACCOUNT") != nil {
		t.Fatal("the own values stay")
	}
	selected := false
	for _, x := range p.Connections {
		selected = selected || x == c
	}
	if !selected {
		t.Fatal("the product does not select the connection")
	}
	if rc := h.run("env", "adopt-connections", "--env", "qa"); rc != 0 || !strings.Contains(h.out.String(), "holds no value") {
		t.Fatalf("rc=%d %s", rc, h.out.String())
	}
	if rc := h.run("env", "adopt-connections", "--env", "nothing"); rc != 1 {
		t.Fatalf("an unknown environment: rc=%d", rc)
	}
	if rc := h.run("env", "adopt-connections", "--env", "qa", "--site", "compose"); rc != 2 {
		t.Fatalf("a flag that is not for adopt-connections: rc=%d", rc)
	}
	if rc := h.run("env", "fill-missing", "--env", "qa"); rc != 2 {
		t.Fatalf("fill-missing is gone: rc=%d", rc)
	}
}
