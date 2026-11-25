package cli

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/vmodel"
)

// A value held in a connection of a product counts as filled in status, and the empty ones are named (never their values).
func TestStatusNamesTheEmptyVariablesAndCountsConnectionValuesAsFilled(t *testing.T) {
	h := goldenHarness(t)
	h.editModel(func(m *vmodel.Vault) {
		m.Shared = append(m.Shared, &vmodel.Var{Key: "CONTACT_ADDRESS", Value: "help@example.org", Vis: vmodel.VisPlain})
		var cdn *vmodel.Connection
		for _, c := range m.Connections {
			if c.Kind == "cloudflare" {
				cdn = c
			}
		}
		if cdn == nil {
			t.Fatal("no cloudflare connection")
		}
		for _, f := range cdn.Fields {
			f.Value = "cdn-" + f.Name + "-secret-1"
			if f.Name == "api_token" {
				f.Value = "" // the one really empty
			}
			if f.Name == "purge_key" {
				f.Value = "${{ shared.CONTACT_ADDRESS }}"
			}
		}
		p := m.Env("prod").Product("portal")
		found := false
		for _, c := range p.Connections {
			found = found || c == cdn
		}
		if !found {
			p.Connections = append(p.Connections, cdn)
		}
	})
	if rc := h.run("status", "--env", "prod"); rc != 0 {
		t.Fatalf("rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	out := h.out.String()
	if strings.Contains(out, "secret-1") {
		t.Fatalf("status shows a value:\n%s", out)
	}
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "services/portal.env:") {
			line = l
		}
	}
	if line == "" || strings.Contains(line, "CDN_PURGE_KEY") || strings.Contains(line, "CDN_SIGNING_KEY") {
		t.Fatalf("a connection value is counted as empty: %q\n%s", line, out)
	}
	if !strings.Contains(line, "1 empty (CDN_TOKEN)") {
		t.Fatalf("the empty variables are not named: %q", line)
	}
}
