package cli

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

func (h *harness) model() *vmodel.Vault {
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
	return m
}

func hasKey(vs []*vmodel.Var, k string) *vmodel.Var {
	for _, x := range vs {
		if x.Key == k {
			return x
		}
	}
	return nil
}

// env create makes the environment with its site and products and every owner variable it needs as an empty entry; nothing the system
// makes, nothing whose condition does not hold, nothing of a product that is off, and no value.
func TestEnvCreate(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	if rc := h.run("env", "create", "--env", "qa", "--site", "google-cluster", "--products", "portal,engine"); rc != 0 {
		t.Fatalf("rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "env create: created qa:") || !strings.Contains(out, "made connection    GCP project (google)") || !strings.Contains(out, "no value was written") {
		t.Fatalf("%s", out)
	}
	m := h.model()
	e := m.Env("qa")
	if e == nil || len(e.Sites) != 1 || e.Sites[0].Kind != "google-cluster" || e.Sites[0].Name != vmodel.SiteName {
		t.Fatalf("site: %+v", e)
	}
	s := e.Sites[0]
	if s.Connection == nil || s.Connection.Kind != "google" || s.Connection.Field("project") == nil || s.State == nil || s.State.Kind != "hcp" ||
		s.State.Field("organization") == nil {
		t.Fatalf("connections of the site: %+v", s)
	}
	if hasKey(s.Vars, "GKE_POOL") == nil || hasKey(s.Vars, "GCP_ZONE") == nil {
		t.Fatalf("site vars %+v", s.Vars)
	}
	if d := hasKey(e.General, "PUBLIC_HOST"); d == nil || d.Description == "" || d.Managed != vmodel.ManagedOwner {
		t.Fatalf("general PUBLIC_HOST: %+v", d)
	}
	if hasKey(e.General, "HOSTING") != nil || hasKey(e.General, "PORTAL") != nil {
		t.Fatal("a derived or a place variable was made")
	}
	web, api, worker := e.Product("portal"), e.Product("engine"), e.Product("indexer")
	if web == nil || !web.Enabled || web.Site != s || api == nil || !api.Enabled || worker == nil || worker.Enabled || worker.Place != "none" {
		t.Fatalf("products %+v %+v %+v", web, api, worker)
	}
	if x := hasKey(web.Vars, "BILLING_ACCOUNT"); x == nil || x.Vis != vmodel.VisSecret {
		t.Fatalf("secret var: %+v", x)
	}
	for _, k := range []string{"COOKIE_KEY", "INVITE_SALT", "CHANGELOG_TAG"} { // generated; SIGNUP_MODE is not invite; no changelog flag
		if hasKey(web.Vars, k) != nil {
			t.Errorf("%s was made", k)
		}
	}
	if hasKey(api.Vars, "ENGINE_PROFILE_DIR") != nil || len(web.Sub["google-cluster"]) != 0 || len(worker.Vars) != 0 {
		t.Fatal("a system value, or a variable of a product that is off, was made")
	}
	// the blob store is made once and shared by portal and engine; the optional CDN connection is not made
	blobs := 0
	for _, c := range m.Connections {
		if c.Kind == "s3" {
			blobs++
		}
		if c.Kind == "cloudflare" {
			t.Fatal("an optional connection was made")
		}
	}
	if blobs != 1 || len(web.Connections) != 1 || len(api.Connections) != 1 || web.Connections[0] != api.Connections[0] {
		t.Fatalf("blobs=%d portal=%v engine=%v", blobs, web.Connections, api.Connections)
	}
	for _, x := range append(append(append([]*vmodel.Var(nil), e.General...), s.Vars...), append(web.Vars, api.Vars...)...) {
		if x.Value != "" {
			t.Fatalf("%s has a value", x.Key)
		}
	}
	for _, c := range m.Connections {
		for _, f := range c.Fields {
			if f.Value != "" {
				t.Fatalf("%s.%s has a value", c.Name, f.Name)
			}
		}
	}
	// a second create of the same environment is refused, the vault unchanged
	if rc := h.run("env", "create", "--env", "qa", "--site", "compose", "--products", "portal"); rc != 1 || !strings.Contains(h.errb.String(), "already") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
}

// A place given on the command line decides the conditions: the indexer on a host reads its file, and its required-when key is made.
func TestEnvCreatePlaceAndFromCheckout(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	if rc := h.run("env", "create", "--env", "dev", "--site", "compose", "--products", "portal,indexer=host"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	m := h.model()
	e := m.Env("dev")
	w := e.Product("indexer")
	if w == nil || w.Place != "host" || hasKey(w.Vars, "BROKER_PASSWORD") == nil || hasKey(w.Vars, "INDEXER_SECRET") != nil {
		t.Fatalf("indexer %+v", w)
	}
	if len(e.Sites[0].Vars) == 0 || hasKey(e.Sites[0].Vars, "BUILD_REF") != nil {
		t.Fatalf("compose site vars %+v", e.Sites[0].Vars)
	}
	// --from-checkout: the committed settings of prod name the hosting and the places
	if rc := h.run("env", "create", "--env", "prod", "--from-checkout"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	st := h.model().Env("prod")
	if st == nil || st.Sites[0].Kind != "google-cluster" || st.Product("indexer").Place != "host" || hasKey(st.Product("indexer").Vars, "BROKER_PASSWORD") == nil {
		t.Fatalf("prod %+v", st)
	}
}

// fill-missing adds only what an environment lacks and never touches an entry that exists.
func TestEnvFillMissing(t *testing.T) {
	h := goldenHarness(t)
	var domain string
	h.editModel(func(m *vmodel.Vault) {
		p := m.Env("prod").Product("portal")
		var keep []*vmodel.Var
		for _, x := range p.Vars {
			if x.Key != "CONTACT_ADDRESS" {
				keep = append(keep, x)
			}
		}
		p.Vars = keep
	})
	for _, x := range h.model().Env("prod").General {
		if x.Key == "PUBLIC_HOST" {
			domain = x.Value
		}
	}
	if rc := h.run("env", "fill-missing", "--env", "prod"); rc != 0 || !strings.Contains(h.out.String(), "CONTACT_ADDRESS") {
		t.Fatalf("rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	e := h.model().Env("prod")
	if x := hasKey(e.Product("portal").Vars, "CONTACT_ADDRESS"); x == nil || x.Value != "" {
		t.Fatalf("CONTACT_ADDRESS %+v", x)
	}
	for _, x := range e.General {
		if x.Key == "PUBLIC_HOST" && x.Value != domain {
			t.Fatal("an existing value changed")
		}
	}
	if rc := h.run("env", "fill-missing", "--env", "prod"); rc != 0 || !strings.Contains(h.out.String(), "lacks nothing") {
		t.Fatalf("second run: rc=%d %s", rc, h.out.String())
	}
	if rc := h.run("env", "fill-missing", "--env", "nothing"); rc != 1 || !strings.Contains(h.errb.String(), "holds no environment nothing") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
}
