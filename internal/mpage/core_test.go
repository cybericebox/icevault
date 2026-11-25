package mpage

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

func newCore(t *testing.T) (*Core, *vault.Vault) {
	t.Helper()
	return newCoreWith(t, example.Description())
}

func newCoreWith(t *testing.T, desc []byte) (*Core, *vault.Vault) {
	t.Helper()
	d, err := project.Parse(desc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "v.kdbx")
	v, err := vault.Create(p, vault.Credentials{Password: []byte("pw-throwaway-1")}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	gcp := &vmodel.Connection{Name: "GCP", Kind: "google", Fields: []*vmodel.Field{{Name: "credentials", Value: "gkey-secret-1", Secret: true}, {Name: "project", Value: "lumen-prod"}}}
	cf := &vmodel.Connection{Name: "Blob store", Kind: "s3", Fields: []*vmodel.Field{{Name: "secret_access_key", Value: "blob-secret-1", Secret: true}}}
	admin := &vmodel.Var{Key: "CONTACT_ADDRESS", Value: "hello@example.net", Vis: vmodel.VisPlain}
	site := &vmodel.Site{Name: "main", Kind: "google-cluster", Connection: gcp, Vars: []*vmodel.Var{{Key: "GKE_POOL", Value: "c1", Vis: vmodel.VisPlain}}}
	m := &vmodel.Vault{Format: vmodel.Format, Shared: []*vmodel.Var{admin}, Connections: []*vmodel.Connection{gcp, cf},
		Envs: []*vmodel.Environment{{Name: "prod", General: []*vmodel.Var{{Key: "PUBLIC_HOST", Value: "example.org", Vis: vmodel.VisPlain}}, Imports: []*vmodel.Var{admin}, Sites: []*vmodel.Site{site},
			Layouts: map[string][]byte{}, Products: []*vmodel.Product{{Name: "portal", Enabled: true, Site: site, Connections: []*vmodel.Connection{cf},
				Vars: []*vmodel.Var{{Key: "COOKIE_KEY", Value: "sig-secret-1", Vis: vmodel.VisSealed, Managed: vmodel.ManagedSystem}}, Sub: map[string][]*vmodel.Var{}}}}},
		Other: []*vmodel.Other{{Title: "wifi", Value: "wifi-secret-1"}}}
	if err := vmodel.Write(v, m); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	c, err := New(v, d)
	if err != nil {
		t.Fatal(err)
	}
	return c, v
}

func code(err error) string {
	var de *desktop.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

func TestUnimportAsksWhenValuesUseIt(t *testing.T) {
	c, _ := newCore(t)
	for _, w := range []map[string]any{
		{"scope": "shared", "key": "PAIR_ONE", "value": "one", "visibility": "plain"},
		{"scope": "shared", "key": "PAIR_TWO", "value": "two", "visibility": "plain"},
		{"scope": "env/prod/general", "key": "PAIR_JOIN", "value": "${{ self.PAIR_ONE }}-x", "visibility": "plain"},
	} {
		if _, err := c.Write("m-var", w); err != nil {
			t.Fatalf("%v: %v", w, err)
		}
	}
	both := []any{"PAIR_ONE", "PAIR_TWO"}
	if _, err := c.Write("m-import", map[string]any{"env": "prod", "keys": both}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-import", map[string]any{"env": "prod", "keys": []any{"PAIR_ONE"}}); err != nil {
		t.Fatalf("taking out a value nobody uses: %v", err)
	}
	if _, err := c.Write("m-import", map[string]any{"env": "prod", "keys": []any{"PAIR_TWO"}}); code(err) != "confirm_unimport_used" {
		t.Fatalf("replacing a value other values use by another one: %v", err)
	}
	_, err := c.Write("m-import", map[string]any{"env": "prod", "keys": []any{}})
	if code(err) != "confirm_unimport_used" {
		t.Fatalf("taking out a value other values use: %v", err)
	}
	var de *desktop.Error
	if !errors.As(err, &de) || !strings.Contains(fmt.Sprint(de.Params["list"]), "PAIR_JOIN") {
		t.Fatalf("the refusal does not name where it is used: %v", err)
	}
	if len(c.Model().Env("prod").Imports) != 1 {
		t.Fatal("a refused change was kept")
	}
	if _, err := c.Write("m-import", map[string]any{"env": "prod", "keys": []any{}, "confirm": true}); err != nil {
		t.Fatalf("confirmed: %v", err)
	}
}

func TestReferencesAndPreview(t *testing.T) {
	c, _ := newCore(t)
	if _, err := c.Write("m-var", map[string]any{"scope": "env/prod/general", "key": "ADMIN_MAIL", "value": "ops@example.net", "visibility": "plain"}); err != nil {
		t.Fatal(err)
	}
	// the picker: variables of the environment, shared values, never a value
	got, err := c.Read("references", map[string]any{"scope": "env/prod/general"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	for _, want := range []string{`"system":"self"`, `"key":"ADMIN_MAIL"`, `"system":"shared"`, `"key":"CONTACT_ADDRESS"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("targets lack %s: %s", want, raw)
		}
	}
	for _, secret := range []string{"ops@example.net", "sig-secret-1", "gkey-secret-1"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the picker shows a value: %s", secret)
		}
	}
	// the variable being edited is never offered, nor a variable that refers back to it
	if _, err := c.Write("m-var", map[string]any{"scope": "env/prod/general", "key": "BACK_MAIL", "value": "${{ self.ADMIN_MAIL }}", "visibility": "plain"}); err != nil {
		t.Fatal(err)
	}
	own, err := c.Read("references", map[string]any{"scope": "env/prod/general", "key": "ADMIN_MAIL"})
	if err != nil {
		t.Fatal(err)
	}
	rawOwn, _ := json.Marshal(own)
	if strings.Contains(string(rawOwn), `"key":"ADMIN_MAIL"`) || strings.Contains(string(rawOwn), `"key":"BACK_MAIL"`) || !strings.Contains(string(rawOwn), `"key":"CONTACT_ADDRESS"`) {
		t.Errorf("the edited variable or a cycle is offered: %s", rawOwn)
	}
	sh, _ := c.Read("references", map[string]any{"scope": "shared"})
	if raw, _ := json.Marshal(sh); strings.Contains(string(raw), `"system":"self"`) {
		t.Errorf("a shared value is offered self: %s", raw)
	}
	// the preview: plain text for plain, nothing for a sealed target
	p, err := c.Read("preview-value", map[string]any{"scope": "env/prod/general", "key": "SUPPORT", "value": "to ${{ self.ADMIN_MAIL }}", "visibility": "plain"})
	if err != nil {
		t.Fatal(err)
	}
	pm := p.(map[string]any)
	if pm["preview"] != "to ops@example.net" || pm["eff_vis"] != "plain" || pm["ref_errors"] != 0 {
		t.Fatalf("preview: %v", pm)
	}
	p, _ = c.Read("preview-value", map[string]any{"scope": "env/prod/general", "key": "SUPPORT", "value": "${{ self.COOKIE_KEY }}", "visibility": "plain"})
	if raw, _ := json.Marshal(p); strings.Contains(string(raw), "sig-secret-1") || p.(map[string]any)["preview"] != nil {
		t.Fatalf("a sealed value came through the preview: %s", raw)
	}
	p, _ = c.Read("preview-value", map[string]any{"scope": "env/prod/general", "key": "SUPPORT", "value": "${{ self.NOPE }}", "visibility": "plain"})
	if pm := p.(map[string]any); pm["ref_errors"] != 1 || pm["preview"] != nil {
		t.Fatalf("broken: %v", pm)
	}
	// a shared value refers to no environment: the write is refused and nothing changes
	if _, err := c.Write("m-var", map[string]any{"scope": "shared", "key": "BAD", "value": "${{ self.ADMIN_MAIL }}", "visibility": "plain"}); code(err) != "model_invalid" {
		t.Fatalf("shared self: %v", err)
	}
	if c.Model().SharedVar("BAD") != nil {
		t.Fatal("the refused value was kept")
	}
}

func TestProductHelpFollowsThePlacement(t *testing.T) {
	c, _ := newCore(t)
	dp := c.d.Product("portal")
	dp.Help = project.Text{"en": "as host processes"}
	dp.HelpOnSiteKind = map[string]project.Text{"google-cluster": {"en": "in the cluster"}}
	helpOf := func() string {
		for _, e := range c.Nav()["envs"].([]map[string]any) {
			for _, p := range e["products"].([]map[string]any) {
				if p["name"] == "portal" {
					return p["help"].(map[string]string)["en"]
				}
			}
		}
		return ""
	}
	if got := helpOf(); got != "in the cluster" {
		t.Fatalf("on a cluster site: %q", got)
	}
	c.m.Env("prod").Product("portal").Site = nil
	if got := helpOf(); got != "as host processes" {
		t.Fatalf("without a site: %q", got)
	}
}

func TestEnumAndBoolSaveAsAReferenceAndAsAValue(t *testing.T) {
	c, _ := newCore(t)
	scope := "env/prod/product/portal"
	valueOf := func() string {
		for _, x := range c.Model().Env("prod").Product("portal").Vars {
			if x.Key == "SIGNUP_MODE" {
				return x.Value
			}
		}
		return "(none)"
	}
	for _, v := range []string{"${{ self.PUBLIC_HOST }}", "open", "${{ shared.CONTACT_ADDRESS }}", "invite"} {
		if _, err := c.Write("m-var", map[string]any{"scope": scope, "key": "SIGNUP_MODE", "value": v, "visibility": "plain"}); err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if valueOf() != v {
			t.Fatalf("saved %q, model holds %q", v, valueOf())
		}
		if p := c.d.ValueProblem("SIGNUP_MODE", v); p != "" {
			t.Fatalf("%q is a choice or a reference: %s", v, p)
		}
	}
	if c.d.ValueProblem("SIGNUP_MODE", "nonsense") == "" {
		t.Fatal("a value that is not a choice passes")
	}
	// a bool is the same: true, false and a reference pass, anything else is a problem
	b := project.Variable{Name: "FLAG", Type: project.RuleBool}
	for _, v := range []string{"true", "false", "${{ self.PUBLIC_HOST }}", "a-${{ shared.X }}"} {
		if p := b.ValueProblem(v); p != "" {
			t.Errorf("bool %q: %s", v, p)
		}
	}
	if b.ValueProblem("yes") == "" || b.ValueProblem("$${{ x }}") == "" {
		t.Error("a bool takes only true, false or a reference (an escaped one is text)")
	}
}

func TestAKeyFileIsOneLine(t *testing.T) {
	c, _ := newCore(t)
	gcp := c.Model().Connections[0]
	for _, v := range []string{"{\n \"a\": 1\n}", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "a\rb"} {
		if _, err := c.Write("m-field", map[string]any{"uuid": gcp.UUID, "field": "credentials", "value": v}); code(err) != "line_break" {
			t.Fatalf("a multi-line value was not refused: %v", err)
		}
	}
	if _, err := c.Write("m-field", map[string]any{"uuid": gcp.UUID, "field": "credentials", "value": `{"a":1}`}); err != nil {
		t.Fatal(err)
	}
	if f := c.Model().Connections[0].Field("credentials"); f == nil || f.Value != `{"a":1}` || !f.Secret {
		t.Fatalf("a compact JSON key is kept, as a secret: %+v", f)
	}
}

func TestMissingCountsAThingOnceForTheEnvironment(t *testing.T) {
	c, _ := newCore(t)
	prod := c.Model().Env("prod")
	prod.General = nil // PUBLIC_HOST is required and now empty
	site := prod.Sites[0]
	prod.Products = append(prod.Products, &vmodel.Product{Name: "engine", Enabled: true, Site: site, Sub: map[string][]*vmodel.Var{}})
	site.Connection = nil // the connection every product of the site lacks
	var env map[string]any
	for _, e := range c.Nav()["envs"].([]map[string]any) {
		if e["name"] == "prod" {
			env = e
		}
	}
	perProduct, general, siteConn := 0, 0, 0
	for _, p := range env["products"].([]map[string]any) {
		for _, r := range p["missing"].([]map[string]any) {
			perProduct++
			if r["where"] == "general" {
				general++
			}
			if r["where"] == "site_connection" {
				siteConn++
				if r["site"] != "main" {
					t.Fatalf("the row does not name its site: %v", r)
				}
			}
		}
	}
	if general < 2 || siteConn < 2 {
		t.Fatalf("each product lists the shared things (general %d, site connection %d)", general, siteConn)
	}
	if got := env["missing"].(int); got >= perProduct || got != perProduct-(general-1)-(siteConn-1) {
		t.Fatalf("the environment counts %d, the products list %d (general %d, site connection %d)", got, perProduct, general, siteConn)
	}
}

func TestBrokenReferenceIsNeededForDeploy(t *testing.T) {
	c, _ := newCore(t)
	if _, err := c.Write("m-var", map[string]any{"scope": "env/prod/product/portal", "key": "LINK", "value": "${{ self.NOPE }}", "visibility": "plain"}); err != nil {
		t.Fatal(err)
	}
	nav := c.Nav()
	var rows []map[string]any
	for _, e := range nav["envs"].([]map[string]any) {
		for _, p := range e["products"].([]map[string]any) {
			rows = append(rows, p["missing"].([]map[string]any)...)
		}
	}
	found := false
	for _, r := range rows {
		if r["where"] == "reference" && r["key"] == "LINK" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no row for the broken reference: %v", rows)
	}
	if _, err := c.Write("m-var", map[string]any{"scope": "env/prod/product/portal", "key": "LINK", "value": "${{ self.PUBLIC_HOST }}"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range c.Nav()["envs"].([]map[string]any) {
		for _, p := range e["products"].([]map[string]any) {
			for _, r := range p["missing"].([]map[string]any) {
				if r["where"] == "reference" {
					t.Fatalf("still a broken reference after the fix: %v", r)
				}
			}
		}
	}
}

func TestNavShowsTheModelAndNoSecret(t *testing.T) {
	c, _ := newCore(t)
	b, err := json.Marshal(c.Nav())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, secret := range []string{"gkey-secret-1", "blob-secret-1", "sig-secret-1", "wifi-secret-1"} {
		if strings.Contains(s, secret) {
			t.Fatalf("the answer holds %s", secret)
		}
	}
	for _, want := range []string{"example.org", "lumen-prod", "\"imported\":true", "\"kind\":\"google-cluster\"", "Публічний хост", "\"missing\":["} {
		if !strings.Contains(s, want) {
			t.Errorf("the answer lacks %s", want)
		}
	}
	if v, err := c.Reveal("m", "conn/"+c.Model().Connection("GCP").UUID, "", "credentials"); err != nil || v != "gkey-secret-1" {
		t.Fatalf("reveal %q %v", v, err)
	}
	if _, err := c.Reveal("m", "env/prod/product/portal", "", "COOKIE_KEY"); code(err) != "sealed" {
		t.Fatalf("a sealed value is revealed: %v", err)
	}
}

func TestWritesAskBeforeTouchingWhatIsUsed(t *testing.T) {
	c, v := newCore(t)
	gcp := c.Model().Connection("GCP").UUID
	if _, err := c.Write("m-connection", map[string]any{"action": "update", "uuid": gcp, "name": "GCP main"}); code(err) != "confirm_rename_used" {
		t.Fatalf("rename of a used connection: %v", err)
	}
	if _, err := c.Write("m-connection", map[string]any{"action": "update", "uuid": gcp, "name": "GCP main", "confirm": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-connection", map[string]any{"action": "create", "name": "GCP second", "kind": "google"}); err != nil {
		t.Fatal(err)
	}
	second := c.Model().Connection("GCP second")
	if _, err := c.Write("m-site", map[string]any{"env": "prod", "action": "update", "name": "main", "connection": second.UUID}); code(err) != "confirm_site_connection" {
		t.Fatalf("a new connection of a site that runs: %v", err)
	}
	if _, err := c.Write("m-site", map[string]any{"env": "prod", "action": "update", "name": "main", "connection": c.Model().Connection("Blob store").UUID, "confirm": true}); code(err) != "wrong_connection_kind" {
		t.Fatalf("a connection of another kind: %v", err)
	}
	if _, err := c.Write("m-site", map[string]any{"env": "prod", "action": "update", "name": "main", "connection": second.UUID, "confirm": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-var", map[string]any{"scope": "env/prod/product/portal", "key": "COOKIE_KEY", "value": "x"}); code(err) != "system_managed" {
		t.Fatalf("a system value is edited by hand: %v", err)
	}
	for _, w := range []map[string]any{
		{"scope": "env/prod/general", "key": "NOTES_LABEL", "value": "the production"},
		{"scope": "env/prod/product/portal/google-cluster", "key": "EXPORT_BUCKET", "value": "b1"},
		{"scope": "shared", "key": "SHARED_NOTE", "value": "age1x"},
	} {
		if _, err := c.Write("m-var", w); err != nil {
			t.Fatalf("%v: %v", w, err)
		}
	}
	if _, err := c.Write("m-import", map[string]any{"env": "prod", "keys": []any{"CONTACT_ADDRESS", "SHARED_NOTE"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-var", map[string]any{"scope": "shared", "key": "SHARED_NOTE", "delete": true}); code(err) != "confirm_shared_used" {
		t.Fatalf("a shared value in use: %v", err)
	}
	// a reference ${{ shared.KEY }} in a value counts as a use, with the key of the value that holds it
	if _, err := c.Write("m-var", map[string]any{"scope": "shared", "key": "OAUTH_ID", "value": "id-1", "visibility": "plain"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-var", map[string]any{"scope": "env/prod/general", "key": "SOCIAL_CLIENT_ID", "value": "${{ shared.OAUTH_ID }}", "visibility": "plain"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-var", map[string]any{"scope": "shared", "key": "OAUTH_ID", "delete": true}); code(err) != "confirm_shared_used" {
		t.Fatalf("a shared value used by a reference: %v", err)
	}
	if _, err := c.Write("m-var", map[string]any{"scope": "env/prod/general", "key": "SOCIAL_CLIENT_ID", "delete": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-var", map[string]any{"scope": "shared", "key": "OAUTH_ID", "delete": true}); err != nil {
		t.Fatalf("an unused shared value: %v", err)
	}
	if _, err := c.Write("m-env", map[string]any{"action": "copy", "name": "staging", "from": "prod", "title": "Staging"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-product", map[string]any{"env": "staging", "action": "update", "name": "portal", "enabled": false}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-other", map[string]any{"action": "create", "title": "router", "value": "r-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-site", map[string]any{"env": "prod", "action": "delete", "name": "main"}); code(err) != "confirm_delete_site" {
		t.Fatalf("delete a used site: %v", err)
	}
	// what was written is in the file
	back, err := vmodel.Load(v)
	if err != nil || len(back.Problems) > 0 {
		t.Fatalf("%v %v", err, back.Problems)
	}
	st := back.Env("staging")
	if st == nil || st.Title != "Staging" || st.Product("portal").Enabled || st.Site("main").Connection != back.Connection("GCP second") || len(st.Imports) != 2 {
		t.Fatalf("the copy %+v", st)
	}
	if back.Env("prod").Product("portal").Sub["google-cluster"][0].Value != "b1" || back.Connection("GCP main") == nil || len(back.Other) != 2 {
		t.Fatal("the writes are not in the vault")
	}
	if back.Env("prod").Site("main").Connection.Name != "GCP second" {
		t.Fatal("the site connection")
	}
}

// m-env-fill: the window's "create missing entries" is vmodel.FillMissing: empty entries only, nothing that exists is changed, an imported
// key is not made again.
func TestEnvFill(t *testing.T) {
	c, _ := newCore(t)
	res, err := c.Write("m-env-fill", map[string]any{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := res.(map[string]any)
	if n, _ := r["added"].(int); n == 0 {
		t.Fatalf("nothing added: %v", res)
	}
	e := c.Model().Env("prod")
	web := e.Product("portal")
	for _, x := range web.Vars {
		if x.Key == "COOKIE_KEY" && x.Value != "sig-secret-1" {
			t.Fatal("an existing value changed")
		}
		if x.Key == "CONTACT_ADDRESS" {
			t.Fatal("an imported key was made again")
		}
		if x.Key == "SIGNUP_MODE" && x.Value != "" {
			t.Fatal("a value was written")
		}
	}
	if e.Sites[0].Connection.Field("credentials").Value != "gkey-secret-1" {
		t.Fatal("a connection field changed")
	}
	again, err := c.Write("m-env-fill", map[string]any{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := again.(map[string]any)["added"].(int); n != 0 {
		t.Fatalf("second fill added %d", n)
	}
	if _, err := c.Write("m-env-fill", map[string]any{"env": "nothing"}); code(err) != "no_env" {
		t.Fatalf("unknown environment: %v", err)
	}
}

// A value that does not fit the declared type is refused with the variable and the rule (never the value); an empty value and a reference
// are accepted; the answer carries the type and the choices so the page draws a drop-down.
func TestTypedVariables(t *testing.T) {
	c, _ := newCore(t)
	scope := "env/prod/product/portal"
	for _, tc := range []struct{ key, value, rule string }{
		{"SIGNUP_MODE", "closed", "enum"}, {"CONTACT_ADDRESS", "not an address", "email"}, {"ENGINE_THREADS", "x", "int"}, {"ENGINE_THREADS", "100", "range"}, {"ENGINE_THREADS", "0", "range"},
	} {
		_, err := c.Write("m-var", map[string]any{"scope": scope, "key": tc.key, "value": tc.value})
		var de *desktop.Error
		if !errors.As(err, &de) || de.Code != "bad_value" || de.Params["rule"] != tc.rule || de.Params["key"] != tc.key {
			t.Fatalf("%s: %v", tc.key, err)
		}
		if strings.Contains(err.Error(), tc.value) {
			t.Fatal("the value is in the error")
		}
	}
	for _, v := range []string{"invite", "", "${{ shared.MODE }}"} {
		if _, err := c.Write("m-var", map[string]any{"scope": scope, "key": "SIGNUP_MODE", "value": v}); err != nil {
			t.Fatalf("%q: %v", v, err)
		}
	}
	b, _ := json.Marshal(c.Nav())
	if !strings.Contains(string(b), `"choices":["open","invite"]`) || !strings.Contains(string(b), `"type":"enum"`) {
		t.Fatalf("the page is not told the type: %s", b)
	}
}

// "Needed for deploy" follows required-when over the place of the product (INDEXER=cluster needs its broker, INDEXER=none does not) and the
// defaults of the description; a product that is off needs nothing.
func TestRequiredWhenFollowsThePlaceOfTheProduct(t *testing.T) {
	c, _ := newCore(t)
	e := c.Model().Env("prod")
	e.Products = append(e.Products, &vmodel.Product{Name: "indexer", Enabled: true, Place: "cluster", Site: e.Sites[0], Sub: map[string][]*vmodel.Var{}})
	missing := func() []string {
		var keys []string
		for _, p := range c.envView(e, nil)["products"].([]map[string]any) {
			if p["name"] == "indexer" {
				for _, m := range p["missing"].([]map[string]any) {
					keys = append(keys, m["key"].(string))
				}
			}
		}
		return keys
	}
	has := func(keys []string, k string) bool { return contains(keys, k) }
	if m := missing(); !has(m, "BROKER_URL") || !has(m, "BROKER_PASSWORD") {
		t.Fatalf("on the cluster both are needed: %v", m)
	}
	e.Products[len(e.Products)-1].Place = "host"
	if m := missing(); has(m, "BROKER_URL") || !has(m, "BROKER_PASSWORD") {
		t.Fatalf("on a host only the password: %v", m)
	}
	e.Products[len(e.Products)-1].Place = "none"
	if m := missing(); has(m, "BROKER_URL") || has(m, "BROKER_PASSWORD") {
		t.Fatalf("not run: nothing: %v", m)
	}
	e.Products[len(e.Products)-1].Place = "cluster"
	e.Products[len(e.Products)-1].Enabled = false
	if m := missing(); len(m) != 0 {
		t.Fatalf("a product that is off needs nothing: %v", m)
	}
}

// A vault without a project says so in its navigation, so that the page does not offer the missing description as a problem.
func TestNavSaysTheVaultHasNoProject(t *testing.T) {
	c, v := newCore(t)
	desc := func(c *Core) map[string]any {
		b, err := json.Marshal(c.Nav())
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		d, _ := m["description"].(map[string]any)
		return d
	}
	if d := desc(c); d["found"] != true || d["no_project"] != false {
		t.Fatalf("a vault with its project: %+v", d)
	}
	loose, err := New(v, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := desc(loose); d["found"] != false || d["no_project"] != false {
		t.Fatalf("no description, not marked: %+v", d)
	}
	loose.NoProject = true
	if d := desc(loose); d["found"] != false || d["no_project"] != true {
		t.Fatalf("marked: %+v", d)
	}
}
