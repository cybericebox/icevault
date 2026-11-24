package mpage

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/vmodel"
)

// findVar digs the row of a variable out of the answer of Nav (a JSON round trip, as the page sees it).
func rowOf(t *testing.T, nav map[string]any, scope, key string) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(nav)
	var back map[string]any
	_ = json.Unmarshal(raw, &back)
	var rows []any
	if scope == "shared" {
		rows, _ = back["shared"].([]any)
	} else {
		env := back["envs"].([]any)[0].(map[string]any)
		rows, _ = env["general"].([]any)
	}
	for _, r := range rows {
		if m := r.(map[string]any); m["key"] == key {
			return m
		}
	}
	t.Fatalf("no row %s in %s", key, scope)
	return nil
}

func TestTablesShowTheResolvedValue(t *testing.T) {
	c, _ := newCore(t)
	w := func(scope, key, value, vis string) {
		t.Helper()
		if _, err := c.Write("m-var", map[string]any{"scope": scope, "key": key, "value": value, "visibility": vis}); err != nil {
			t.Fatal(err)
		}
	}
	w("shared", "DEMO_TOKEN", "tok-secret-9", "secret")
	w("env/prod/general", "MAIL_COPY", "${{ shared.CONTACT_ADDRESS }}", "plain")
	w("env/prod/general", "TOKEN_COPY", "${{ shared.DEMO_TOKEN }}", "plain")
	w("env/prod/general", "OWN_SECRET", "x-${{ self.PUBLIC_HOST }}", "secret")
	w("env/prod/general", "LOST", "${{ self.NOPE }}", "plain")
	w("env/prod/site/main", "SITE_MAIL", "${{ shared.CONTACT_ADDRESS }}", "plain")
	nav := c.Nav()

	// a plain result is sent, with where it comes from; the raw reference stays in value for the editor
	r := rowOf(t, nav, "env", "MAIL_COPY")
	res := r["resolved"].(map[string]any)
	if res["value"] != "hello@example.net" || res["broken"] != false || res["vis"] != "plain" || r["value"] != "${{ shared.CONTACT_ADDRESS }}" {
		t.Fatalf("plain ref: %v", r)
	}
	if refs := res["refs"].([]any); len(refs) != 1 || refs[0] != "shared.CONTACT_ADDRESS" {
		t.Fatalf("refs: %v", refs)
	}
	// a plain value that refers to a secret is a secret result: no text on the page
	for _, k := range []string{"TOKEN_COPY", "OWN_SECRET"} {
		res = rowOf(t, nav, "env", k)["resolved"].(map[string]any)
		if _, has := res["value"]; has || res["vis"] != "secret" {
			t.Fatalf("%s: a secret result is shown: %v", k, res)
		}
	}
	// a broken reference: no value, flagged
	res = rowOf(t, nav, "env", "LOST")["resolved"].(map[string]any)
	if _, has := res["value"]; has || res["broken"] != true {
		t.Fatalf("broken: %v", res)
	}
	// a value with no reference carries no resolution
	if _, has := rowOf(t, nav, "env", "PUBLIC_HOST")["resolved"]; has {
		t.Fatal("a plain value has a resolution")
	}
	b, _ := json.Marshal(nav)
	for _, secret := range []string{"tok-secret-9", "x-example.org"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("the answer holds %s", secret)
		}
	}
	// the eye gives the resolved secret on request, the raw text otherwise; a broken one is refused
	if v, err := c.Reveal("m", "env/prod/general", "resolved", "TOKEN_COPY"); err != nil || v != "tok-secret-9" {
		t.Fatalf("resolved reveal %q %v", v, err)
	}
	if v, err := c.Reveal("m", "env/prod/general", "resolved", "OWN_SECRET"); err != nil || v != "x-example.org" {
		t.Fatalf("resolved reveal %q %v", v, err)
	}
	if v, err := c.Reveal("m", "env/prod/general", "", "TOKEN_COPY"); err != nil || v != "${{ shared.DEMO_TOKEN }}" {
		t.Fatalf("raw reveal %q %v", v, err)
	}
	if _, err := c.Reveal("m", "env/prod/general", "resolved", "LOST"); code(err) != "ref_broken" {
		t.Fatalf("broken reveal: %v", err)
	}
}

func TestSharedAndConnectionRowsResolveToo(t *testing.T) {
	c, _ := newCore(t)
	if _, err := c.Write("m-var", map[string]any{"scope": "shared", "key": "ALIAS", "value": "${{ shared.CONTACT_ADDRESS }}", "visibility": "plain"}); err != nil {
		t.Fatal(err)
	}
	res := rowOf(t, c.Nav(), "shared", "ALIAS")["resolved"].(map[string]any)
	if res["value"] != "hello@example.net" {
		t.Fatalf("shared: %v", res)
	}
}

func TestAValueThatDiffersBetweenSitesIsMarked(t *testing.T) {
	c, _ := newCore(t)
	e := c.Model().Env("prod")
	e.Sites = append(e.Sites, &vmodel.Site{Name: "second", Kind: "google-cluster", Vars: []*vmodel.Var{{Key: "GKE_POOL", Value: "c2", Vis: vmodel.VisPlain}}})
	e.General = append(e.General, &vmodel.Var{Key: "POOL_COPY", Value: "${{ self.GKE_POOL }}", Vis: vmodel.VisPlain})
	res := rowOf(t, c.Nav(), "env", "POOL_COPY")["resolved"].(map[string]any)
	if res["varies"] != true {
		t.Fatalf("not marked: %v", res)
	}
	if _, has := res["value"]; has {
		t.Fatalf("a value is shown for a site-dependent result: %v", res)
	}
	if _, err := c.Reveal("m", "env/prod/general", "resolved", "POOL_COPY"); code(err) != "ref_varies" {
		t.Fatalf("reveal: %v", err)
	}
}
