package vmodel

import (
	"reflect"
	"strings"
	"testing"
)

func TestPreviewSelfReferences(t *testing.T) {
	m := sample()
	d := desc(t)
	prod := m.Env("prod")
	portal, main := prod.Product("portal"), prod.Site("main")
	general := Place{Env: prod}
	before := len(prod.General)

	pv := m.PreviewValue(d, general, "SUPPORT_EMAIL", "mail:${{ self.PUBLIC_HOST }}", VisPlain)
	if pv.Text != "mail:example.org" || pv.Vis != VisPlain || len(pv.Errors) != 0 || len(pv.Refs) != 1 || !pv.Refs[0].OK {
		t.Fatalf("self in General: %+v", pv)
	}
	// an imported shared variable is a variable of the environment; shared.KEY reaches it too
	if pv := m.PreviewValue(d, general, "X", "${{ self.CONTACT_ADDRESS }} ${{ shared.CONTACT_ADDRESS }}", VisPlain); pv.Text != "help@example.org help@example.org" {
		t.Fatalf("imported: %+v", pv)
	}
	// the strictest visibility wins, and a sealed value is never shown through a reference
	pv = m.PreviewValue(d, Place{Env: prod, Product: portal}, "X", "k=${{ self.COOKIE_KEY }}", VisPlain)
	if pv.Vis != VisSealed || len(pv.Because) != 1 || pv.Because[0] != "self.COOKIE_KEY" {
		t.Fatalf("sealed: %+v", pv)
	}
	if strings.Contains(pv.Text, "sig") {
		t.Fatal("a sealed value came through a reference")
	}
	// the pair (environment, site): a product sees the variables of its site and its subgroup, General does not see a site's when there are two
	if pv := m.PreviewValue(d, Place{Env: prod, Product: portal}, "X", "${{ self.GKE_POOL }}/${{ self.EXPORT_BUCKET }}", VisPlain); pv.Text != "c1/b1" || len(pv.Errors) != 0 {
		t.Fatalf("product pair: %+v", pv)
	}
	if pv := m.PreviewValue(d, Place{Env: prod, Site: main}, "X", "${{ self.GKE_POOL }}", VisPlain); pv.Text != "c1" {
		t.Fatalf("site: %+v", pv)
	}
	// two sites and a value of General: resolved per site, never a false "no value" for the site that has it
	pv = m.PreviewValue(d, general, "X", "${{ self.GKE_POOL }}", VisPlain)
	if len(pv.Sites) != 2 || pv.Sites[0].Site != "main" || pv.Sites[0].Text != "c1" || len(pv.Sites[0].Errors) != 0 || len(pv.Sites[1].Errors) != 1 || !strings.Contains(pv.Sites[1].Errors[0], "no value self.GKE_POOL") {
		t.Fatalf("two sites, no pair: %+v", pv)
	}
	if pv := m.PreviewValue(d, general, "X", "${{ self.PUBLIC_HOST }}", VisPlain); len(pv.Sites) != 0 || pv.Text != "example.org" {
		t.Fatalf("sites agree: %+v", pv)
	}
	// a cycle names its chain; editing a value that refers to itself is one
	pv = m.PreviewValue(d, general, "PUBLIC_HOST", "${{ self.PUBLIC_HOST }}", VisPlain)
	if len(pv.Errors) != 1 || !strings.HasPrefix(pv.Errors[0], "cycle: self.PUBLIC_HOST -> self.PUBLIC_HOST") {
		t.Fatalf("cycle: %+v", pv)
	}
	// a shared value has no environment
	pv = m.PreviewValue(d, Place{}, "X", "${{ self.PUBLIC_HOST }}", VisPlain)
	if len(pv.Errors) != 1 || !strings.Contains(pv.Errors[0], "no environment") {
		t.Fatalf("shared: %+v", pv)
	}
	if pv := m.PreviewValue(d, Place{}, "X", "${{ shared.CONTACT_ADDRESS }}", VisPlain); pv.Text != "help@example.org" {
		t.Fatalf("shared to shared: %+v", pv)
	}
	// a preview changes nothing
	if len(prod.General) != before || prod.Product("portal").Sub["google-cluster"][0].Value != "b1" || len(prod.Sites) != 2 {
		t.Fatal("the preview changed the model")
	}
}

func TestBatchesExpandReferences(t *testing.T) {
	m := sample()
	d := desc(t)
	prod := m.Env("prod")
	prod.General = append(prod.General, &Var{Key: "HOME_URL", Value: "https://${{ self.PUBLIC_HOST }}/", Vis: VisPlain})
	prod.Product("portal").Vars = append(prod.Product("portal").Vars, &Var{Key: "POOL_REF", Value: "${{ self.GKE_POOL }}-${{ self.EXPORT_BUCKET }}", Vis: VisPlain})
	bs, err := Batches(m, d, "prod", Selection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, b := range bs {
		for _, v := range b.Vars {
			found[b.Name+"/"+v.Key] = v.Value
		}
	}
	if found["general/HOME_URL"] != "https://example.org/" || found["product-portal/POOL_REF"] != "c1-b1" {
		t.Fatalf("expanded: %v", found)
	}
	prod.General = append(prod.General, &Var{Key: "BROKEN", Value: "${{ self.NOPE }}", Vis: VisPlain})
	if _, err := Batches(m, d, "prod", Selection{All: true}); err == nil || !strings.Contains(err.Error(), "general BROKEN") {
		t.Fatalf("broken: %v", err)
	}
}

func TestSelfInSharedAndConnectionsIsRefused(t *testing.T) {
	m := sample()
	m.Shared[0].Value = "${{ self.PUBLIC_HOST }}"
	if errs := m.Check(); len(errs) != 1 || !strings.Contains(errs[0], "shared CONTACT_ADDRESS") {
		t.Fatalf("shared: %v", errs)
	}
	m = sample()
	m.Connections[0].Fields[1].Value = "${{ self.PUBLIC_HOST }}"
	if errs := m.Check(); len(errs) != 1 || !strings.Contains(errs[0], "connection GCP main") {
		t.Fatalf("connection: %v", errs)
	}
}

func TestBrokenRefsAndTargets(t *testing.T) {
	m := sample()
	d := desc(t)
	prod := m.Env("prod")
	if got := m.BrokenRefs(d, prod); len(got) != 0 {
		t.Fatalf("clean: %v", got)
	}
	prod.General = append(prod.General, &Var{Key: "OK_REF", Value: "${{ self.PUBLIC_HOST }}", Vis: VisPlain})
	prod.Product("portal").Vars = append(prod.Product("portal").Vars, &Var{Key: "BAD_REF", Value: "${{ self.NOPE }}", Vis: VisPlain})
	got := m.BrokenRefs(d, prod)
	want := []Broken{{Where: "product", Name: "portal", Key: "BAD_REF", Msg: "no value self.NOPE"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("broken: %v", got)
	}
	var self, shared []string
	for _, x := range m.RefTargets(d, Place{Env: prod, Product: prod.Product("portal")}) {
		switch x.System {
		case "self":
			self = append(self, x.Key)
		case "shared":
			shared = append(shared, x.Key)
		}
	}
	if !contains(self, "PUBLIC_HOST") || !contains(self, "GKE_POOL") || !reflect.DeepEqual(shared, []string{"CONTACT_ADDRESS"}) {
		t.Fatalf("targets: self %v shared %v", self, shared)
	}
	for _, x := range m.RefTargets(d, Place{}) {
		if x.System == "self" {
			t.Fatal("a shared value is offered self")
		}
	}
}

func TestRefTargetsForLeavesOutCycles(t *testing.T) {
	m := sample()
	d := desc(t)
	prod := m.Env("prod")
	prod.General = append(prod.General,
		&Var{Key: "EDITED", Value: "x", Vis: VisPlain},
		&Var{Key: "BACK", Value: "${{ self.EDITED }}", Vis: VisPlain},
		&Var{Key: "BACK2", Value: "${{ self.BACK }}", Vis: VisPlain},
		&Var{Key: "FINE", Value: "ok", Vis: VisPlain})
	keys := func(l []RefTarget) []string {
		var out []string
		for _, x := range l {
			out = append(out, x.System+"."+x.Key)
		}
		return out
	}
	got := keys(m.RefTargetsFor(d, Place{Env: prod}, "EDITED"))
	for _, bad := range []string{"self.EDITED", "self.BACK", "self.BACK2"} {
		if contains(got, bad) {
			t.Errorf("%s offered: %v", bad, got)
		}
	}
	for _, ok := range []string{"self.FINE", "self.PUBLIC_HOST", "shared.CONTACT_ADDRESS"} {
		if !contains(got, ok) {
			t.Errorf("%s missing: %v", ok, got)
		}
	}
	if all := keys(m.RefTargetsFor(d, Place{Env: prod}, "")); !contains(all, "self.EDITED") || !contains(all, "self.BACK") {
		t.Errorf("no key must not filter: %v", all)
	}
	// the shared level: a shared variable that refers to the edited one is a cycle too
	m.Shared = append(m.Shared, &Var{Key: "S_EDITED", Value: "x", Vis: VisPlain}, &Var{Key: "S_BACK", Value: "${{ shared.S_EDITED }}", Vis: VisPlain}, &Var{Key: "S_FINE", Value: "y", Vis: VisPlain})
	sg := keys(m.RefTargetsFor(d, Place{}, "S_EDITED"))
	if contains(sg, "shared.S_EDITED") || contains(sg, "shared.S_BACK") || !contains(sg, "shared.S_FINE") || !contains(sg, "shared.CONTACT_ADDRESS") {
		t.Errorf("shared: %v", sg)
	}
}

func contains(l []string, x string) bool {
	for _, y := range l {
		if y == x {
			return true
		}
	}
	return false
}

func TestSelfIsAReservedNameInTheModel(t *testing.T) {
	for _, mod := range []func(m *Vault){
		func(m *Vault) { m.Env("prod").Name = "self" },
		func(m *Vault) { m.Env("prod").Sites[0].Name = "self" },
		func(m *Vault) { m.Connections[0].Name = "Self" },
	} {
		m := sample()
		mod(m)
		found := false
		for _, e := range m.Check() {
			found = found || strings.Contains(e, "'self'")
		}
		if !found {
			t.Errorf("a name self was accepted: %v", m.Check())
		}
	}
}

func TestBatchesExpandConnectionFields(t *testing.T) {
	m := sample()
	d := desc(t)
	m.Connections[0].Fields[1].Value = "proj-${{ shared.CONTACT_ADDRESS }}"
	bs, err := Batches(m, d, "prod", Selection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, b := range bs {
		if b.Kind == BatchConnection {
			for _, v := range b.Vars {
				ok = ok || v.Value == "proj-help@example.org"
			}
		}
	}
	if !ok {
		t.Fatal("a reference in a connection field is not resolved in the export")
	}
	m.Connections[0].Fields[1].Value = "${{ shared.NOPE }}"
	if _, err := Batches(m, d, "prod", Selection{All: true}); err == nil || !strings.Contains(err.Error(), "shared.NOPE") {
		t.Fatalf("broken field: %v", err)
	}
}
