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
	pv = m.PreviewValue(d, general, "X", "${{ self.GKE_POOL }}", VisPlain)
	if len(pv.Errors) != 1 || !strings.Contains(pv.Errors[0], "no value self.GKE_POOL") || pv.Refs[0].OK || pv.Text != "" {
		t.Fatalf("two sites, no pair: %+v", pv)
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

func contains(l []string, x string) bool {
	for _, y := range l {
		if y == x {
			return true
		}
	}
	return false
}
