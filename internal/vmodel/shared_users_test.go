package vmodel

import (
	"reflect"
	"testing"
)

func TestSharedUsers(t *testing.T) {
	m := sample()
	prod := m.Env("prod")
	oauth := &Var{Key: "SHARED_CLIENT_ID", Value: "id-1", Vis: VisPlain}
	m.Shared = append(m.Shared, oauth)
	if got := m.SharedUsers(oauth); len(got) != 0 {
		t.Fatalf("unused: %v", got)
	}
	// a direct import
	prod.Imports = append(prod.Imports, oauth)
	if got := m.SharedUsers(oauth); !reflect.DeepEqual(got, []string{"prod"}) {
		t.Fatalf("import: %v", got)
	}
	// a reference under another name in General; the import and the reference of one environment give one line
	prod.General = append(prod.General, &Var{Key: "SOCIAL_CLIENT_ID", Value: "${{ shared.SHARED_CLIENT_ID }}", Vis: VisPlain})
	if got := m.SharedUsers(oauth); !reflect.DeepEqual(got, []string{"prod (SOCIAL_CLIENT_ID)"}) {
		t.Fatalf("general: %v", got)
	}
	// a chain through self: only the value that holds the reference is named
	prod.General = append(prod.General, &Var{Key: "VIA_SELF", Value: "${{ self.SOCIAL_CLIENT_ID }}", Vis: VisPlain})
	// a site, a product and its subgroup, an escaped reference that is only text
	prod.Site("main").Vars = append(prod.Site("main").Vars, &Var{Key: "SITE_ID", Value: "x-${{ shared.SHARED_CLIENT_ID }}", Vis: VisPlain})
	portal := prod.Product("portal")
	portal.Vars = append(portal.Vars, &Var{Key: "PROD_ID", Value: "${{ shared.SHARED_CLIENT_ID }}", Vis: VisPlain}, &Var{Key: "TEXT_ONLY", Value: "$${{ shared.SHARED_CLIENT_ID }}", Vis: VisPlain})
	portal.Sub["google-cluster"] = append(portal.Sub["google-cluster"], &Var{Key: "SUB_ID", Value: "${{ shared.SHARED_CLIENT_ID }}", Vis: VisPlain})
	if got := m.SharedUsers(oauth); !reflect.DeepEqual(got, []string{"prod (SOCIAL_CLIENT_ID, SITE_ID, PROD_ID, SUB_ID)"}) {
		t.Fatalf("site and product: %v", got)
	}
	// another shared value and a connection field
	m.Shared = append(m.Shared, &Var{Key: "SHARED_COPY", Value: "${{ shared.SHARED_CLIENT_ID }}", Vis: VisPlain})
	m.Connection("State store").Fields = append(m.Connection("State store").Fields, &Field{Name: "token", Value: "${{ shared.SHARED_CLIENT_ID }}"})
	got := m.SharedUsers(oauth)
	if len(got) != 3 || got[1] != "shared (SHARED_COPY)" || got[2] != "State store (token)" {
		t.Fatalf("shared and connection: %v", got)
	}
}
