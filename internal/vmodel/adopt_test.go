package vmodel

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/project"
)

// descWithKind is the example project where the portal takes two of its variables from a connection of a kind the description declares.
func descWithKind(t *testing.T) *project.Description {
	t.Helper()
	d, err := project.Parse(example.DescriptionDeclaringKind())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func portalWithOwnValues(t *testing.T) (*Vault, *Product) {
	m := sample()
	p := m.Envs[0].Product("portal")
	p.Vars = append(p.Vars, &Var{Key: "ANALYTICS_ID", Value: "site-77", Vis: VisPlain}, &Var{Key: "BILLING_ACCOUNT", Value: "${{ shared.CONTACT_ADDRESS }}", Vis: VisSecret})
	return m, p
}

func TestAdoptConnectionsMovesOwnValues(t *testing.T) {
	d := descWithKind(t)
	m, p := portalWithOwnValues(t)
	plan, err := AdoptConnections(m, d, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].Product != "portal" || plan[0].Kind != "stats" || !plan[0].New || plan[0].Connection != "Stats" || strings.Join(plan[0].Variables, ",") != "ANALYTICS_ID,BILLING_ACCOUNT" {
		t.Fatalf("%+v", plan)
	}
	c := m.Connection("Stats")
	if c == nil || c.Kind != "stats" || c.Field("site_id").Value != "site-77" || c.Field("site_id").Secret {
		t.Fatalf("%+v", c)
	}
	if f := c.Field("token"); f == nil || f.Value != "${{ shared.CONTACT_ADDRESS }}" || !f.Secret {
		t.Fatal("a reference moves as a reference, and a secret stays secret")
	}
	for _, x := range p.Vars {
		if x.Key == "ANALYTICS_ID" || x.Key == "BILLING_ACCOUNT" {
			t.Fatalf("%s was not removed", x.Key)
		}
	}
	if len(p.Vars) != 1 || len(p.Connections) != 2 || p.Connections[1] != c {
		t.Fatalf("the product selects the connection: %+v", p.Connections)
	}
	if errs := m.Check(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if again, _ := AdoptConnections(m, d, "prod"); len(again) != 0 {
		t.Fatalf("a second run moves nothing: %+v", again)
	}
	if _, err := AdoptConnections(m, d, "nowhere"); err == nil {
		t.Fatal("no such environment")
	}
}

func TestAdoptConnectionsFillsAndKeepsConflicts(t *testing.T) {
	d := descWithKind(t)
	m, p := portalWithOwnValues(t)
	have := &Connection{Name: "Stats main", Kind: "stats", Fields: []*Field{{Name: "site_id", Value: "other-1"}, {Name: "token", Value: ""}}}
	m.Connections = append(m.Connections, have)
	plan, _ := AdoptConnections(m, d, "prod")
	if len(plan) != 1 || plan[0].New || plan[0].Connection != "Stats main" || strings.Join(plan[0].Conflicts, ",") != "ANALYTICS_ID" || strings.Join(plan[0].Variables, ",") != "BILLING_ACCOUNT" {
		t.Fatalf("the only connection of the kind is used: %+v", plan)
	}
	if have.Field("site_id").Value != "other-1" || have.Field("token").Value == "" {
		t.Fatal("a value that differs stays, an empty field is filled")
	}
	kept := false
	for _, x := range p.Vars {
		kept = kept || (x.Key == "ANALYTICS_ID" && x.Value == "site-77")
	}
	if !kept {
		t.Fatal("a value in conflict stays an own value")
	}
}

func TestAdoptConnectionsNeedsAnEnabledProductAndSkipsEmptyPlans(t *testing.T) {
	d := descWithKind(t)
	m, _ := portalWithOwnValues(t)
	m.Envs[0].Product("portal").Enabled = false
	if plan, _ := AdoptConnections(m, d, "prod"); len(plan) != 0 {
		t.Fatalf("%+v", plan)
	}
	if len(m.Connections) != 4 {
		t.Fatal("a connection was made for nothing")
	}
}

func TestAKindOnlyTheDescriptionKnowsStaysInTheVault(t *testing.T) {
	m := sample()
	m.Connections = append(m.Connections, &Connection{Name: "Stats", Kind: "stats", Fields: []*Field{{Name: "token", Value: "x", Secret: true}}})
	if errs := m.Check(); len(errs) > 0 {
		t.Fatalf("a connection of a kind this tool does not know is kept: %v", errs)
	}
}
