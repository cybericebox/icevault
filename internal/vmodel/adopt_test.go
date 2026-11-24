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
	p.Vars = append(p.Vars, &Var{Key: "ANALYTICS_ID", Value: "site-77", Vis: VisPlain}, &Var{Key: "BILLING_ACCOUNT", Value: "${{ shared.CONTACT_ADDRESS }}", Vis: VisSecret, Expires: "2027-03-01"})
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
	if c.Field("token").Expires != "2027-03-01" {
		t.Fatal("the expiry date moves with the value")
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
	have := &Connection{Name: "Stats", Kind: "stats", Fields: []*Field{{Name: "site_id", Value: "other-1"}, {Name: "token", Value: ""}}}
	m.Connections = append(m.Connections, have)
	plan, _ := AdoptConnections(m, d, "prod")
	if len(plan) != 1 || plan[0].New || plan[0].Chosen != "named" || plan[0].Connection != "Stats" || strings.Join(plan[0].Conflicts, ",") != "ANALYTICS_ID" || strings.Join(plan[0].Variables, ",") != "BILLING_ACCOUNT" {
		t.Fatalf("the connection the description names is used: %+v", plan)
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

// A connection of the kind that this environment does not use may belong to other environments: it is never filled; a new one is made.
func TestAdoptConnectionsLeavesAConnectionOfAnotherEnvironmentAlone(t *testing.T) {
	d := descWithKind(t)
	m, _ := portalWithOwnValues(t)
	other := &Connection{Name: "Stats staging", Kind: "stats", Fields: []*Field{{Name: "site_id", Value: ""}}}
	m.Connections = append(m.Connections, other)
	plan, _ := AdoptConnections(m, d, "prod")
	if len(plan) != 1 || !plan[0].New || plan[0].Chosen != "new" || plan[0].Connection != "Stats" {
		t.Fatalf("%+v", plan)
	}
	if other.Field("site_id").Value != "" || len(other.Fields) != 1 {
		t.Fatal("another environment's connection was filled")
	}
}

// A variable the environment holds in several places with different values moves nowhere and loses nothing.
func TestAdoptConnectionsKeepsAVariableThatDiffers(t *testing.T) {
	d := descWithKind(t)
	m, p := portalWithOwnValues(t)
	p.Sub = map[string][]*Var{"google-cluster": {{Key: "ANALYTICS_ID", Value: "site-OTHER", Vis: VisPlain}}}
	plan, _ := AdoptConnections(m, d, "prod")
	if len(plan) != 1 || strings.Join(plan[0].Differing, ",") != "ANALYTICS_ID" || strings.Join(plan[0].Variables, ",") != "BILLING_ACCOUNT" {
		t.Fatalf("%+v", plan)
	}
	if len(p.Sub["google-cluster"]) != 1 {
		t.Fatal("the other place lost its value")
	}
	n := 0
	for _, x := range p.Vars {
		if x.Key == "ANALYTICS_ID" {
			n++
		}
	}
	if n != 1 || m.Connection("Stats").Field("site_id") != nil {
		t.Fatal("a differing variable was moved")
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

// A sealed value never moves, in any path: it stays an own value with its visibility, and the adoption names it as kept.
func TestAdoptConnectionsNeverMovesASealedValue(t *testing.T) {
	d := descWithKind(t)
	m, p := portalWithOwnValues(t)
	for _, x := range p.Vars {
		if x.Key == "BILLING_ACCOUNT" {
			x.Vis = VisSealed
			x.Value = "sealed-secret-9"
		}
	}
	plan, err := AdoptConnections(m, d, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || strings.Join(plan[0].Variables, ",") != "ANALYTICS_ID" || strings.Join(plan[0].Sealed, ",") != "BILLING_ACCOUNT" || strings.Join(plan[0].Conflicts, ",") != "BILLING_ACCOUNT" {
		t.Fatalf("%+v", plan)
	}
	kept := false
	for _, x := range p.Vars {
		if x.Key == "BILLING_ACCOUNT" {
			kept = x.Vis == VisSealed && x.Value == "sealed-secret-9"
		}
	}
	if !kept {
		t.Fatal("the sealed value moved or lost its visibility")
	}
	if f := m.Connection("Stats").Field("token"); f != nil && f.Value != "" {
		t.Fatal("the sealed value is in the connection")
	}
	// only sealed values: nothing moves and no connection is made
	m2, p2 := portalWithOwnValues(t)
	p2.Vars = p2.Vars[:1]
	p2.Vars = append(p2.Vars, &Var{Key: "ANALYTICS_ID", Value: "x", Vis: VisSealed})
	n := len(m2.Connections)
	plan2, _ := AdoptConnections(m2, d, "prod")
	if len(plan2) != 1 || plan2[0].Count() != 0 || len(m2.Connections) != n || len(p2.Connections) != 1 {
		t.Fatalf("%+v", plan2)
	}
}
