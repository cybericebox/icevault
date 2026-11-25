package vmodel

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/project"
)

func TestFillMissingMakesAnOptionalConnectionWhoseRequiredWhenHolds(t *testing.T) {
	desc := strings.Replace(string(example.DescriptionDeclaringKind()), "{name: BILLING_ACCOUNT, field: token, secret: true}", "{name: BILLING_ACCOUNT, field: token, secret: true, required-when: \"SIGNUP_MODE=invite\"}", 1)
	if desc == string(example.DescriptionDeclaringKind()) {
		t.Fatal("the example changed: the required-when was not added")
	}
	d, err := project.Parse([]byte(desc))
	if err != nil {
		t.Fatal(err)
	}
	m := sample()
	has := func() bool {
		for _, c := range m.Envs[0].Product("portal").Connections {
			if c.Kind == "stats" {
				return true
			}
		}
		return false
	}
	if _, err := FillMissing(m, d, "prod", nil); err != nil {
		t.Fatal(err)
	}
	if has() {
		t.Fatal("an optional connection is not made while its condition is off")
	}
	e := m.Envs[0]
	e.General = append(e.General, &Var{Key: "SIGNUP_MODE", Value: "invite", Vis: VisPlain})
	rep, err := FillMissing(m, d, "prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !has() || len(rep.Made) != 1 || rep.Made[0] != "Stats (stats)" {
		t.Fatalf("a required-when that holds makes the optional connection: %+v", rep)
	}
	c := m.Connection("Stats")
	if c.Field("token") == nil || c.Field("site_id") == nil {
		t.Fatalf("its fields are made empty: %+v", c.Fields)
	}
	if errs := m.Check(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if again, _ := FillMissing(m, d, "prod", nil); len(again.Made)+len(again.Linked)+len(again.Added) != 0 {
		t.Fatalf("a second run changes nothing: %+v", again)
	}
}
