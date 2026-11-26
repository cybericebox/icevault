package mpage

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/vmodel"
)

func navKind(nav map[string]any, id string) map[string]any {
	for _, k := range nav["connection_kinds"].([]map[string]any) {
		if k["id"] == id {
			return k
		}
	}
	return nil
}

func TestDeclaredKindsAreOfferedAndChecked(t *testing.T) {
	c, _ := newCoreWith(t, example.DescriptionDeclaringKind())
	k := navKind(c.Nav(), "stats")
	if k == nil || k["declared"] != true || k["titles"].(map[string]string)["uk"] != "Сервіс статистики" || len(k["fields"].([]map[string]any)) != 2 {
		t.Fatalf("the declared kind is in the list of the window: %v", k)
	}
	if navKind(c.Nav(), "s3") == nil || navKind(c.Nav(), "s3")["declared"] != false {
		t.Fatal("built-in kinds stay")
	}
	if _, err := c.Write("m-connection", map[string]any{"action": "create", "kind": "stats", "name": "Stats main"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-connection", map[string]any{"action": "create", "kind": "nope", "name": "x"}); code(err) != "bad_kind" {
		t.Fatalf("an undeclared kind: %v", err)
	}
	x := c.Model().Connection("Stats main")
	if _, err := c.Write("m-field", map[string]any{"uuid": x.UUID, "field": "token", "value": "t-1", "secret": true}); err != nil {
		t.Fatal(err)
	}
	if f := c.Model().Connection("Stats main").Field("token"); f == nil || !f.Secret || f.Value != "t-1" {
		t.Fatalf("%+v", f)
	}
}

func TestDeclaredFieldTypeAndMultiline(t *testing.T) {
	desc := strings.Replace(string(example.DescriptionDeclaringKind()), "      - {name: token, label: {en: Token}, secret: true}", "      - {name: token, label: {en: Token}, secret: true, multiline: true}\n      - {name: mail, type: email}", 1)
	c, _ := newCoreWith(t, []byte(desc))
	if _, err := c.Write("m-connection", map[string]any{"action": "create", "kind": "stats", "name": "S"}); err != nil {
		t.Fatal(err)
	}
	u := c.Model().Connection("S").UUID
	if _, err := c.Write("m-field", map[string]any{"uuid": u, "field": "mail", "value": "not-mail"}); code(err) != "bad_value" {
		t.Fatalf("the type of the field is checked: %v", err)
	}
	if _, err := c.Write("m-field", map[string]any{"uuid": u, "field": "token", "value": "a\nb", "secret": true}); err != nil {
		t.Fatalf("a multiline field takes line breaks: %v", err)
	}
	if _, err := c.Write("m-field", map[string]any{"uuid": u, "field": "site_id", "value": "a\nb"}); code(err) != "line_break" {
		t.Fatalf("a single-line field refuses them: %v", err)
	}
}

// Without the description that declares it, a connection of the kind is shown as it is, cannot be edited and is never dropped.
func TestAConnectionOfAnUnknownKindIsReadOnlyAndKept(t *testing.T) {
	c, v := newCoreWith(t, example.DescriptionDeclaringKind())
	if _, err := c.Write("m-connection", map[string]any{"action": "create", "kind": "stats", "name": "S"}); err != nil {
		t.Fatal(err)
	}
	u := c.Model().Connection("S").UUID
	if _, err := c.Write("m-field", map[string]any{"uuid": u, "field": "token", "value": "t-1", "secret": true}); err != nil {
		t.Fatal(err)
	}
	bare, err := New(v, nil)
	if err != nil {
		t.Fatal(err)
	}
	nav := bare.Nav()
	var view map[string]any
	for _, x := range nav["connections"].([]map[string]any) {
		if x["name"] == "S" {
			view = x
		}
	}
	if view == nil || view["unknown_kind"] != true || view["kind"] != "stats" {
		t.Fatalf("%v", view)
	}
	if navKind(nav, "stats") != nil {
		t.Fatal("the vault alone has the built-in kinds only")
	}
	if _, err := bare.Write("m-field", map[string]any{"uuid": u, "field": "token", "value": "t-2"}); code(err) != "unknown_kind" {
		t.Fatalf("%v", err)
	}
	for _, a := range []map[string]any{{"uuid": u, "field": "token", "delete": true}} {
		if _, err := bare.Write("m-field", a); code(err) != "unknown_kind" {
			t.Fatalf("a field of an unknown kind is not deleted: %v", err)
		}
	}
	for _, a := range []map[string]any{{"action": "update", "uuid": u, "name": "Renamed"}} {
		if _, err := bare.Write("m-connection", a); code(err) != "unknown_kind" {
			t.Fatalf("%v: %v", a, err)
		}
	}
	if _, err := bare.Write("m-connection", map[string]any{"action": "create", "kind": "aws", "name": "A"}); err != nil {
		t.Fatalf("other writes still work: %v", err)
	}
	m, _ := vmodel.Load(v)
	if f := m.Connection("S").Field("token"); m.Connection("S").Kind != "stats" || f == nil || f.Value != "t-1" {
		t.Fatal("the connection was dropped or changed")
	}
	// the only changes allowed: empty a value (the end of a move), and delete the whole connection
	if _, err := bare.Write("m-field", map[string]any{"uuid": u, "field": "token", "value": "", "expires": ""}); err != nil {
		t.Fatalf("a value of an unknown kind may be emptied: %v", err)
	}
	if f := bare.Model().Connection("S").Field("token"); f == nil || f.Value != "" {
		t.Fatal("the value was not emptied")
	}
	if _, err := bare.Write("m-connection", map[string]any{"action": "delete", "uuid": u}); err != nil {
		t.Fatalf("a connection of an unknown kind may be deleted: %v", err)
	}
	if bare.Model().Connection("S") != nil {
		t.Fatal("the connection is still there")
	}
}

func envOfNav(c *Core, name string) map[string]any {
	for _, e := range c.Nav()["envs"].([]map[string]any) {
		if e["name"] == name {
			return e
		}
	}
	return nil
}

func TestAdoptBannerAndMove(t *testing.T) {
	c, _ := newCoreWith(t, example.DescriptionDeclaringKind())
	if a := envOfNav(c, "prod")["adopt"].([]map[string]any); len(a) != 0 {
		t.Fatalf("nothing to move yet: %v", a)
	}
	p := c.Model().Env("prod").Product("portal")
	p.Vars = append(p.Vars, &vmodel.Var{Key: "ANALYTICS_ID", Value: "site-secret-1", Vis: vmodel.VisPlain}, &vmodel.Var{Key: "BILLING_ACCOUNT", Value: "bill-secret-1", Vis: vmodel.VisSecret})
	if err := c.commit(); err != nil {
		t.Fatal(err)
	}
	a := envOfNav(c, "prod")["adopt"].([]map[string]any)
	if len(a) != 1 || a[0]["kind"] != "stats" || len(a[0]["variables"].([]string)) != 2 || a[0]["new"] != true {
		t.Fatalf("%v", a)
	}
	for k, v := range a[0] {
		if s, ok := v.(string); ok && strings.Contains(s, "secret-") {
			t.Fatalf("the banner carries a value in %s", k)
		}
	}
	if _, err := c.Write("m-env-adopt", map[string]any{"env": "prod"}); err != nil {
		t.Fatal(err)
	}
	if a := envOfNav(c, "prod")["adopt"].([]map[string]any); len(a) != 0 {
		t.Fatalf("moved: %v", a)
	}
	x := c.Model().Connection("Stats")
	if x == nil || x.Field("site_id").Value != "site-secret-1" {
		t.Fatalf("%+v", x)
	}
	if _, err := c.Write("m-env-adopt", map[string]any{"env": "nothing"}); code(err) != "no_env" {
		t.Fatalf("%v", err)
	}
}

func TestRequiredWhenOfAnOptionalConnection(t *testing.T) {
	desc := strings.Replace(string(example.DescriptionDeclaringKind()), "{name: BILLING_ACCOUNT, field: token, secret: true}", "{name: BILLING_ACCOUNT, field: token, secret: true, required-when: \"SIGNUP_MODE=invite\"}", 1)
	d, err := project.Parse([]byte(desc))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := newCoreWith(t, []byte(desc))
	c.d = d
	missing := func() bool {
		for _, p := range envOfNav(c, "prod")["products"].([]map[string]any) {
			for _, r := range p["missing"].([]map[string]any) {
				if r["where"] == "connection" && r["key"] == "stats" {
					return true
				}
			}
		}
		return false
	}
	if missing() {
		t.Fatal("an optional connection is not missing while its condition is off")
	}
	p := c.Model().Env("prod").Product("portal")
	p.Vars = append(p.Vars, &vmodel.Var{Key: "SIGNUP_MODE", Value: "invite", Vis: vmodel.VisPlain})
	if !missing() {
		t.Fatal("a required-when that holds makes the optional connection needed")
	}
}
