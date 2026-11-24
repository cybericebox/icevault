package project

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/example"
)

func withKinds(t *testing.T, kindsYAML, productConn string) (*Description, error) {
	t.Helper()
	s := string(example.Description())
	s = strings.Replace(s, "format: 2", "format: 3", 1)
	s = strings.Replace(s, "products:\n", kindsYAML+"\nproducts:\n", 1)
	if productConn != "" {
		s = strings.Replace(s, "    place-variable: INDEXER\n", "    place-variable: INDEXER\n"+productConn, 1)
	}
	return Parse([]byte(s))
}

const mailerKind = `connection-kinds:
  - id: mailer
    title: {en: Mail relay, uk: Поштовий релей}
    help: {en: Sends the mails of the service.}
    fields:
      - {name: host, label: {en: Host}, type: domain, required: true}
      - {name: api_key, label: {en: API key, uk: Ключ API}, secret: true, required: true}
      - {name: sender, label: {en: Sender}, type: email}
      - {name: mode, type: enum, choices: [live, test]}
`

const mailerUse = `    connections:
      - kind: mailer
        optional: true
        file: services/indexer.env
        variables:
          - {name: MAIL_HOST, field: host}
          - {name: MAIL_KEY, field: api_key, secret: true, required-when: "INDEXER=cluster"}
          - {name: MAIL_FROM, field: sender}
`

func TestDeclaredKinds(t *testing.T) {
	d, err := withKinds(t, mailerKind, mailerUse)
	if err != nil {
		t.Fatal(err)
	}
	k, ok := d.Kinds().Kind("mailer")
	if !ok || !k.Declared || k.TitleIn("uk") != "Поштовий релей" || k.TitleIn("ru") != "Mail relay" || len(k.Fields) != 4 || k.Field("api_key") == nil || !k.Field("api_key").Secret {
		t.Fatalf("%+v", k)
	}
	if _, ok := d.Kinds().Kind("s3"); !ok {
		t.Fatal("built-in kinds stay")
	}
	if _, ok := (*Description)(nil).Kinds().Kind("mailer"); ok {
		t.Fatal("no description, no declared kinds")
	}
	if _, ok := load(t).Kinds().Kind("mailer"); ok {
		t.Fatal("declared kind leaked")
	}
	// the variable takes the type of its field
	if p := d.ValueProblem("MAIL_FROM", "not-an-email"); p == "" {
		t.Fatal("a variable of a declared field is checked by the field's type")
	}
	if p := d.ValueProblem("MAIL_FROM", "a@b.example"); p != "" {
		t.Fatal(p)
	}
}

func TestDeclaredKindsAreChecked(t *testing.T) {
	for name, c := range map[string]struct{ kinds, use, want string }{
		"built-in id":               {strings.Replace(mailerKind, "id: mailer", "id: s3", 1), "", "built-in kind"},
		"twice":                     {mailerKind + strings.Replace(strings.TrimPrefix(mailerKind, "connection-kinds:\n"), "  - id", "  - id", 1), mailerUse, "twice"},
		"bad id":                    {strings.Replace(mailerKind, "id: mailer", "id: Mail_Relay", 1), "", "lower case letters"},
		"no title":                  {strings.Replace(mailerKind, "title: {en: Mail relay, uk: Поштовий релей}", "title: {uk: x}", 1), "", "en text"},
		"language":                  {strings.Replace(mailerKind, "uk: Ключ API", "de: x", 1), "", "language"},
		"no fields":                 {"connection-kinds:\n  - {id: empty, title: {en: Empty}, fields: []}\n", "", "no fields"},
		"bad type":                  {strings.Replace(mailerKind, "type: domain", "type: nope", 1), "", "type"},
		"bad field":                 {strings.Replace(mailerKind, "name: host", "name: 1host", 1), "", "not a field name"},
		"field twice":               {strings.Replace(mailerKind, "name: sender", "name: host", 1), "", "twice"},
		"unknown field of the kind": {mailerKind, strings.Replace(mailerUse, "field: sender", "field: nowhere", 1), "not a field of the declared kind"},
		"undeclared kind":           {"", mailerUse, "neither built in nor declared"},
	} {
		_, err := withKinds(t, c.kinds, c.use)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, err)
		}
	}
}

func TestDeclaredKindsNeedFormat3(t *testing.T) {
	s := strings.Replace(string(example.Description()), "products:\n", mailerKind+"\nproducts:\n", 1)
	_, err := Parse([]byte(s)) // format: 2
	if err == nil || !strings.Contains(err.Error(), "needs format 3") {
		t.Fatal(err)
	}
	// an older tool reads format 2 only and refuses format 3 by its number
	if Format != 3 || MinFormat != 2 {
		t.Fatal(Format, MinFormat)
	}
}
