package project

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/example"
)

func load(t *testing.T) *Description {
	t.Helper()
	d, err := Parse(example.Description())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTheExampleIsValid(t *testing.T) {
	d := load(t)
	if d.Name != "Lumen Notes" || len(d.Products) != 3 || d.SiteKindOf("gcp") != "google-cluster" || d.SiteKindOf("compose") != "compose" || d.GeneralFile() != "core.env" {
		t.Fatalf("%+v", d)
	}
	hs := d.Homes("shared/blobs.env", "BLOB_KEY_SECRET")
	if len(hs) != 2 || hs[0].Kind != HomeProductConnection || hs[0].Var.Field != "secret_access_key" {
		t.Fatalf("a connection two products share: %+v", hs)
	}
	if hs := d.Homes("targets/gcp.env", "EXPORT_BUCKET"); len(hs) != 1 || hs[0].Kind != HomeProductSub || hs[0].SiteKind != "google-cluster" || !hs[0].Var.System() {
		t.Fatalf("bucket %+v", hs)
	}
	if !d.SystemVar("targets/gcp.env", "EXPORT_BUCKET") || d.SystemVar("targets/compose.env", "EXPORT_BUCKET") {
		t.Fatal("managed by the system in one file only")
	}
	if !d.GeneratedVar("COOKIE_KEY") || d.GeneratedVar("PUBLIC_HOST") {
		t.Fatal("generated")
	}
	if hs := d.Homes("services/portal.env", "PUBLIC_HOST"); len(hs) != 1 || hs[0].Kind != HomeGeneral {
		t.Fatalf("public host %+v", hs)
	}
	if k := d.Kept("keys/gcp/release/r1.key"); k == nil || k.Guard != "release" || !k.KeepRetired {
		t.Fatalf("kept %+v", k)
	}
	if k := d.Kept("keys/gcp/release/ACTIVE"); k == nil || k.KeepRetired {
		t.Fatal("the first rule that matches wins")
	}
	if d.LeftOutWhy("dumps/x") == "" || d.LeftOutWhy("services/portal.env") != "" {
		t.Fatal("left out")
	}
	if d.SessionPrefix() != "lumen" || d.SessionVars().Marker != "LUMEN_SESSION" || d.SessionVars().SettingsFile != "ICEVAULT_SETTINGS_FILE" {
		t.Fatalf("session %+v", d.SessionVars())
	}
	if a := d.App("web-client"); a == nil || a.Prefix != "VITE_" || d.App("nope") != nil {
		t.Fatal("apps")
	}
	if c := d.Served("monitor"); c == nil || c.Kind != "other" {
		t.Fatal("served")
	}
	if d.RequiredCheck == nil || d.RequiredCheck.Interpreter != "sh" || d.RequiredCheck.Script != "tools/check-required.sh" {
		t.Fatal("required check")
	}
}

// Which files an environment reads, by the conditions of the example.
func TestFileUses(t *testing.T) {
	d := load(t)
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	prod := get(map[string]string{"HOSTING": "gcp", "PORTAL": "cluster", "ENGINE": "cluster", "INDEXER": "host"})
	dev := get(map[string]string{"HOSTING": "compose", "PORTAL": "shared", "ENGINE": "cluster", "INDEXER": "none"})
	for f, want := range map[string]Use{"targets/gcp-access.env": UseWhole, "targets/gcp.env": UseWhole, "shared/blobs.env": UseWhole, "services/portal.env": UseWhole,
		"services/engine.env": UseWhole, "services/indexer.env": UseWhole, "targets/compose.env": UseNone, "core.env": UseWhole} {
		if got := d.FileUse(f, prod); got != want {
			t.Errorf("prod %s: %v", f, got)
		}
	}
	for f, want := range map[string]Use{"shared/blobs.env": UseWhole, "services/portal.env": UsePartly, "services/engine.env": UsePartly, "services/indexer.env": UseNone,
		"targets/compose.env": UseWhole, "targets/gcp.env": UseNone} {
		if got := d.FileUse(f, dev); got != want {
			t.Errorf("dev %s: %v", f, got)
		}
	}
	if !d.KeyUsed("services/portal.env", "THEME_COLOR", dev) || d.KeyUsed("services/portal.env", "PUBLIC_HOST", dev) {
		t.Error("partly-used keys")
	}
	if d.FileUse("shared/blobs.env", get(map[string]string{"HOSTING": "elsewhere"})) != UseNone {
		t.Error("HOSTING in [gcp, compose]")
	}
	// the defaults (INDEXER none) and the word before '@' (PORTAL=shared@staging is shared)
	if d.FileUse("services/indexer.env", get(map[string]string{"HOSTING": "gcp"})) != UseNone {
		t.Error("the default of INDEXER")
	}
	if d.FileUse("services/portal.env", get(map[string]string{"HOSTING": "compose", "PORTAL": "shared@staging", "ENGINE": "none"})) != UseNone {
		t.Error("the word before '@'")
	}
	if d.FileUse("services/portal.env", get(map[string]string{"HOSTING": "compose", "PORTAL": "cluster@x"})) != UseWhole {
		t.Error("cluster@x is cluster")
	}
}

// The new parts of format 2 are checked as strictly as the rest.
func TestValidationOfFormat2(t *testing.T) {
	base := string(example.Description())
	cases := map[string][2]string{
		"a condition on an unknown key":     {"used-when: HOSTING=compose\n", "used-when: NOWHERE=compose\n"},
		"a partly-used key that is no name": {"keys: [THEME_COLOR]", "keys: [theme-color]"},
		"a guarded pattern without /.+":     {"pattern: keys/[a-z0-9_-]+/release/.+", "pattern: keys/[a-z0-9_-]+/release"},
		"a bad mode":                        {"mode: \"0400\"\n    why: names", "mode: \"rw\"\n    why: names"},
		"a reserved guard word":             {"guard: release", "guard: sealed"},
		"an app with nothing to take":       {"    all: true\n", "\n"},
		"required and required-when":        {"required-when: \"INDEXER=cluster\"}", "required-when: \"INDEXER=cluster\", required: true}"},
		"a vault that is not a kdbx file":   {"vault: plain/vault/lumen.kdbx", "vault: plain/vault/lumen.txt"},
		"a session prefix":                  {"prefix: lumen", "prefix: Lumen Notes"},
		"no general file":                   {"general:\n  file: core.env", "general:\n  file: nowhere.conf"},
		"a mode for the group":              {"mode: \"0600\"\n    why: made once", "mode: \"0640\"\n    why: made once"},
		"an example outside the app":        {"    prefix: VITE_\n", "    prefix: VITE_\n    example: ../../secret.env\n"},
	}
	for name, c := range cases {
		if !strings.Contains(base, c[0]) {
			t.Fatalf("%s: the example has no %q", name, c[0])
		}
		if _, err := Parse([]byte(strings.Replace(base, c[0], c[1], 1))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a file is a path or a mapping
	if _, err := Parse([]byte(strings.Replace(base, "  - core.env\n", "  - {path: core.env}\n", 1))); err != nil {
		t.Fatal(err)
	}
}

func TestValidationListsEveryProblem(t *testing.T) {
	bad := `format: 4
name: ""
files: [a.env, a.env, /abs]
general:
  variables:
    - {name: lower, file: a.env}
    - {name: X, file: nope.env, when: "garbage"}
    - {name: Y, file: a.env, when: "NOPE=1", label: {de: x}}
site-kinds:
  moon-base: {provider: moon}
  local:
    provider: local
    connection: {kind: aws, variables: []}
products:
  - name: Bad_Name
    file: a.env
    connections:
      - {kind: ftp, variables: []}
      - kind: aws
        file: a.env
        variables: [{name: Z}]
derived:
  - {name: P, file: a.env, from: elsewhere}
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("accepted")
	}
	want := []string{"format is 4", "name is empty", "a.env twice", "not a relative path", "is not a variable name", "nope.env is not in files", "a condition is",
		"the condition names NOPE, which the description does not have", "language", "moon-base: not a site kind", "a local kind has no connection", "lower case letters",
		"connection kind \"ftp\"", "names its field", "from is site.provider"}
	all := strings.Join(err.(*Errors).List, "\n")
	for _, w := range want {
		if !strings.Contains(all, w) {
			t.Errorf("no %q in\n%s", w, all)
		}
	}
	if _, err := Parse([]byte("format: 2\nname: x\nunknown: 1\n")); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestConditions(t *testing.T) {
	vals := map[string]string{"A": "x", "L": "main, event"}
	get := func(k string) string { return vals[k] }
	for s, want := range map[string]bool{"A=x": true, "A=y": false, "A!=y": true, "L has event": true, "L has id": false, "B=": true,
		"A in [x, y]": true, "A in [y]": false, "A not in [y, z]": true, "A=x and L has main": true, "A=y or L has main": true, "A=y or L has id": false,
		"not A=y": true, "A=x and (L has id or B=)": true, "A=x and not (B= or L has id)": false, `A="x"`: true, "A=x and B= or A=y": true} {
		c, err := ParseWhen(s)
		if err != nil || c.Holds(get) != want {
			t.Errorf("%s: %v %v", s, c, err)
		}
	}
	for _, bad := range []string{"A", "a=1", "A in x", "A in []", "A=1 and", "(A=1", "A=1 B=2", "A ! 1", "A has"} {
		if _, err := ParseWhen(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if c, _ := ParseWhen("A=1 and (B in [x] or not C=2)"); strings.Join(c.Keys(), ",") != "A,B,C" {
		t.Errorf("keys %v", c.Keys())
	}
}

func TestServeAsSelfIsReserved(t *testing.T) {
	data := strings.Replace(string(example.Description()), "serve-as: monitor", "serve-as: self", 1)
	if _, err := Parse([]byte(data)); err == nil || !strings.Contains(err.Error(), "serve-as cannot be 'self'") {
		t.Fatalf("serve-as self was accepted: %v", err)
	}
}
