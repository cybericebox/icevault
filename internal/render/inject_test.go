package render

import (
	"strings"
	"testing"
)

// A file name is data from a filesystem: it may hold a line break or hidden
// characters. None of it may reach the notes of the vault.

func mustRefuseTree(t *testing.T, what string, tr tree) {
	t.Helper()
	r := newRun(t)
	_, _, err := r.imp("staging", tr, nil)
	if err == nil {
		t.Errorf("%s: the import must be refused", what)
		return
	}
	if strings.ContainsAny(err.Error(), "\n\r\u2028") {
		t.Errorf("%s: the error carries a raw line break: %q", what, err.Error())
	}
	if r.mv.writes != 0 || len(r.mv.ents) != 0 {
		t.Errorf("%s: nothing may be written, got %d writes", what, r.mv.writes)
	}
}

func TestImportRefusesFileNamesThatWouldInjectNotes(t *testing.T) {
	for name, rel := range map[string]string{
		"a line break and a machine line": "built/a\ntype=aws/keys/x",
		"U+2028 in a directory":           "built/dir\u2028state=retired/keys/x",
		"U+0085":                          "built/x\u0085labels/keys/x",
		"a zero-width space":              "built/x/keys/\u200bstate=retired",
		"a carriage return":               "built/x/keys/a\rtitle=evil",
		"a BOM":                           "built/x/keys/\ufeffstate=x",
		"a space":                         "built/x/keys/a b",
		"a quote":                         "built/x/keys/a\"b",
	} {
		tr := populate()
		tr.put(rel, "A=1\n", 0o600)
		if k, _ := proj().Classify(rel); k == "" {
			continue // a name no rule keeps is not imported at all (below)
		}
		mustRefuseTree(t, name, tr)
	}
	// a key file name too (the rule's .+ takes U+2028 but not a line break)
	tr := populate()
	tr.put("built/google/keys/x\u2028y", "k", 0o600)
	mustRefuseTree(t, "a key file with U+2028", tr)
	// a name the rules do not keep is not imported at all
	r := newRun(t)
	tr2 := populate()
	tr2.put("built/google/keys/x\ny=z", "k", 0o600)
	out := r.mustImport("staging", tr2, nil)
	if strings.Contains(out, "x\ny") || !strings.Contains(out, `x\ny=z`) {
		t.Errorf("an unkept name is reported escaped:\n%s", out)
	}
	for p := range r.mv.ents {
		if strings.Contains(p, "x\ny") {
			t.Error("an unkept file was written")
		}
	}
}

func TestImportRefusesBadEnvironmentAndSiteNames(t *testing.T) {
	r := newRun(t)
	for _, env := range []string{"st\naging", "Staging", "", "a b"} {
		if _, _, err := r.imp(env, populate(), nil); err == nil {
			t.Errorf("environment %q must be refused", env)
		}
	}
	for _, s := range []string{"aws\nmain", "Aws", "a b"} {
		if _, _, err := r.imp("staging", populate(), func(o *Options) { o.Site = s }); err == nil {
			t.Errorf("site %q must be refused", s)
		}
	}
	if r.mv.writes != 0 {
		t.Error("nothing may be written")
	}
}

func TestImportedValuesAndCommentsCannotInjectNotes(t *testing.T) {
	r := newRun(t)
	tr := tree{}
	tr.put("apps/web.env", "# state=retired\n# \u200bvisibility=plain\n# TYPE = aws\n# fine\n# x\u2028labels=evil\nBASE_HOST=example.org\n", 0o600)
	out := r.mustImport("staging", tr, nil)
	contains2(t, out, "had a reserved or hidden line that was not kept")
	n := r.mv.ents["IceVault/environments/staging/apps-web/BASE_HOST"].notes
	eq(t, n, "managed-by=owner\nvisibility=plain\nlabels=file:apps/web.env\nfine", "only what we wrote")
	// a CRLF file imports, and nothing of the carriage returns reaches the notes
	r2 := newRun(t)
	crlf := tree{}
	crlf.put("apps/web.env", "# state=retired\r\n# fine\r\nB=2\r\n", 0o600)
	r2.mustImport("staging", crlf, nil)
	n2 := r2.mv.ents["IceVault/environments/staging/apps-web/B"].notes
	eq(t, n2, "managed-by=owner\nvisibility=plain\nlabels=file:apps/web.env\nfine", "CRLF notes")
	eq(t, rendered(t, r2.p, r2.snap(), "staging", "", false)[webRel], "600|# state=retired\r\n# fine\r\nB=2\r\n", "byte for byte")
	// a key with a carriage return is not a variable at all
	_, vars := ParseEnv("A\r=1\nB=2\n")
	eq(t, vars, []Var{{"B", "2", ""}}, "variables")
	// the names shown in the report are escaped
	r3 := newRun(t)
	odd := populate()
	odd.put("stray/odd\nname.txt", "x", 0o600)
	out = r3.mustImport("staging", odd, nil)
	if strings.Contains(out, "odd\nname") {
		t.Error("a raw line break in the report")
	}
	contains2(t, out, `odd\nname.txt`)
}
