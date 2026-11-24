package project

import (
	"strings"
	"testing"
)

func TestValueProblem(t *testing.T) {
	enum := Variable{Name: "MODE", Type: TypeEnum, Choices: []string{"open", "invite"}}
	cases := []struct {
		v    Variable
		val  string
		want string
	}{
		{Variable{Name: "A"}, "anything at all", ""},
		{Variable{Name: "A", Type: TypeString}, "x y", ""},
		{enum, "", ""},
		{enum, "open", ""},
		{enum, "closed", RuleEnum},
		{enum, "Open", RuleEnum},
		{Variable{Name: "B", Type: TypeBool}, "true", ""},
		{Variable{Name: "B", Type: TypeBool}, "false", ""},
		{Variable{Name: "B", Type: TypeBool}, "yes", RuleBool},
		{Variable{Name: "N", Type: TypeInt}, "-12", ""},
		{Variable{Name: "N", Type: TypeInt}, "12.5", RuleInt},
		{Variable{Name: "N", Type: TypeInt}, " 3", RuleInt},
		{Variable{Name: "E", Type: TypeEmail}, "a.b+c@example.org", ""},
		{Variable{Name: "E", Type: TypeEmail}, "a@b", RuleEmail},
		{Variable{Name: "E", Type: TypeEmail}, "a b@example.org", RuleEmail},
		{Variable{Name: "U", Type: TypeURL}, "https://example.org/x?y=1", ""},
		{Variable{Name: "U", Type: TypeURL}, "example.org", RuleURL},
		{Variable{Name: "U", Type: TypeURL}, "https://", RuleURL},
		{Variable{Name: "D", Type: TypeDomain}, "cyber.example.org", ""},
		{Variable{Name: "D", Type: TypeDomain}, "localhost", ""},
		{Variable{Name: "D", Type: TypeDomain}, "https://example.org", RuleDomain},
		{Variable{Name: "D", Type: TypeDomain}, "example.org/path", RuleDomain},
		{Variable{Name: "D", Type: TypeDomain}, "-bad.example.org", RuleDomain},
		{Variable{Name: "P", Pattern: "[a-z]{2}-[0-9]+"}, "eu-12", ""},
		{Variable{Name: "P", Pattern: "[a-z]{2}-[0-9]+"}, "xeu-12x", RulePattern},
		{Variable{Name: "N", Type: TypeInt, Min: i64(0), Max: i64(7)}, "7", ""},
		{Variable{Name: "N", Type: TypeInt, Min: i64(0), Max: i64(7)}, "8", RuleRange},
		{Variable{Name: "N", Type: TypeInt, Min: i64(0), Max: i64(7)}, "-1", RuleRange},
		{Variable{Name: "N", Type: TypeInt, Min: i64(0)}, "99999999999", ""},
		{Variable{Name: "N", Type: TypeInt}, "99999999999999999999", RuleInt},
		{Variable{Name: "P", Pattern: "a)|(b"}, "b", RulePattern}, // a broken pattern never matches, never slips out of its anchors
		{Variable{Name: "P", Pattern: "a|b"}, "ab", RulePattern},
		{Variable{Name: "P", Pattern: "a|b"}, "b", ""},
		{Variable{Name: "S"}, strings.Repeat("x", MaxLength+1), RuleLength},
		{Variable{Name: "S"}, strings.Repeat("x", MaxLength), ""},
		// a reference is checked after it resolves
		{Variable{Name: "N", Type: TypeInt}, "${{ shared.COUNT }}", ""},
		{enum, "prefix ${{ shared.MODE }}", ""},
		{Variable{Name: "N", Type: TypeInt}, "$${{ shared.COUNT }}", RuleInt},
	}
	for _, c := range cases {
		if got := c.v.ValueProblem(c.val); got != c.want {
			t.Errorf("%s %q: got %q, want %q", c.v.Type, c.val, got, c.want)
		}
	}
}

func i64(n int64) *int64 { return &n }

func TestIsReference(t *testing.T) {
	for v, want := range map[string]bool{"${{ a.B }}": true, "x ${{ a.B }} y": true, "$${{ a.B }}": false, "${ a }": false, "": false, "{{ a }}": false} {
		if IsReference(v) != want {
			t.Errorf("%q", v)
		}
	}
}

func desc(vars string) []byte {
	return []byte("format: 2\nname: T\ncheckout: {environments: e, plaintext: p, vault: v.kdbx}\nfiles: [core.env]\ngeneral:\n  file: core.env\n  variables:\n" + vars +
		"site-kinds:\n  compose: {provider: compose, file: core.env}\nproducts: []\n")
}

func TestTypeMetadataIsValidated(t *testing.T) {
	for name, tc := range map[string]struct{ vars, want string }{
		"ok":          {"    - {name: MODE, type: enum, choices: [a, b]}\n    - {name: N, type: int}\n    - {name: P, pattern: '[a-z]+'}\n", ""},
		"unknown":     {"    - {name: X, type: number}\n", "type"},
		"no choices":  {"    - {name: X, type: enum}\n", "choices"},
		"stray":       {"    - {name: X, type: int, choices: [a]}\n", "choices"},
		"empty":       {"    - {name: X, type: enum, choices: [a, '']}\n", "choice"},
		"twice":       {"    - {name: X, type: enum, choices: [a, a]}\n", "twice"},
		"bad pattern": {"    - {name: X, pattern: '('}\n", "pattern"},
		"alone":       {"    - {name: X, pattern: 'a)|(b'}\n", "pattern"},
		"long":        {"    - {name: X, pattern: '" + strings.Repeat("a", MaxLength+1) + "'}\n", "pattern"},
		"min/max":     {"    - {name: X, type: int, min: 0, max: 7}\n", ""},
		"min above":   {"    - {name: X, type: int, min: 8, max: 7}\n", "min is above max"},
		"min on text": {"    - {name: X, type: string, min: 1}\n", "min and max"},
		"pattern/int": {"    - {name: X, type: int, pattern: '[0-9]+'}\n", "pattern"},
	} {
		_, err := Parse(desc(tc.vars))
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTypeOfOneNameAgrees(t *testing.T) {
	d := []byte(string(desc("    - {name: X, type: int}\n")))
	d = []byte(strings.Replace(string(d), "site-kinds:\n  compose: {provider: compose, file: core.env}", "site-kinds:\n  compose: {provider: compose, file: core.env, variables: [{name: X, type: bool}]}", 1))
	if _, err := Parse(d); err == nil || !strings.Contains(err.Error(), "X") {
		t.Fatalf("two types for one name: %v", err)
	}
}

func TestSpecOf(t *testing.T) {
	d, err := Parse(desc("    - {name: MODE, type: enum, choices: [a, b]}\n    - {name: FREE}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if v := d.Typed("MODE"); v == nil || len(v.Choices) != 2 {
		t.Fatal("typed")
	}
	if d.Typed("FREE") != nil || d.Typed("NOPE") != nil {
		t.Fatal("free text and unknown names have no type")
	}
	if p := d.ValueProblem("MODE", "c"); p != RuleEnum || d.ValueProblem("FREE", "c") != "" {
		t.Fatal(p)
	}
}

func TestWhenFalseVariableIsNotActive(t *testing.T) {
	d, err := Parse(desc("    - {name: MODE, type: enum, choices: [a, b]}\n    - {name: ONLY_A, type: int, when: 'MODE=a'}\n"))
	if err != nil {
		t.Fatal(err)
	}
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if !d.Active("ONLY_A", get(map[string]string{"MODE": "a"})) || d.Active("ONLY_A", get(map[string]string{"MODE": "b"})) || !d.Active("MODE", get(nil)) || !d.Active("UNKNOWN", get(nil)) {
		t.Fatal("when decides")
	}
}
