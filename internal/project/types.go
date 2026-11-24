package project

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// The types a variable may declare (type: in the description). No type is free text.
const (
	TypeString = "string"
	TypeBool   = "bool"
	TypeInt    = "int"
	TypeEmail  = "email"
	TypeURL    = "url"
	TypeDomain = "domain"
	TypeEnum   = "enum"
)

// Types lists the types in the order the documentation names them.
var Types = []string{TypeString, TypeBool, TypeInt, TypeEmail, TypeURL, TypeDomain, TypeEnum}

// The rules a value can break: the word a report and the window give (never the value).
const (
	RuleBool    = "bool"
	RuleInt     = "int"
	RuleEmail   = "email"
	RuleURL     = "url"
	RuleDomain  = "domain"
	RuleEnum    = "enum"
	RulePattern = "pattern"
	RuleRange   = "range"  // an int outside min..max
	RuleLength  = "length" // longer than MaxLength
)

// MaxLength is the longest value, and the longest pattern, a description may declare or a check reads.
const MaxLength = 4096

var (
	refRE    = regexp.MustCompile(`(^|[^$])\$\{\{`)
	intRE    = regexp.MustCompile(`^-?[0-9]+$`)
	emailRE  = regexp.MustCompile(`^[^@\s/]+@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
	domainRE = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,61}[A-Za-z0-9]$`)
)

// IsReference reports whether a value holds a reference "${{ ... }}" (an escaped "$${{" is text). A reference is checked against the type only
// after it resolves, never as typed.
func IsReference(value string) bool { return refRE.MatchString(value) }

// Kind is the declared type, string when none.
func (v Variable) Kind() string {
	if v.Type == "" {
		return TypeString
	}
	return v.Type
}

// Typed reports whether the variable declares anything a value is checked against.
func (v Variable) Typed() bool { return (v.Type != "" && v.Type != TypeString) || v.Pattern != "" }

// ValueProblem checks a value against the declared type, the choices and the pattern: "" when it fits, else the rule it breaks (Rule...). An
// empty value is "not set" and always fits; a value with a reference is not checked here. It never returns the value.
func (v Variable) ValueProblem(value string) string {
	if value == "" || IsReference(value) {
		return ""
	}
	if len(value) > MaxLength {
		return RuleLength
	}
	switch v.Type {
	case TypeBool:
		if value != "true" && value != "false" {
			return RuleBool
		}
	case TypeInt:
		if !intRE.MatchString(value) {
			return RuleInt
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return RuleInt
		}
		if (v.Min != nil && n < *v.Min) || (v.Max != nil && n > *v.Max) {
			return RuleRange
		}
	case TypeEmail:
		if len(value) > 254 || !emailRE.MatchString(value) {
			return RuleEmail
		}
	case TypeURL:
		u, err := url.Parse(value)
		if err != nil || u.Scheme == "" || u.Host == "" || strings.ContainsAny(value, " \t") {
			return RuleURL
		}
	case TypeDomain:
		if value != "localhost" && (len(value) > 253 || !domainRE.MatchString(value)) {
			return RuleDomain
		}
	case TypeEnum:
		if !contains(v.Choices, value) {
			return RuleEnum
		}
	}
	if v.Pattern != "" {
		if re, err := anchored(v.Pattern); err != nil || !re.MatchString(value) {
			return RulePattern
		}
	}
	return ""
}

// anchored compiles a pattern so that it must match the whole value. The pattern has to be a regular expression on its own and keep its groups
// inside the anchors: "a)|(b" does not compile alone, and so cannot slip out of the anchors.
func anchored(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > MaxLength {
		return nil, fmt.Errorf("longer than %d", MaxLength)
	}
	alone, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		return nil, err
	}
	if re.NumSubexp() != alone.NumSubexp() {
		return nil, fmt.Errorf("its groups change when it is anchored")
	}
	return re, nil
}

// Typed returns the first variable of that name that declares a type, choices or a pattern, or nil. One name has one type in a description
// (Validate), so it does not matter which home answers.
func (d *Description) Typed(name string) *Variable {
	var found *Variable
	d.Walk(func(h Home) {
		if found == nil && h.Var.Name == name && h.Var.Typed() {
			v := h.Var
			found = &v
		}
	})
	return found
}

// ValueProblem checks a value of the variable called name: "" when it fits or the variable declares nothing.
func (d *Description) ValueProblem(name, value string) string {
	if v := d.Typed(name); v != nil {
		return v.ValueProblem(value)
	}
	return ""
}

// validateType lists what is wrong with the type metadata of one variable.
func (v Variable) validateType(w string, add func(string, ...any)) {
	if v.Type != "" && !contains(Types, v.Type) {
		add("%s: type %q is not one of %s", w, v.Type, strings.Join(Types, ", "))
	}
	if v.Type == TypeEnum && len(v.Choices) == 0 {
		add("%s: an enum names its choices (choices: [a, b])", w)
	}
	if v.Type != TypeEnum && len(v.Choices) > 0 {
		add("%s: choices only belong to type enum", w)
	}
	if v.Type != TypeInt && (v.Min != nil || v.Max != nil) {
		add("%s: min and max only belong to type int", w)
	}
	if v.Min != nil && v.Max != nil && *v.Min > *v.Max {
		add("%s: min is above max", w)
	}
	seen := map[string]bool{}
	for _, c := range v.Choices {
		switch {
		case len(c) > MaxLength:
			add("%s: a choice is longer than %d", w, MaxLength)
		case c == "" || strings.TrimSpace(c) != c || strings.ContainsAny(c, "\r\n"):
			add("%s: a choice is a non-empty single line without outer spaces", w)
		case seen[c]:
			add("%s: choice %q twice", w, c)
		}
		seen[c] = true
	}
	if v.Pattern != "" {
		if v.Type != "" && v.Type != TypeString {
			add("%s: pattern only belongs to a string variable (type %s has its own rule)", w, v.Type)
		}
		if _, err := anchored(v.Pattern); err != nil {
			add("%s: pattern is not a regular expression (%v)", w, err)
		}
	}
}

// sameType reports whether two declarations of one name agree.
func (v Variable) sameType(o Variable) bool {
	return v.Kind() == o.Kind() && v.Pattern == o.Pattern && fmt.Sprint(v.Choices) == fmt.Sprint(o.Choices) && sameBound(v.Min, o.Min) && sameBound(v.Max, o.Max)
}

func sameBound(a, b *int64) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

// Active reports whether a variable of that name is used under these settings: a variable whose when condition is false at every home is not
// used (it is not rendered, so nothing is checked against its type). A name the description does not know is active.
func (d *Description) Active(name string, get func(string) string) bool {
	g := d.Getter(get)
	known, active := false, false
	d.Walk(func(h Home) {
		if h.Var.Name != name {
			return
		}
		known = true
		if c, err := ParseWhen(h.Var.When); err != nil || c == nil || c.Holds(g) {
			active = true
		}
	})
	return !known || active
}
