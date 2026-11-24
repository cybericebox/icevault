package project

import (
	"fmt"
	"regexp"

	"github.com/cybericebox/icevault/internal/kinds"
)

// ConnectionKind is a kind of connection a description declares: an access to one concrete outside service. A built-in kind keeps its own
// behaviour and cannot be redeclared.
type ConnectionKind struct {
	ID     string      `yaml:"id"`
	Title  Text        `yaml:"title"`
	Help   Text        `yaml:"help,omitempty"`
	Fields []KindField `yaml:"fields"`
}

// KindField is a field of a declared kind; Type, Choices and Pattern are what a variable's are.
type KindField struct {
	Name      string   `yaml:"name"`
	Label     Text     `yaml:"label,omitempty"`
	Help      Text     `yaml:"help,omitempty"`
	Secret    bool     `yaml:"secret,omitempty"`
	Required  bool     `yaml:"required,omitempty"`
	Type      string   `yaml:"type,omitempty"`
	Choices   []string `yaml:"choices,omitempty"`
	Pattern   string   `yaml:"pattern,omitempty"`
	Multiline bool     `yaml:"multiline,omitempty"`
}

var kindIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Kinds is the one lookup of connection kinds for this description: the built-in kinds plus the declared ones. A nil description has the
// built-in kinds only.
func (d *Description) Kinds() kinds.Set {
	if d == nil || len(d.ConnectionKinds) == 0 {
		return kinds.Builtin()
	}
	var out []kinds.Connection
	for _, k := range d.ConnectionKinds {
		if kinds.IsBuiltin(k.ID) {
			continue // Validate refuses it; a description that failed to validate is never used
		}
		c := kinds.Connection{ID: k.ID, Title: k.Title["en"], TitleText: kinds.Text(k.Title), Help: kinds.Text(k.Help), Declared: true}
		for _, f := range k.Fields {
			title := f.Label["en"]
			if title == "" {
				title = f.Name
			}
			c.Fields = append(c.Fields, kinds.Field{Name: f.Name, Title: title, Secret: f.Secret, Label: kinds.Text(f.Label), Help: kinds.Text(f.Help), Required: f.Required,
				Type: f.Type, Choices: f.Choices, Pattern: f.Pattern, Multiline: f.Multiline})
		}
		out = append(out, c)
	}
	return kinds.With(out)
}

// inheritFieldTypes gives a variable of a connection of a declared kind the type, choices and pattern of its field when it names none, so a
// value is checked wherever it is entered.
func (d *Description) inheritFieldTypes() {
	set := d.Kinds()
	fix := func(u *ConnectionUse) {
		if u == nil {
			return
		}
		k, ok := set.Kind(u.Kind)
		if !ok || !k.Declared {
			return
		}
		for i := range u.Variables {
			v := &u.Variables[i]
			if f := k.Field(v.Field); f != nil && v.Type == "" && len(v.Choices) == 0 && v.Pattern == "" {
				v.Type, v.Choices, v.Pattern = f.Type, f.Choices, f.Pattern
			}
		}
	}
	for i := range d.Products {
		for j := range d.Products[i].Connections {
			fix(&d.Products[i].Connections[j])
		}
	}
	for i := range d.VaultConnections {
		fix(&d.VaultConnections[i])
	}
	for id, sk := range d.SiteKinds {
		fix(sk.Connection)
		fix(sk.State)
		d.SiteKinds[id] = sk
	}
}

// validateKinds checks connection-kinds and returns the lookup the rest of the validation uses.
func (d *Description) validateKinds(add func(string, ...any)) kinds.Set {
	seen := map[string]bool{}
	for i, k := range d.ConnectionKinds {
		where := fmt.Sprintf("connection-kinds %d", i+1)
		if k.ID != "" {
			where = "connection kind " + k.ID
		}
		switch {
		case !kindIDRE.MatchString(k.ID):
			add("%s: id %q is lower case letters, digits and dashes", where, k.ID)
		case kinds.IsBuiltin(k.ID):
			add("%s: %s is a built-in kind and cannot be declared again", where, k.ID)
		case seen[k.ID]:
			add("%s: twice", where)
		}
		seen[k.ID] = true
		for _, t := range []struct {
			n string
			t Text
		}{{"title", k.Title}, {"help", k.Help}} {
			for l := range t.t {
				if !contains(Languages, l) {
					add("%s %s: language %q (en, uk, ru)", where, t.n, l)
				}
			}
		}
		if k.Title["en"] == "" {
			add("%s: title needs an en text", where)
		}
		if len(k.Fields) == 0 {
			add("%s: no fields", where)
		}
		names := map[string]bool{}
		for _, f := range k.Fields {
			w := where + " field " + f.Name
			if !kinds.FieldRE.MatchString(f.Name) {
				add("%s: %q is not a field name", where, f.Name)
			}
			if names[f.Name] {
				add("%s: twice", w)
			}
			names[f.Name] = true
			for _, t := range []Text{f.Label, f.Help} {
				for l := range t {
					if !contains(Languages, l) {
						add("%s: language %q (en, uk, ru)", w, l)
					}
				}
			}
			if f.Multiline && f.Type != "" && f.Type != TypeString {
				add("%s: multiline is for a text field", w)
			}
			Variable{Type: f.Type, Choices: f.Choices, Pattern: f.Pattern}.validateType(w, add)
		}
	}
	return d.Kinds()
}
