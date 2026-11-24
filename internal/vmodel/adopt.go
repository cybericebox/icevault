package vmodel

import (
	"fmt"

	"github.com/cybericebox/icevault/internal/project"
)

// An adoption moves a variable an environment holds as its own value into the connection the project description now gives it (a product's
// connections: ... variables: name/field). The connection is the one the product already has, else the one of the description's name, else the
// only one of its kind, else a new one; the raw value moves as it is (a reference stays a reference), the product selects the connection and the
// own value is removed. A plan holds names only, never a value.

// Adoption is what moves for one connection of one product.
type Adoption struct {
	Product string
	Kind    string
	// Connection is the name of the connection that gets the values; New says the adoption makes it.
	Connection string
	New        bool
	// Chosen says why this connection: "product" (the product already has one of the kind), "this-environment" (another product or site of the
	// environment uses it), "named" (the one the description names) or "new".
	Chosen string
	// Variables are the names that move (in the order of the description).
	Variables []string
	// Conflicts are variables whose connection field already holds another value: they stay where they are.
	Conflicts []string
	// Sealed are variables that stay where they are because their value is sealed (never shown, never moved: a connection field can be revealed).
	// They are also listed in Conflicts.
	Sealed []string
	// Differing are variables held in several places of the environment with different values: nothing of them is touched (also in Conflicts).
	Differing []string
}

// Count is the number of values the adoption moves.
func (a Adoption) Count() int { return len(a.Variables) }

// AdoptConnections moves the values of the environment into connections (see above) and returns what it did. It changes m in memory only: the
// caller saves it, or drops it for a dry run. An environment the vault does not hold is an error.
func AdoptConnections(m *Vault, d *project.Description, env string) ([]Adoption, error) {
	e := m.Env(env)
	if e == nil {
		return nil, fmt.Errorf("the vault holds no environment %s", env)
	}
	var out []Adoption
	for _, p := range e.Products {
		dp := d.Product(p.Name)
		if dp == nil || !p.Enabled || p.Place == PlaceNone {
			continue
		}
		for _, use := range dp.Connections {
			if a, ok := adoptUse(m, d, e, p, use); ok {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// ownValue finds where the environment holds the variable as its own value: the product, its site-kind subgroups and, when no other product
// of the description takes the variable from a connection, General.
func ownValue(d *project.Description, e *Environment, p *Product, name string) []ownHome {
	var found []ownHome
	find := func(get func() []*Var, set func([]*Var)) {
		for _, x := range get() {
			if x.Key == name {
				found = append(found, ownHome{v: x, remove: func() { set(without(get(), x)) }})
			}
		}
	}
	find(func() []*Var { return p.Vars }, func(l []*Var) { p.Vars = l })
	for k := range p.Sub {
		find(func() []*Var { return p.Sub[k] }, func(l []*Var) { p.Sub[k] = l })
	}
	shared := false
	for _, o := range d.Products {
		if o.Name == p.Name {
			continue
		}
		for _, u := range o.Connections {
			for _, v := range u.Variables {
				shared = shared || v.Name == name
			}
		}
	}
	if !shared {
		find(func() []*Var { return e.General }, func(l []*Var) { e.General = l })
	}
	return found
}

type ownHome struct {
	v      *Var
	remove func()
}

func adoptUse(m *Vault, d *project.Description, e *Environment, p *Product, use project.ConnectionUse) (Adoption, bool) {
	type move struct {
		name  string
		field string
		homes []ownHome
		value string
		vis   string
		// expires is the expiry date of the value (kept when it moves)
		expires string
	}
	var moves []move
	var sealed, differing []string
	for _, v := range use.Variables {
		if v.Field == "" {
			continue
		}
		homes := ownValue(d, e, p, v.Name)
		if len(homes) == 0 {
			continue
		}
		isSealed := false
		for _, h := range homes {
			isSealed = isSealed || h.v.Vis == VisSealed
		}
		if isSealed {
			sealed = append(sealed, v.Name) // a sealed value never moves: the visibility is never lowered
			continue
		}
		mv := move{name: v.Name, field: v.Field, homes: homes, vis: VisPlain}
		differ := false
		for _, h := range homes {
			if h.v.Value != "" && mv.value != "" && h.v.Value != mv.value {
				differ = true
			}
			if mv.value == "" {
				mv.value = h.v.Value
			}
			if mv.expires == "" {
				mv.expires = h.v.Expires
			}
			if h.v.Vis != VisPlain {
				mv.vis = VisSecret
			}
		}
		if v.Secret {
			mv.vis = VisSecret
		}
		if differ {
			differing = append(differing, v.Name) // the same variable holds different values in several places: nothing is touched
			continue
		}
		moves = append(moves, mv)
	}
	a := Adoption{Product: p.Name, Kind: use.Kind, Sealed: sealed, Differing: differing, Conflicts: append(append([]string(nil), sealed...), differing...)}
	if len(moves) == 0 {
		return a, len(a.Conflicts) > 0
	}
	c, why := adoptTarget(m, d, e, p, use)
	a.Chosen = why
	if c == nil {
		a.Chosen = "new"
		k, _ := d.Kinds().Kind(use.Kind)
		name := or(use.Name, or(k.Title, use.Kind))
		base := name
		for i := 2; m.Connection(name) != nil; i++ {
			name = fmt.Sprintf("%s %d", base, i)
		}
		c = &Connection{Name: name, Kind: use.Kind}
		m.Connections = append(m.Connections, c)
		a.New = true
	}
	a.Connection = c.Name
	for _, mv := range moves {
		f := c.Field(mv.field)
		if f != nil && f.Value != "" && mv.value != "" && f.Value != mv.value {
			a.Conflicts = append(a.Conflicts, mv.name)
			continue
		}
		secret := mv.vis != VisPlain
		if f == nil {
			c.Fields = append(c.Fields, &Field{Name: mv.field, Value: mv.value, Secret: secret, Expires: mv.expires})
		} else {
			if f.Value == "" {
				f.Value = mv.value
			}
			if f.Expires == "" {
				f.Expires = mv.expires
			}
			f.Secret = f.Secret || secret
		}
		for _, h := range mv.homes {
			h.remove()
		}
		a.Variables = append(a.Variables, mv.name)
	}
	if len(a.Variables) == 0 {
		if a.New {
			m.Connections = m.Connections[:len(m.Connections)-1]
		}
		return a, len(a.Conflicts) > 0
	}
	have := false
	for _, x := range p.Connections {
		have = have || x == c
	}
	if !have {
		p.Connections = append(p.Connections, c)
	}
	return a, true
}

// adoptTarget is the connection the values go to and why, nil when a new one is to be made. Only a connection this environment already uses (or the
// one the description names) is taken: another connection of the kind may belong to other environments, and filling it would change them.
func adoptTarget(m *Vault, d *project.Description, e *Environment, p *Product, use project.ConnectionUse) (*Connection, string) {
	for _, x := range p.Connections {
		if x.Kind == use.Kind {
			return x, "product"
		}
	}
	for _, o := range e.Products {
		for _, x := range o.Connections {
			if x.Kind == use.Kind {
				return x, "this-environment"
			}
		}
	}
	for _, s := range e.Sites {
		for _, x := range []*Connection{s.Connection, s.State} {
			if x != nil && x.Kind == use.Kind {
				return x, "this-environment"
			}
		}
	}
	k, _ := d.Kinds().Kind(use.Kind)
	if c := m.Connection(or(use.Name, k.Title)); c != nil && c.Kind == use.Kind {
		return c, "named"
	}
	return nil, "new"
}

func without(list []*Var, x *Var) []*Var {
	var out []*Var
	for _, v := range list {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}
