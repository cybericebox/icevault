// Package vmodel is the vault model: what a vault holds for deploying into several environments .
// On the vault level: Shared variables, Connections (a kind and a name, with the fields of the kind) and Other secrets;
// in an environment: General (with imported shared variables), Sites (where to run: a kind, a connection, where the state lives, settings) and
// Products (what runs: on or off, a site, the connections it needs, its own variables and a subgroup per site kind). store.go keeps it in the
// KDBX file, batch.go exports it per run, compat.go lays it out as the settings files the project's scripts read today.
package vmodel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cybericebox/icevault/internal/kinds"
	"github.com/cybericebox/icevault/internal/model"
)

// Format is the version of the vault model this tool reads and writes. A vault without one is in the layout before the model (IceVault 0.2), which this version does not read.
const Format = 1

// FormatKey is the key of the format version in the custom data of the database.
const FormatKey = "IceVault.Format"

// Visibility and who manages a value (the words of the store).
const (
	VisPlain      = "plain"
	VisSecret     = "secret"
	VisSealed     = "sealed"
	ManagedOwner  = "owner"
	ManagedSystem = "system"
)

// Var is a variable: a key with a value.
type Var struct {
	UUID        string
	Key         string
	Value       string
	Description string
	Managed     string // owner | system
	Vis         string // plain | secret | sealed
	Labels      []string
	Changed     string
	Expires     string // the date the value expires (YYYY-MM-DD), "" = never
}

// Field is a field of a connection.
type Field struct {
	Name   string
	Value  string
	Secret bool
	// Expires is the date the value expires (YYYY-MM-DD), "" = never.
	Expires string
}

// Connection is an access to an outside service, on the vault level.
type Connection struct {
	UUID        string
	Name        string
	Kind        string
	Description string
	Fields      []*Field
	Changed     string // the last change of its entry
}

// Field returns a field by name, or nil.
func (c *Connection) Field(name string) *Field {
	for _, f := range c.Fields {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// Set stores a field (made when missing).
func (c *Connection) Set(name, value string, secret bool) {
	if f := c.Field(name); f != nil {
		f.Value, f.Secret = value, f.Secret || secret
		return
	}
	c.Fields = append(c.Fields, &Field{Name: name, Value: value, Secret: secret})
}

// File is a file (an attachment) of an environment or a site.
type File struct {
	UUID    string
	Rel     string // the path the project's scripts see (below the plaintext tree of the environment)
	Data    []byte
	Mode    int
	Managed string
	Vis     string
	Changed string
}

// Site is where things run.
type Site struct {
	UUID       string
	Name       string
	Kind       string
	Connection *Connection
	State      *Connection
	// StateBackend is the word of the project for where the Terraform state lives (hcp, legacy), kept as it was.
	StateBackend string
	Vars         []*Var
	Files        []*File
}

// Product is what runs.
type Product struct {
	UUID    string
	Name    string
	Enabled bool
	// Place is the word of the project for where the product runs (cluster, compose, host, none, external:<env>); "" = not said.
	Place       string
	Site        *Site
	Connections []*Connection
	Vars        []*Var
	Sub         map[string][]*Var // site kind -> variables used only on a site of that kind
}

// Environment is one deployment target.
type Environment struct {
	UUID     string
	Name     string
	Title    string
	General  []*Var
	Imports  []*Var // shared variables imported into General (pointers into Vault.Shared)
	Sites    []*Site
	Products []*Product
	Files    []*File
	// Layouts are the stored layouts of the project's files (comments, order, quoting; no value), by stem, kept byte for byte from the layout
	// before the model so the files come out as they were.
	Layouts map[string][]byte
	// Derived names the derived and place variables this environment writes into the project's files; nil = all of them.
	Derived []string
}

// Other is a free entry outside the model: never exported to a deployment.
type Other struct {
	UUID  string
	Title string
	Value string
	Notes string
	Data  []byte // the attachment "content", if any
	// Extra is the path below the plaintext folder of a single extra file of the layout before the model (export --file).
	Extra string
	Mode  int
	// Expires is the date the secret expires (YYYY-MM-DD), "" = never.
	Expires string
}

// Vault is the whole model.
type Vault struct {
	Format      int
	ReadOnly    bool // a newer format: readable, never written
	Shared      []*Var
	Connections []*Connection
	Envs        []*Environment
	Other       []*Other
	// Problems are what Load found broken (a reference to a missing entry, an unknown kind): shown, never fatal for reading.
	Problems []string
}

// Env returns an environment by name, or nil.
func (v *Vault) Env(name string) *Environment {
	for _, e := range v.Envs {
		if e.Name == name {
			return e
		}
	}
	return nil
}

// Connection returns a connection by name, or nil.
func (v *Vault) Connection(name string) *Connection {
	for _, c := range v.Connections {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// SharedVar returns a shared variable by key, or nil.
func (v *Vault) SharedVar(key string) *Var {
	for _, s := range v.Shared {
		if s.Key == key {
			return s
		}
	}
	return nil
}

// EnvNames lists the environments, sorted.
func (v *Vault) EnvNames() []string {
	out := make([]string, 0, len(v.Envs))
	for _, e := range v.Envs {
		out = append(out, e.Name)
	}
	sort.Strings(out)
	return out
}

// Site returns a site by name, or nil.
func (e *Environment) Site(name string) *Site {
	for _, s := range e.Sites {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// Product returns a product by name, or nil.
func (e *Environment) Product(name string) *Product {
	for _, p := range e.Products {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// GeneralValues is the General group with the imported shared variables: the environment's own value of a name replaces the imported one.
func (e *Environment) GeneralValues() []*Var {
	out := append([]*Var(nil), e.General...)
	for _, s := range e.Imports {
		if findVar(e.General, s.Key) == nil {
			out = append(out, s)
		}
	}
	return out
}

// WritesDerived reports whether the environment writes a derived or place variable into the project's files.
func (e *Environment) WritesDerived(name string) bool {
	if e.Derived == nil {
		return true
	}
	for _, d := range e.Derived {
		if d == name {
			return true
		}
	}
	return false
}

func findVar(vs []*Var, key string) *Var {
	for _, v := range vs {
		if v.Key == key {
			return v
		}
	}
	return nil
}

var (
	// EnvNameRE is the form of an environment name (as the commands take it).
	EnvNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,19}$`)
	// ThingNameRE is the form of a site or product name.
	ThingNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	// KeyRE is the form of a variable key.
	KeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,99}$`)
)

// ValidConnectionName: 1 to 64 characters, no slash, not starting with a dot, no line break.
func ValidConnectionName(n string) bool {
	return n != "" && len(n) <= 64 && !strings.ContainsAny(n, "/\n\r") && !strings.HasPrefix(n, ".") && strings.TrimSpace(n) == n
}

// Check lists what is wrong with the model (names, kinds, references); empty means it can be written.
func (v *Vault) Check() []string {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	known := map[*Connection]bool{}
	names := map[string]bool{}
	for _, c := range v.Connections {
		known[c] = true
		if strings.EqualFold(c.Name, model.SelfRef) {
			add("connection %q: 'self' is the word references use for the environment itself", c.Name)
		}
		if !ValidConnectionName(c.Name) {
			add("connection %q: not a name (1-64 characters, no slash)", c.Name)
		}
		if names[c.Name] {
			add("connection %s: twice", c.Name)
		}
		names[c.Name] = true
		k, ok := kinds.ConnectionKind(c.Kind)
		if !ok {
			add("connection %s: unknown kind %q", c.Name, c.Kind)
		}
		seen := map[string]bool{}
		for _, f := range c.Fields {
			if !kinds.FieldRE.MatchString(f.Name) || reservedField(f.Name) {
				add("connection %s: field %q is not a field name", c.Name, f.Name)
			}
			if seen[f.Name] {
				add("connection %s: field %s twice", c.Name, f.Name)
			}
			seen[f.Name] = true
			if _, err := ParseDay(f.Expires); err != nil {
				add("connection %s: the expiry of field %s: %v", c.Name, f.Name, err)
			}
			_ = k
		}
	}
	checkVars := func(where string, vs []*Var) {
		seen := map[string]bool{}
		for _, x := range vs {
			if !KeyRE.MatchString(x.Key) {
				add("%s: %q is not a variable name", where, x.Key)
			}
			if seen[x.Key] {
				add("%s: %s twice", where, x.Key)
			}
			seen[x.Key] = true
			if strings.ContainsAny(x.Value, "\n\r") {
				add("%s: the value of %s has a line break", where, x.Key)
			}
			if _, err := ParseDay(x.Expires); err != nil {
				add("%s: the expiry of %s: %v", where, x.Key, err)
			}
		}
	}
	checkVars("shared", v.Shared)
	noSelf := func(where, value string) {
		for _, r := range model.ReferencesIn(value) {
			if r[0] == model.SelfRef {
				add("%s: a reference to self has no environment here (self is for the values of an environment)", where)
				return
			}
		}
	}
	for _, x := range v.Shared {
		noSelf("shared "+x.Key, x.Value)
	}
	for _, c := range v.Connections {
		for _, f := range c.Fields {
			noSelf("connection "+c.Name+" field "+f.Name, f.Value)
		}
	}
	shared := map[*Var]bool{}
	for _, s := range v.Shared {
		shared[s] = true
	}
	envs := map[string]bool{}
	for _, e := range v.Envs {
		w := "environment " + e.Name
		if e.Name == model.SelfRef {
			add("environment %q: 'self' is the word references use for the environment itself", e.Name)
		}
		if !EnvNameRE.MatchString(e.Name) {
			add("environment %q: not an environment name", e.Name)
		}
		if envs[e.Name] {
			add("%s: twice", w)
		}
		envs[e.Name] = true
		checkVars(w+" general", e.General)
		for _, s := range e.Imports {
			if !shared[s] {
				add("%s: imports a shared variable the vault does not have", w)
			}
		}
		sites := map[*Site]bool{}
		sn := map[string]bool{}
		for _, s := range e.Sites {
			sites[s] = true
			sw := w + " site " + s.Name
			if s.Name == model.SelfRef {
				add("%s: 'self' is the word references use for the environment itself", sw)
			}
			if !ThingNameRE.MatchString(s.Name) || sn[s.Name] {
				add("%s: not a name, or twice", sw)
			}
			sn[s.Name] = true
			sk, ok := kinds.SiteKind(s.Kind)
			if !ok {
				add("%s: unknown site kind %q", sw, s.Kind)
			}
			if s.Connection != nil {
				if !known[s.Connection] {
					add("%s: its connection is not in the vault", sw)
				} else if ok && sk.Connection != s.Connection.Kind {
					add("%s: a site of kind %s needs a connection of kind %q, %s is of kind %s", sw, s.Kind, sk.Connection, s.Connection.Name, s.Connection.Kind)
				}
			}
			if s.State != nil {
				if !known[s.State] {
					add("%s: its state connection is not in the vault", sw)
				} else if s.State.Kind != kinds.HCP || (ok && !sk.State) {
					add("%s: the state lives in a connection of kind hcp, on a cloud site", sw)
				}
			}
			checkVars(sw, s.Vars)
		}
		pn := map[string]bool{}
		for _, p := range e.Products {
			pw := w + " product " + p.Name
			if !ThingNameRE.MatchString(p.Name) || pn[p.Name] {
				add("%s: not a name, or twice", pw)
			}
			pn[p.Name] = true
			if p.Site != nil && !sites[p.Site] {
				add("%s: its site is not a site of %s", pw, e.Name)
			}
			for _, c := range p.Connections {
				if !known[c] {
					add("%s: a connection that is not in the vault", pw)
				}
			}
			checkVars(pw, p.Vars)
			for sk, vs := range p.Sub {
				if _, ok := kinds.SiteKind(sk); !ok {
					add("%s: a subgroup for the unknown site kind %q", pw, sk)
				}
				checkVars(pw+" on "+sk, vs)
			}
		}
	}
	return errs
}

func reservedField(name string) bool {
	switch name {
	case "Title", "UserName", "Password", "URL", "Notes":
		return true
	}
	return strings.HasPrefix(name, "IceVault")
}
