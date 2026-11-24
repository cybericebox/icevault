// Package mpage is the window's core on a vault of the vault model (internal/vmodel): the answers of the page for the two levels of the model
// (Shared, Connections, Other secrets; environments with General, Sites and Products) and its writes. Every write changes the model in memory,
// checks it, writes it into the vault through vmodel.Sync (the one write path) and saves; a refusal changes nothing. Values: a plain value is
// in the answer; a secret or sealed one never is, only Reveal gives one secret value. The labels and help texts come from the project
// description (uk, en, ru); without one the variables show by name.
package mpage

import (
	"sort"
	"strings"

	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/kinds"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// The keys of the answers and the arguments that many ops share, and the actions of the CRUD ops.
const (
	jName     = "name"
	jState    = "state"
	jKind     = "kind"
	jEnv      = "env"
	jKey      = "key"
	jList     = "list"
	jTitle    = "title"
	jWhere    = "where"
	actCreate = "create"
	actUpdate = "update"
	actDelete = "delete"
)

// Core is the window's core over an open vault of the vault model.
type Core struct {
	v *vault.Vault
	m *vmodel.Vault
	d *project.Description // nil: no project description found
	// DescPath is where the description was read from ("" when none); DescErr is why it could not be read.
	DescPath, DescErr string
	// NoProject says the vault has no project on purpose (no description is expected): the page does not offer the missing description as a problem.
	NoProject bool
	// Remember saves a description path the window was given (cli.RememberProject); nil: not offered.
	Remember func(path string) error
}

// New loads the model of an open vault. d may be nil (no description): the vault still opens.
func New(v *vault.Vault, d *project.Description) (*Core, error) {
	m, err := vmodel.Load(v)
	if err != nil {
		return nil, err
	}
	return &Core{v: v, m: m, d: d}, nil
}

// Model is the model the core holds (tests).
func (c *Core) Model() *vmodel.Vault { return c.m }

func refuse(code string, params map[string]any) error {
	if params == nil {
		params = map[string]any{}
	}
	return &desktop.Error{Status: 409, Code: code, Params: params}
}

func bad(code string) error { return &desktop.Error{Status: 400, Code: code, Params: map[string]any{}} }

// ---- answers

func text(t project.Text) map[string]string {
	if len(t) == 0 {
		return nil
	}
	return t
}

// varView is one variable as the page shows it: a plain value only.
func (c *Core) varView(x *vmodel.Var, h *project.Variable, values func(string) string) map[string]any {
	state := "set"
	if x == nil || x.Value == "" {
		state = "empty"
	}
	out := map[string]any{jState: state}
	if x != nil {
		out[jKey], out["visibility"], out["managed"], out["description"], out["changed"] = x.Key, x.Vis, x.Managed, x.Description, x.Changed
		if x.Vis == vmodel.VisPlain {
			out["value"] = x.Value
		}
	}
	if h != nil {
		out[jKey] = h.Name
		out["label"], out["help"] = text(h.Label), text(h.Help)
		required := h.Required
		if cond, err := project.ParseWhen(h.RequiredWhen); err == nil && cond != nil && values != nil && cond.Holds(values) {
			required = true // required-when holds: the variable is needed now
		}
		out["required"], out["when"], out["secret"], out["system"] = required, h.When, h.Secret, h.System()
		if h.Type != "" {
			out["type"] = h.Type
		}
		if h.Min != nil {
			out["min"] = *h.Min
		}
		if h.Max != nil {
			out["max"] = *h.Max
		}
		if len(h.Choices) > 0 {
			out["choices"] = h.Choices
		}
		if h.Pattern != "" {
			out["has_pattern"] = true
		}
		active := true
		if cond, err := project.ParseWhen(h.When); err == nil && cond != nil && values != nil {
			active = cond.Holds(values)
		}
		out["active"] = active
		if x == nil {
			out["missing"] = true
			out["visibility"] = vmodel.VisPlain
			if h.Secret {
				out["visibility"] = vmodel.VisSecret
			}
		}
	}
	return out
}

// vars lists the variables of a scope: the described ones in the order of the description (present or missing), then the others by key.
func (c *Core) vars(have []*vmodel.Var, described []project.Variable, values func(string) string) []map[string]any {
	out := []map[string]any{}
	seen := map[string]bool{}
	for i := range described {
		h := &described[i]
		var x *vmodel.Var
		for _, v := range have {
			if v.Key == h.Name {
				x = v
			}
		}
		seen[h.Name] = true
		out = append(out, c.varView(x, h, values))
	}
	rest := []*vmodel.Var{}
	for _, v := range have {
		if !seen[v.Key] {
			rest = append(rest, v)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].Key < rest[j].Key })
	for _, v := range rest {
		out = append(out, c.varView(v, nil, values))
	}
	return out
}

func (c *Core) connView(x *vmodel.Connection) map[string]any {
	k, _ := kinds.ConnectionKind(x.Kind)
	fields := []map[string]any{}
	names := map[string]bool{}
	add := func(name, title string, secret bool) {
		f := x.Field(name)
		state := "empty"
		if f != nil && f.Value != "" {
			state = "set"
		}
		if f != nil {
			secret = secret || f.Secret
		}
		row := map[string]any{jName: name, jTitle: title, "secret": secret, jState: state, "present": f != nil}
		if f != nil && !secret {
			row["value"] = f.Value
		}
		used := []string{}
		if c.d != nil {
			c.d.Walk(func(h project.Home) {
				if h.Conn != nil && h.Conn.Kind == x.Kind && h.Var.Field == name && !contains(used, h.Var.Name) {
					used = append(used, h.Var.Name)
				}
			})
		}
		row["variables"] = used
		fields = append(fields, row)
		names[name] = true
	}
	for _, f := range k.Fields {
		add(f.Name, f.Title, f.Secret)
	}
	for _, f := range x.Fields {
		if !names[f.Name] {
			add(f.Name, "", f.Secret)
		}
	}
	return map[string]any{"uuid": x.UUID, jName: x.Name, jKind: x.Kind, "kind_title": k.Title, "description": x.Description, "fields": fields, "users": c.usersOf(x), "changed": x.Changed}
}

// usersOf lists what uses a connection: "env/site name", "env/site name (state)", "env/product name".
func (c *Core) usersOf(x *vmodel.Connection) []map[string]string {
	out := []map[string]string{}
	for _, e := range c.m.Envs {
		for _, s := range e.Sites {
			if s.Connection == x {
				out = append(out, map[string]string{jEnv: e.Name, jKind: "site", jName: s.Name})
			}
			if s.State == x {
				out = append(out, map[string]string{jEnv: e.Name, jKind: jState, jName: s.Name})
			}
		}
		for _, p := range e.Products {
			for _, pc := range p.Connections {
				if pc == x {
					out = append(out, map[string]string{jEnv: e.Name, jKind: "product", jName: p.Name})
				}
			}
		}
	}
	return out
}

func connUUID(x *vmodel.Connection) string {
	if x == nil {
		return ""
	}
	return x.UUID
}

// values is the namespace of an environment for the conditions (General with imports, the site, every product).
// The place variable of a product (BRAIN, INDEXER ...) is written from its place on export, so the conditions read it from there; the defaults of the
// description apply to what is not set.
func (c *Core) values(e *vmodel.Environment) func(string) string {
	m := map[string]string{}
	for _, x := range e.GeneralValues() {
		m[x.Key] = x.Value
	}
	for _, s := range e.Sites {
		for _, x := range s.Vars {
			m[x.Key] = x.Value
		}
	}
	for _, p := range e.Products {
		for _, x := range p.Vars {
			m[x.Key] = x.Value
		}
		if c.d != nil {
			if dp := c.d.Product(p.Name); dp != nil && dp.PlaceVariable != "" {
				place := p.Place
				if !p.Enabled {
					place = "none"
				}
				m[dp.PlaceVariable] = place
			}
		}
	}
	get := func(k string) string { return m[k] }
	if c.d != nil {
		return c.d.Getter(get)
	}
	return get
}

func (c *Core) envView(e *vmodel.Environment) map[string]any {
	vals := c.values(e)
	var gdesc []project.Variable
	if c.d != nil {
		gdesc = c.d.General.Variables
	}
	general := c.vars(e.GeneralValues(), gdesc, vals)
	imported := map[string]bool{}
	for _, x := range e.Imports {
		imported[x.Key] = true
	}
	own := map[string]bool{}
	for _, x := range e.General {
		own[x.Key] = true
	}
	for _, g := range general {
		k, _ := g[jKey].(string)
		if imported[k] {
			g["imported"] = true
			g["overridden"] = own[k]
		}
	}
	sites := []map[string]any{}
	for _, s := range e.Sites {
		var sdesc []project.Variable
		if c.d != nil {
			sdesc = c.d.SiteKinds[s.Kind].Variables
		}
		users := []string{}
		for _, p := range e.Products {
			if p.Site == s {
				users = append(users, p.Name)
			}
		}
		sk, _ := kinds.SiteKind(s.Kind)
		sites = append(sites, map[string]any{"uuid": s.UUID, jName: s.Name, jKind: s.Kind, "kind_title": sk.Title, "needs_connection": sk.Connection, "state_kind": sk.State,
			"connection": connUUID(s.Connection), jState: connUUID(s.State), "state_backend": s.StateBackend, "vars": c.vars(s.Vars, sdesc, vals), "files": len(s.Files), "users": users})
	}
	products := []map[string]any{}
	for _, p := range e.Products {
		products = append(products, c.productView(e, p, vals))
	}
	avail := []string{}
	for _, s := range c.m.Shared {
		if !imported[s.Key] {
			avail = append(avail, s.Key)
		}
	}
	missing := 0
	for _, p := range products {
		missing += len(p["missing"].([]map[string]any))
	}
	return map[string]any{jName: e.Name, jTitle: e.Title, "general": general, "imports": keysOf(e.Imports), "shared_available": avail, "sites": sites, "products": products,
		"files": len(e.Files), "missing": missing}
}

func keysOf(vs []*vmodel.Var) []string {
	out := []string{}
	for _, x := range vs {
		out = append(out, x.Key)
	}
	return out
}

func (c *Core) productView(e *vmodel.Environment, p *vmodel.Product, vals func(string) string) map[string]any {
	var dp *project.Product
	if c.d != nil {
		dp = c.d.Product(p.Name)
	}
	var desc []project.Variable
	var title, help project.Text
	needs := []map[string]any{}
	if dp != nil {
		desc, title, help = dp.Variables, dp.Title, dp.Help
		for _, u := range dp.Connections {
			needs = append(needs, map[string]any{jKind: u.Kind, "role": u.Role, "optional": u.Optional, jName: u.Name})
		}
	}
	siteKind := ""
	if p.Site != nil {
		siteKind = p.Site.Kind
	}
	out := map[string]any{"uuid": p.UUID, jName: p.Name, jTitle: text(title), "help": text(help), "enabled": p.Enabled, "place": p.Place, "site": "", "connections": []string{},
		"vars": c.vars(p.Vars, desc, vals), "needs": needs, "site_kind": siteKind}
	if p.Site != nil {
		out["site"] = p.Site.UUID
	}
	cs := []string{}
	for _, x := range p.Connections {
		cs = append(cs, x.UUID)
	}
	out["connections"] = cs
	// the subgroup of the kind of its site only (the others are kept, never shown)
	if siteKind != "" {
		var sdesc []project.Variable
		if dp != nil {
			sdesc = dp.OnSiteKind[siteKind]
		}
		if len(sdesc) > 0 || len(p.Sub[siteKind]) > 0 {
			out["sub"] = map[string]any{jKind: siteKind, "vars": c.vars(p.Sub[siteKind], sdesc, vals)}
		}
	}
	out["missing"] = c.missing(e, p, out, vals)
	return out
}

// missing is what a deployment of the product lacks: required variables of the product, of its subgroup, of General and of its site that are
// empty while their condition holds, a site, and a connection the product needs (not optional) that is not chosen or lacks a required field.
func (c *Core) missing(e *vmodel.Environment, p *vmodel.Product, view map[string]any, vals func(string) string) []map[string]any {
	out := []map[string]any{}
	if !p.Enabled || c.d == nil {
		return out
	}
	scan := func(where string, rows []map[string]any) {
		for _, r := range rows {
			if req, _ := r["required"].(bool); req && r[jState] == "empty" && r["active"] != false {
				out = append(out, map[string]any{jWhere: where, jKey: r[jKey], "label": r["label"]})
			}
		}
	}
	scan("product", view["vars"].([]map[string]any))
	if sub, ok := view["sub"].(map[string]any); ok {
		scan("product", sub["vars"].([]map[string]any))
	}
	scan("general", c.vars(e.GeneralValues(), c.d.General.Variables, vals))
	if p.Site == nil {
		out = append(out, map[string]any{jWhere: "site", jKey: ""})
	} else {
		scan("site", c.vars(p.Site.Vars, c.d.SiteKinds[p.Site.Kind].Variables, vals))
		if sk, _ := kinds.SiteKind(p.Site.Kind); sk.Connection != "" && p.Site.Connection == nil {
			out = append(out, map[string]any{jWhere: "site_connection", jKey: sk.Connection})
		}
	}
	if dp := c.d.Product(p.Name); dp != nil {
		for _, u := range dp.Connections {
			var have *vmodel.Connection
			for _, x := range p.Connections {
				if x.Kind == u.Kind {
					have = x
				}
			}
			if have == nil {
				if !u.Optional {
					out = append(out, map[string]any{jWhere: "connection", jKey: u.Kind})
				}
				continue
			}
			for _, v := range u.Variables {
				if f := have.Field(v.Field); v.Required && (f == nil || f.Value == "") {
					out = append(out, map[string]any{jWhere: "connection_field", jKey: v.Name, "label": text(v.Label), "connection": have.Name})
				}
			}
		}
	}
	return out
}

// Nav is the whole model as the page draws it (a vault is small).
func (c *Core) Nav() map[string]any {
	ck := []map[string]any{}
	for _, k := range kinds.ConnectionKinds() {
		fs := []map[string]any{}
		for _, f := range k.Fields {
			fs = append(fs, map[string]any{jName: f.Name, jTitle: f.Title, "secret": f.Secret})
		}
		ck = append(ck, map[string]any{"id": k.ID, jTitle: k.Title, "fields": fs, "free": k.Free})
	}
	sk := []map[string]any{}
	for _, s := range kinds.SiteKinds() {
		supported := c.d == nil
		if c.d != nil {
			_, supported = c.d.SiteKinds[s.ID]
		}
		sk = append(sk, map[string]any{"id": s.ID, jTitle: s.Title, "connection": s.Connection, jState: s.State, "supported": supported})
	}
	var shared []project.Variable
	sharedRows := c.vars(c.m.Shared, shared, nil)
	for _, r := range sharedRows {
		k, _ := r[jKey].(string)
		users := []string{}
		for _, e := range c.m.Envs {
			for _, x := range e.Imports {
				if x.Key == k {
					users = append(users, e.Name)
				}
			}
		}
		r["users"] = users
		if c.d != nil {
			c.d.Walk(func(h project.Home) {
				if h.Kind == project.HomeGeneral && h.Var.Name == k && r["label"] == nil {
					r["label"], r["help"] = text(h.Var.Label), text(h.Var.Help)
				}
			})
		}
	}
	conns := []map[string]any{}
	for _, x := range c.m.Connections {
		conns = append(conns, c.connView(x))
	}
	other := []map[string]any{}
	for _, o := range c.m.Other {
		state := "set"
		if o.Value == "" && len(o.Data) == 0 {
			state = "empty"
		}
		other = append(other, map[string]any{"uuid": o.UUID, jTitle: o.Title, "notes": o.Notes, jState: state, "file": len(o.Data) > 0 || o.Extra != ""})
	}
	envs := []map[string]any{}
	for _, e := range c.m.Envs {
		envs = append(envs, c.envView(e))
	}
	products := []map[string]any{}
	if c.d != nil {
		for _, p := range c.d.Products {
			products = append(products, map[string]any{jName: p.Name, jTitle: text(p.Title)})
		}
	}
	desc := map[string]any{"found": c.d != nil, "path": c.DescPath, "error": c.DescErr, "can_remember": c.Remember != nil, "no_project": c.NoProject}
	if c.d != nil {
		desc[jName] = c.d.Name
	}
	return map[string]any{"model": true, "format": c.m.Format, "read_only": c.m.ReadOnly, "problems": c.m.Problems, "description": desc, "connection_kinds": ck, "site_kinds": sk,
		"products": products, "shared": sharedRows, "connections": conns, "other": other, "envs": envs, "sections": []any{}}
}

// Read answers the read ops of the model ("nav").
func (c *Core) Read(op string, _ map[string]any) (any, error) {
	if op == "nav" {
		return c.Nav(), nil
	}
	return nil, &desktop.Error{Status: 404, Code: "not_found", Params: map[string]any{}}
}

// Reveal returns one secret value: section "m", name the scope (shared, conn/<uuid>, other/<uuid>, env/<e>/general, env/<e>/site/<s>,
// env/<e>/product/<p>[/<kind>]), key the variable or the field.
func (c *Core) Reveal(section, name, _, key string) (string, error) {
	if section != "m" {
		return "", bad("bad_request")
	}
	switch {
	case strings.HasPrefix(name, "conn/"):
		x := c.connByUUID(strings.TrimPrefix(name, "conn/"))
		if x == nil || x.Field(key) == nil {
			return "", refuse("not_found", nil)
		}
		return x.Field(key).Value, nil
	case strings.HasPrefix(name, "other/"):
		for _, o := range c.m.Other {
			if o.UUID == strings.TrimPrefix(name, "other/") {
				return o.Value, nil
			}
		}
		return "", refuse("not_found", nil)
	}
	list, err := c.scope(name)
	if err != nil {
		return "", err
	}
	for _, x := range list.get() {
		if x.Key == key {
			if x.Vis == vmodel.VisSealed {
				return "", refuse("sealed", nil)
			}
			return x.Value, nil
		}
	}
	if strings.HasSuffix(name, "/general") {
		e := c.m.Env(strings.Split(name, "/")[1])
		for _, x := range e.Imports {
			if x.Key == key && x.Vis != vmodel.VisSealed {
				return x.Value, nil
			}
		}
	}
	return "", refuse("not_found", nil)
}

func (c *Core) connByUUID(u string) *vmodel.Connection {
	for _, x := range c.m.Connections {
		if x.UUID == u && u != "" {
			return x
		}
	}
	return nil
}

// varList is the list of variables of a scope, read and written back (a product's subgroup is a map value).
type varList struct {
	get func() []*vmodel.Var
	set func([]*vmodel.Var)
}

// scope is the list of variables a scope name stands for.
func (c *Core) scope(name string) (*varList, error) {
	if name == "shared" {
		return &varList{func() []*vmodel.Var { return c.m.Shared }, func(l []*vmodel.Var) { c.m.Shared = l }}, nil
	}
	p := strings.Split(name, "/")
	if len(p) < 3 || p[0] != jEnv {
		return nil, bad("bad_scope")
	}
	e := c.m.Env(p[1])
	if e == nil {
		return nil, refuse("no_env", map[string]any{jEnv: p[1]})
	}
	switch {
	case p[2] == "general" && len(p) == 3:
		return &varList{func() []*vmodel.Var { return e.General }, func(l []*vmodel.Var) { e.General = l }}, nil
	case p[2] == "site" && len(p) == 4:
		if s := e.Site(p[3]); s != nil {
			return &varList{func() []*vmodel.Var { return s.Vars }, func(l []*vmodel.Var) { s.Vars = l }}, nil
		}
	case p[2] == "product" && len(p) == 4:
		if pr := e.Product(p[3]); pr != nil {
			return &varList{func() []*vmodel.Var { return pr.Vars }, func(l []*vmodel.Var) { pr.Vars = l }}, nil
		}
	case p[2] == "product" && len(p) == 5:
		if pr := e.Product(p[3]); pr != nil {
			if _, ok := kinds.SiteKind(p[4]); !ok {
				return nil, bad("bad_scope")
			}
			k := p[4]
			return &varList{func() []*vmodel.Var { return pr.Sub[k] }, func(l []*vmodel.Var) { pr.Sub[k] = l }}, nil
		}
	}
	return nil, refuse("not_found", nil)
}

func contains(list []string, x string) bool {
	for _, l := range list {
		if l == x {
			return true
		}
	}
	return false
}

// visibility of a new variable: what the description says, else the name rule.
func (c *Core) defaultVis(key string) string {
	if c.d != nil {
		secret, found := false, false
		c.d.Walk(func(h project.Home) {
			if h.Var.Name == key {
				found = true
				secret = secret || h.Var.Secret
			}
		})
		if found {
			if secret {
				return vmodel.VisSecret
			}
			return vmodel.VisPlain
		}
	}
	if render.LooksSecret(key) {
		return vmodel.VisSecret
	}
	return vmodel.VisPlain
}
