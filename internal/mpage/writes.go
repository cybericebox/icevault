package mpage

import (
	"strings"

	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/kinds"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
)

// The write ops of the window on the vault model (the App refuses them in view mode):
//
//	m-var        {scope, key, value?, new_key?, visibility?, description?, delete?}    a variable of Shared, General, a site, a product, a subgroup
//	m-import     {env, keys}                                                        the shared variables an environment imports
//	m-connection {action: create|update|delete, uuid?, name, kind, description?, confirm?}
//	m-field      {uuid, field, value?, secret?, delete?}                            a field of a connection
//	m-site       {env, action: create|update|delete, name, new_name?, kind?, connection?, state?, confirm?}
//	m-product    {env, action: create|update|delete, name, new_name?, enabled?, site?, connections?, confirm?}
//	m-env        {action: create|copy|update|delete, name, from?, new_name?, title?, confirm?}
//	m-other      {action: create|update|delete, uuid?, title, value?, notes?}
//	m-env-fill   {env}                                                              every owner variable the description says the environment needs, empty
//	m-project    {path}                                                             remember the project description file the window was given
//
// A change that something uses (renaming or removing a used connection or site, removing an environment, changing the connection of a site that
// products run on) answers 409 "confirm_*" with what uses it, and goes on only when the page sends confirm: true after the owner said yes.

func str(a map[string]any, k string) string { s, _ := a[k].(string); return s }

func flag(a map[string]any, k string) bool { b, _ := a[k].(bool); return b }

func has(a map[string]any, k string) bool { _, ok := a[k]; return ok }

func strs(a map[string]any, k string) []string {
	switch v := a[k].(type) {
	case []string:
		return v
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Write runs one write op and saves.
func (c *Core) Write(op string, a map[string]any) (any, error) {
	if c.m.ReadOnly {
		return nil, refuse("newer_format", nil)
	}
	var err error
	switch op {
	case "m-var":
		err = c.writeVar(a)
	case "m-import":
		err = c.writeImports(a)
	case "m-connection":
		err = c.writeConnection(a)
	case "m-field":
		err = c.writeField(a)
	case "m-site":
		err = c.writeSite(a)
	case "m-product":
		err = c.writeProduct(a)
	case "m-env":
		err = c.writeEnv(a)
	case "m-other":
		err = c.writeOther(a)
	case "m-env-fill":
		var rep *vmodel.FillReport
		if rep, err = c.fillEnv(str(a, jEnv)); err == nil {
			if err = c.commit(); err == nil {
				return map[string]any{"added": len(rep.Added), "made": len(rep.Made)}, nil
			}
		}
	case "m-project":
		if c.Remember == nil {
			return nil, refuse("not_found", nil)
		}
		if err := c.Remember(str(a, "path")); err != nil {
			return nil, refuse("project_not_saved", nil)
		}
		return map[string]any{"ok": true, "reload": true}, nil
	default:
		return nil, &desktop.Error{Status: 404, Code: "not_found", Params: map[string]any{}}
	}
	if err == nil {
		err = c.commit()
	}
	if err != nil {
		if m, lerr := vmodel.Load(c.v); lerr == nil {
			c.m = m // a refusal changes nothing: the model is read again from the vault
		}
		return nil, err
	}
	return nil, nil
}

func (c *Core) commit() error {
	if errs := c.m.Check(); len(errs) > 0 {
		return refuse("model_invalid", map[string]any{"why": strings.Join(errs, "; ")})
	}
	if err := vmodel.Sync(c.v, c.m); err != nil {
		return err
	}
	return c.v.Save()
}

func validKey(k string) bool { return vmodel.KeyRE.MatchString(k) }

func (c *Core) writeVar(a map[string]any) error {
	list, err := c.scope(str(a, "scope"))
	if err != nil {
		return err
	}
	key := str(a, jKey)
	vs := list.get()
	var x *vmodel.Var
	for _, v := range vs {
		if v.Key == key {
			x = v
		}
	}
	if flag(a, actDelete) {
		if x == nil {
			return refuse("not_found", nil)
		}
		if str(a, "scope") == "shared" {
			for _, e := range c.m.Envs {
				for _, s := range e.Imports {
					if s == x && !flag(a, "confirm") {
						return refuse("confirm_shared_used", map[string]any{jList: c.importers(x)})
					}
				}
			}
			for _, e := range c.m.Envs {
				var keep []*vmodel.Var
				for _, s := range e.Imports {
					if s != x {
						keep = append(keep, s)
					}
				}
				e.Imports = keep
			}
		}
		var keep []*vmodel.Var
		for _, v := range vs {
			if v != x {
				keep = append(keep, v)
			}
		}
		list.set(keep)
		return nil
	}
	if x == nil {
		if !validKey(key) {
			return refuse("bad_key", map[string]any{jKey: key})
		}
		x = &vmodel.Var{Key: key, Managed: vmodel.ManagedOwner, Vis: c.defaultVis(key)}
		list.set(append(vs, x))
	} else if x.Managed == vmodel.ManagedSystem && has(a, "value") {
		return refuse("system_managed", map[string]any{jKey: key})
	}
	if nk := str(a, "new_key"); nk != "" && nk != key {
		if !validKey(nk) {
			return refuse("bad_key", map[string]any{jKey: nk})
		}
		for _, v := range list.get() {
			if v.Key == nk {
				return refuse("key_exists", map[string]any{jKey: nk})
			}
		}
		x.Key = nk
	}
	if has(a, "value") {
		v := str(a, "value")
		if strings.ContainsAny(v, "\n\r") {
			return refuse("line_break", nil)
		}
		if c.d != nil {
			if rule := c.d.ValueProblem(x.Key, v); rule != "" {
				return refuse("bad_value", map[string]any{jKey: x.Key, "rule": rule})
			}
		}
		x.Value = v
	}
	if vis := str(a, "visibility"); vis != "" {
		if vis != vmodel.VisPlain && vis != vmodel.VisSecret && vis != vmodel.VisSealed {
			return bad("bad_request")
		}
		if x.Vis == vmodel.VisSealed && vis != vmodel.VisSealed {
			return refuse("no_unseal", nil)
		}
		x.Vis = vis
	}
	if has(a, "description") {
		x.Description = str(a, "description")
	}
	return nil
}

func (c *Core) importers(x *vmodel.Var) []string {
	var out []string
	for _, e := range c.m.Envs {
		for _, s := range e.Imports {
			if s == x {
				out = append(out, e.Name)
			}
		}
	}
	return out
}

func (c *Core) env(a map[string]any) (*vmodel.Environment, error) {
	e := c.m.Env(str(a, jEnv))
	if e == nil {
		return nil, refuse("no_env", map[string]any{jEnv: str(a, jEnv)})
	}
	return e, nil
}

func (c *Core) writeImports(a map[string]any) error {
	e, err := c.env(a)
	if err != nil {
		return err
	}
	var imp []*vmodel.Var
	for _, k := range strs(a, "keys") {
		s := c.m.SharedVar(k)
		if s == nil {
			return refuse("not_found", map[string]any{jKey: k})
		}
		imp = append(imp, s)
	}
	e.Imports = imp
	return nil
}

func userList(us []map[string]string) []string {
	var out []string
	for _, u := range us {
		out = append(out, u[jEnv]+" / "+u[jKind]+" "+u[jName])
	}
	return out
}

func (c *Core) writeConnection(a map[string]any) error {
	name := strings.TrimSpace(str(a, jName))
	switch str(a, "action") {
	case actCreate:
		if _, ok := kinds.ConnectionKind(str(a, jKind)); !ok {
			return refuse("bad_kind", nil)
		}
		if !vmodel.ValidConnectionName(name) {
			return refuse("bad_name", nil)
		}
		if c.m.Connection(name) != nil {
			return refuse("name_exists", map[string]any{jName: name})
		}
		c.m.Connections = append(c.m.Connections, &vmodel.Connection{Name: name, Kind: str(a, jKind), Description: str(a, "description")})
		return nil
	case actUpdate:
		x := c.connByUUID(str(a, "uuid"))
		if x == nil {
			return refuse("not_found", nil)
		}
		if name != "" && name != x.Name {
			if !vmodel.ValidConnectionName(name) {
				return refuse("bad_name", nil)
			}
			if c.m.Connection(name) != nil {
				return refuse("name_exists", map[string]any{jName: name})
			}
			if us := c.usersOf(x); len(us) > 0 && !flag(a, "confirm") {
				return refuse("confirm_rename_used", map[string]any{jList: userList(us), jName: x.Name})
			}
			x.Name = name
		}
		if has(a, "description") {
			x.Description = str(a, "description")
		}
		return nil
	case actDelete:
		x := c.connByUUID(str(a, "uuid"))
		if x == nil {
			return refuse("not_found", nil)
		}
		if us := c.usersOf(x); len(us) > 0 && !flag(a, "confirm") {
			return refuse("confirm_delete_used", map[string]any{jList: userList(us), jName: x.Name})
		}
		for _, e := range c.m.Envs {
			for _, s := range e.Sites {
				if s.Connection == x {
					s.Connection = nil
				}
				if s.State == x {
					s.State = nil
				}
			}
			for _, p := range e.Products {
				var keep []*vmodel.Connection
				for _, pc := range p.Connections {
					if pc != x {
						keep = append(keep, pc)
					}
				}
				p.Connections = keep
			}
		}
		var keep []*vmodel.Connection
		for _, y := range c.m.Connections {
			if y != x {
				keep = append(keep, y)
			}
		}
		c.m.Connections = keep
		return nil
	}
	return bad("bad_request")
}

func (c *Core) writeField(a map[string]any) error {
	x := c.connByUUID(str(a, "uuid"))
	if x == nil {
		return refuse("not_found", nil)
	}
	name := str(a, "field")
	if !kinds.FieldRE.MatchString(name) {
		return refuse("bad_key", map[string]any{jKey: name})
	}
	if flag(a, actDelete) {
		var keep []*vmodel.Field
		for _, f := range x.Fields {
			if f.Name != name {
				keep = append(keep, f)
			}
		}
		x.Fields = keep
		return nil
	}
	k, _ := kinds.ConnectionKind(x.Kind)
	secret := flag(a, "secret")
	if kf := k.Field(name); kf != nil {
		secret = secret || kf.Secret
	}
	v := str(a, "value")
	if strings.ContainsAny(v, "\n\r") {
		return refuse("line_break", nil)
	}
	if f := x.Field(name); f != nil {
		if has(a, "value") {
			f.Value = v
		}
		f.Secret = f.Secret || secret
	} else {
		x.Set(name, v, secret)
	}
	return nil
}

func (c *Core) writeSite(a map[string]any) error {
	e, err := c.env(a)
	if err != nil {
		return err
	}
	name := str(a, jName)
	switch str(a, "action") {
	case actCreate:
		if !vmodel.ThingNameRE.MatchString(name) {
			return refuse("bad_name", nil)
		}
		if e.Site(name) != nil {
			return refuse("name_exists", map[string]any{jName: name})
		}
		if _, ok := kinds.SiteKind(str(a, jKind)); !ok {
			return refuse("bad_kind", nil)
		}
		s := &vmodel.Site{Name: name, Kind: str(a, jKind)}
		if err := c.siteConnections(s, a); err != nil {
			return err
		}
		e.Sites = append(e.Sites, s)
		for _, p := range e.Products {
			if p.Site == nil {
				p.Site = s
			}
		}
		return nil
	case actUpdate:
		s := e.Site(name)
		if s == nil {
			return refuse("not_found", nil)
		}
		var users []string
		for _, p := range e.Products {
			if p.Site == s {
				users = append(users, p.Name)
			}
		}
		if nn := str(a, "new_name"); nn != "" && nn != name {
			if !vmodel.ThingNameRE.MatchString(nn) {
				return refuse("bad_name", nil)
			}
			if e.Site(nn) != nil {
				return refuse("name_exists", map[string]any{jName: nn})
			}
			if len(users) > 0 && !flag(a, "confirm") {
				return refuse("confirm_rename_site", map[string]any{jList: users, jName: name})
			}
			s.Name = nn
		}
		if k := str(a, jKind); k != "" && k != s.Kind {
			if _, ok := kinds.SiteKind(k); !ok {
				return refuse("bad_kind", nil)
			}
			if len(users) > 0 && !flag(a, "confirm") {
				return refuse("confirm_site_kind", map[string]any{jList: users, jName: s.Name})
			}
			s.Kind, s.Connection, s.State = k, nil, nil
		}
		before := s.Connection
		if err := c.siteConnections(s, a); err != nil {
			return err
		}
		if before != nil && s.Connection != before && len(users) > 0 && !flag(a, "confirm") {
			s.Connection = before
			return refuse("confirm_site_connection", map[string]any{jList: users, jName: s.Name})
		}
		return nil
	case actDelete:
		s := e.Site(name)
		if s == nil {
			return refuse("not_found", nil)
		}
		var users []string
		for _, p := range e.Products {
			if p.Site == s {
				users = append(users, p.Name)
			}
		}
		if len(users) > 0 && !flag(a, "confirm") {
			return refuse("confirm_delete_site", map[string]any{jList: users, jName: name})
		}
		for _, p := range e.Products {
			if p.Site == s {
				p.Site = nil
			}
		}
		var keep []*vmodel.Site
		for _, x := range e.Sites {
			if x != s {
				keep = append(keep, x)
			}
		}
		e.Sites = keep
		return nil
	}
	return bad("bad_request")
}

// siteConnections sets the connection and the state connection of a site from the args (uuid, "" for none) when they are given.
func (c *Core) siteConnections(s *vmodel.Site, a map[string]any) error {
	sk, _ := kinds.SiteKind(s.Kind)
	if has(a, "connection") {
		u := str(a, "connection")
		if u == "" {
			s.Connection = nil
		} else if x := c.connByUUID(u); x == nil {
			return refuse("not_found", nil)
		} else if x.Kind != sk.Connection {
			return refuse("wrong_connection_kind", map[string]any{jKind: sk.Connection})
		} else {
			s.Connection = x
		}
	}
	if has(a, jState) {
		u := str(a, jState)
		if u == "" {
			s.State = nil
		} else if x := c.connByUUID(u); x == nil {
			return refuse("not_found", nil)
		} else if x.Kind != kinds.HCP || !sk.State {
			return refuse("wrong_connection_kind", map[string]any{jKind: kinds.HCP})
		} else {
			s.State = x
		}
	}
	return nil
}

func (c *Core) writeProduct(a map[string]any) error {
	e, err := c.env(a)
	if err != nil {
		return err
	}
	name := str(a, jName)
	p := e.Product(name)
	switch str(a, "action") {
	case actCreate:
		if !vmodel.ThingNameRE.MatchString(name) {
			return refuse("bad_name", nil)
		}
		if p != nil {
			return refuse("name_exists", map[string]any{jName: name})
		}
		p = &vmodel.Product{Name: name, Enabled: true, Sub: map[string][]*vmodel.Var{}}
		if len(e.Sites) == 1 {
			p.Site = e.Sites[0]
		}
		e.Products = append(e.Products, p)
	case actUpdate:
		if p == nil {
			return refuse("not_found", nil)
		}
		if nn := str(a, "new_name"); nn != "" && nn != name {
			if !vmodel.ThingNameRE.MatchString(nn) {
				return refuse("bad_name", nil)
			}
			if e.Product(nn) != nil {
				return refuse("name_exists", map[string]any{jName: nn})
			}
			p.Name = nn
		}
	case actDelete:
		if p == nil {
			return refuse("not_found", nil)
		}
		if !flag(a, "confirm") {
			return refuse("confirm_delete_product", map[string]any{jName: name})
		}
		var keep []*vmodel.Product
		for _, x := range e.Products {
			if x != p {
				keep = append(keep, x)
			}
		}
		e.Products = keep
		return nil
	default:
		return bad("bad_request")
	}
	if has(a, "enabled") {
		p.Enabled = flag(a, "enabled")
		if !p.Enabled {
			p.Place = "none"
		} else if p.Place == "none" {
			p.Place = ""
		}
	}
	if has(a, jSite) {
		u := str(a, jSite)
		p.Site = nil
		for _, s := range e.Sites {
			if s.UUID == u && u != "" {
				p.Site = s
			}
		}
		if u != "" && p.Site == nil {
			return refuse("not_found", nil)
		}
	}
	if has(a, "connections") {
		var cs []*vmodel.Connection
		for _, u := range strs(a, "connections") {
			x := c.connByUUID(u)
			if x == nil {
				return refuse("not_found", nil)
			}
			cs = append(cs, x)
		}
		p.Connections = cs
	}
	return nil
}

// copyVars copies variables (new entries: no UUID).
func copyVars(vs []*vmodel.Var) []*vmodel.Var {
	var out []*vmodel.Var
	for _, x := range vs {
		y := *x
		y.UUID = ""
		y.Labels = append([]string(nil), x.Labels...)
		out = append(out, &y)
	}
	return out
}

// copyEnv is a new environment made from another: the same variables, sites, products, imports and connections (connections and shared values
// are on the vault level: the copy uses the same ones); files and generated values of a site are not copied (they belong to the running site).
func copyEnv(from *vmodel.Environment, name string) *vmodel.Environment {
	e := &vmodel.Environment{Name: name, Title: "", General: copyVars(from.General), Imports: append([]*vmodel.Var(nil), from.Imports...), Layouts: map[string][]byte{}}
	for k, v := range from.Layouts {
		e.Layouts[k] = append([]byte(nil), v...)
	}
	if from.Derived != nil {
		e.Derived = append([]string{}, from.Derived...)
	}
	sites := map[*vmodel.Site]*vmodel.Site{}
	for _, s := range from.Sites {
		n := &vmodel.Site{Name: s.Name, Kind: s.Kind, Connection: s.Connection, State: s.State, StateBackend: s.StateBackend, Vars: copyVars(s.Vars)}
		sites[s] = n
		e.Sites = append(e.Sites, n)
	}
	for _, p := range from.Products {
		n := &vmodel.Product{Name: p.Name, Enabled: p.Enabled, Place: p.Place, Site: sites[p.Site], Connections: append([]*vmodel.Connection(nil), p.Connections...), Vars: copyVars(p.Vars),
			Sub: map[string][]*vmodel.Var{}}
		for k, vs := range p.Sub {
			n.Sub[k] = copyVars(vs)
		}
		e.Products = append(e.Products, n)
	}
	return e
}

func (c *Core) writeEnv(a map[string]any) error {
	name := str(a, jName)
	switch str(a, "action") {
	case actCreate, "copy":
		if !vmodel.EnvNameRE.MatchString(name) {
			return refuse("bad_env_name", nil)
		}
		if c.m.Env(name) != nil {
			return refuse("name_exists", map[string]any{jName: name})
		}
		var e *vmodel.Environment
		if str(a, "action") == "copy" {
			from := c.m.Env(str(a, "from"))
			if from == nil {
				return refuse("no_env", map[string]any{jEnv: str(a, "from")})
			}
			e = copyEnv(from, name)
		} else {
			e = &vmodel.Environment{Name: name, Layouts: map[string][]byte{}}
		}
		e.Title = str(a, jTitle)
		c.m.Envs = append(c.m.Envs, e)
		return nil
	case actUpdate:
		e := c.m.Env(name)
		if e == nil {
			return refuse("no_env", map[string]any{jEnv: name})
		}
		if nn := str(a, "new_name"); nn != "" && nn != name {
			if !vmodel.EnvNameRE.MatchString(nn) {
				return refuse("bad_env_name", nil)
			}
			if c.m.Env(nn) != nil {
				return refuse("name_exists", map[string]any{jName: nn})
			}
			e.Name = nn
		}
		if has(a, jTitle) {
			e.Title = str(a, jTitle)
		}
		return nil
	case actDelete:
		e := c.m.Env(name)
		if e == nil {
			return refuse("no_env", map[string]any{jEnv: name})
		}
		if !flag(a, "confirm") {
			return refuse("confirm_delete_env", map[string]any{jName: name})
		}
		var keep []*vmodel.Environment
		for _, x := range c.m.Envs {
			if x != e {
				keep = append(keep, x)
			}
		}
		c.m.Envs = keep
		return nil
	}
	return bad("bad_request")
}

func (c *Core) writeOther(a map[string]any) error {
	title := strings.TrimSpace(str(a, jTitle))
	find := func() *vmodel.Other {
		for _, o := range c.m.Other {
			if o.UUID == str(a, "uuid") && o.UUID != "" {
				return o
			}
		}
		return nil
	}
	okTitle := func(t string) bool { return t != "" && len(t) <= 120 && !strings.ContainsAny(t, "/\n\r") }
	switch str(a, "action") {
	case actCreate:
		if !okTitle(title) {
			return refuse("bad_name", nil)
		}
		for _, o := range c.m.Other {
			if o.Title == title {
				return refuse("name_exists", map[string]any{jName: title})
			}
		}
		c.m.Other = append(c.m.Other, &vmodel.Other{Title: title, Value: str(a, "value"), Notes: str(a, "notes")})
		return nil
	case actUpdate:
		o := find()
		if o == nil {
			return refuse("not_found", nil)
		}
		if title != "" && title != o.Title {
			if !okTitle(title) {
				return refuse("bad_name", nil)
			}
			o.Title = title
		}
		if has(a, "value") {
			o.Value = str(a, "value")
		}
		if has(a, "notes") {
			o.Notes = str(a, "notes")
		}
		return nil
	case actDelete:
		o := find()
		if o == nil {
			return refuse("not_found", nil)
		}
		var keep []*vmodel.Other
		for _, x := range c.m.Other {
			if x != o {
				keep = append(keep, x)
			}
		}
		c.m.Other = keep
		return nil
	}
	return bad("bad_request")
}

// fillEnv is m-env-fill: vmodel.FillMissing with the committed settings of the environment in the checkout.
func (c *Core) fillEnv(env string) (*vmodel.FillReport, error) {
	if c.d == nil {
		return nil, refuse("no_description", nil)
	}
	if c.m.Env(env) == nil {
		return nil, refuse("no_env", map[string]any{jEnv: env})
	}
	committed, _ := render.ReadSettings(c.d.CommittedFile(env))
	rep, err := vmodel.FillMissing(c.m, c.d, env, committed)
	if err != nil {
		return nil, refuse("model_invalid", map[string]any{"why": err.Error()})
	}
	return rep, nil
}
