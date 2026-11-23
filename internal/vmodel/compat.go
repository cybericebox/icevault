package vmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
)

// The compat projection lays the model of an environment out the way the commands of the layout before the model read a vault: one item
// environments/<env> of a model.Snapshot whose entries are the variables of the batches of the environment under the names the project
// description gives them (the mapping of batches to the project's files), plus the derived variables, the files and the stored layouts. The
// render of the settings files (internal/render) then writes the files the project expects, byte for byte as they were imported, so export,
// export-app, view, status and settings read the model through it.

// Order ranks a variable for the order of the settings files: the position of the key in the files of the project's manifest (known = false
// for a key the manifest does not have, which keeps the order of the model after the known ones).
type Order func(key string) (rank int, known bool)

// CompatSnapshot is the projection of every environment of the vault. An environment the projection cannot lay out (two sites) is left out and
// named in Skipped with the reason. Targets says what each entry path of the projection is in the model, so a writer of the old layout can
// change the model (migrate.Writer).
type CompatSnapshot struct {
	Snap    *model.Snapshot
	Skipped map[string]string
	Targets map[string]*Target
}

// Target is what an entry of the projection stands for.
type Target struct {
	Env   *Environment
	Var   *Var        // a variable (of General, a site, a product, Shared)
	Owner *[]*Var     // the list Var lives in
	Conn  *Connection // a field of a connection
	Field string
	// Derived is the name of a derived or place variable (the provider word of the site, a product's place, ...); Site or Product is what it
	// comes from.
	Derived string
	Site    *Site
	Product *Product
	Shared  bool // Var is a shared variable imported into the environment
}

// CompatOptions tune the projection: Order ranks keys as the manifest does (nil: the order of the model), Group names the group of the layout
// before the model a variable of a file sat in (nil: one group per part of the model).
type CompatOptions struct {
	Order Order
	Group func(file, key string) string
}

type compatEntry struct {
	e    *model.Entry
	seq  int
	rank int
	ok   bool
}

func notesOf(managed, vis string, labels []string, desc string) string {
	n := "managed-by=" + orDefault(managed, ManagedOwner) + "\nvisibility=" + orDefault(vis, VisSecret)
	if len(labels) > 0 {
		n += "\nlabels=" + strings.Join(labels, ",")
	}
	if desc != "" {
		n += "\n" + desc
	}
	return n
}

// Compat projects the vault. d is the project description (the names of connection fields, the derived variables, the files of keys the manifest
// does not know); order is the manifest order (nil: the order of the model).
func Compat(m *Vault, d *project.Description, order Order) *CompatSnapshot {
	return CompatWith(m, d, CompatOptions{Order: order})
}

// CompatWith is Compat with every option.
func CompatWith(m *Vault, d *project.Description, o CompatOptions) *CompatSnapshot {
	out := &CompatSnapshot{Snap: model.NewSnapshot(), Skipped: map[string]string{}, Targets: map[string]*Target{}}
	for _, e := range m.Envs {
		if len(e.Sites) > 1 {
			out.Skipped[e.Name] = fmt.Sprintf("'%s' has %d sites: the files of the project are written for one site; export it per run with --batches", e.Name, len(e.Sites))
			continue
		}
		out.Snap.Put(compatEnv(e, d, o, out.Targets))
	}
	servedItems(m, d, out)
	for _, o := range m.Other {
		if o.Extra != "" {
			mode := o.Mode
			if mode == 0 {
				mode = 0o600
			}
			out.Snap.Extras[o.Extra] = &model.FileEntry{Data: append([]byte(nil), o.Data...), Mode: mode, Sha: model.SHA256(o.Data)}
		}
	}
	return out
}

// fileOf is the file the description gives a key in a scope ("" when it does not know the key there).
func fileOf(d *project.Description, match func(project.Home) bool, key string) string {
	f := ""
	d.Walk(func(h project.Home) {
		if f == "" && h.Var.Name == key && match(h) {
			f = h.File
		}
	})
	return f
}

// servedItems: a connection the description serves to programs (serve-as) is the item external/<serve-as> of the projection, its fields under
// the names of the description's variables, so external serve reads and writes them.
func servedItems(m *Vault, d *project.Description, out *CompatSnapshot) {
	done := map[string]bool{}
	d.Walk(func(h project.Home) {
		use := h.Conn
		if use == nil || use.ServeAs == "" || done[use.ServeAs] {
			return
		}
		done[use.ServeAs] = true
		var c *Connection
		for _, x := range m.Connections {
			if x.Kind == use.Kind && (c == nil || x.Name == use.Name) {
				c = x
			}
		}
		if c == nil {
			return
		}
		group := use.Role
		if group == "" {
			group = "account"
		}
		it := model.NewItem(model.SecExternal, use.ServeAs)
		it.HasMeta, it.Title = true, c.Name
		for _, v := range use.Variables {
			f := c.Field(v.Field)
			if f == nil {
				continue
			}
			vis := VisPlain
			if f.Secret || v.Secret {
				vis = VisSecret
			}
			path := join(GroupConnections, c.Name) + "#" + f.Name
			en := &model.Entry{Key: v.Name, Value: f.Value, Group: group, Path: path, Managed: ManagedOwner, Vis: vis, Title: v.Name, Changed: c.Changed}
			en.Notes = notesOf(en.Managed, en.Vis, nil, "")
			it.Entries = append(it.Entries, en)
			out.Targets[path] = &Target{Conn: c, Field: f.Name}
		}
		out.Snap.Put(it)
	})
}

func compatEnv(e *Environment, d *project.Description, o CompatOptions, targets map[string]*Target) *model.Item {
	order := o.Order
	it := model.NewItem(model.SecEnvs, e.Name)
	it.HasMeta, it.Title = true, e.Title
	var site *Site
	if len(e.Sites) == 1 {
		site = e.Sites[0]
	}
	var list []*compatEntry
	add := func(group, path string, x *Var, file string, t *Target) {
		if o.Group != nil && file != "" {
			if g := o.Group(file, x.Key); g != "" {
				group = g
			}
		}
		if t != nil {
			t.Env = e
			targets[path] = t
		}
		labels := append([]string(nil), x.Labels...)
		if len(labels) == 0 && file != "" && order != nil {
			if _, known := order(x.Key); !known {
				labels = []string{"file:" + file} // a key the manifest does not have goes to the file the description gives it
			}
		}
		en := &model.Entry{Key: x.Key, Value: x.Value, Group: group, Path: path, Managed: orDefault(x.Managed, ManagedOwner), Vis: orDefault(x.Vis, VisSecret), Title: x.Key,
			Description: x.Description, Labels: labels, Changed: x.Changed}
		en.Notes = notesOf(en.Managed, en.Vis, labels, x.Description)
		ce := &compatEntry{e: en, seq: len(list)}
		if order != nil {
			ce.rank, ce.ok = order(x.Key)
		}
		list = append(list, ce)
	}
	base := join(GroupEnvs, e.Name)
	isGeneral := func(h project.Home) bool { return h.Kind == project.HomeGeneral }
	for _, x := range e.General {
		add("general", join(base, GroupGeneral, x.Key), x, fileOf(d, isGeneral, x.Key), &Target{Var: x, Owner: &e.General})
	}
	for _, x := range e.Imports {
		if findVar(e.General, x.Key) == nil {
			add("general", join(GroupShared, x.Key), x, fileOf(d, isGeneral, x.Key), &Target{Var: x, Shared: true})
		}
	}
	derivedFile := func(name string) string {
		for _, x := range d.Derived {
			if x.Name == name {
				return x.File
			}
		}
		return d.GeneralFile()
	}
	derived := func(name, value, path string, t *Target) {
		if value != "" && e.WritesDerived(name) {
			t.Derived = name
			add("environment", path, &Var{Key: name, Value: value, Managed: ManagedOwner, Vis: VisPlain}, derivedFile(name), t)
		}
	}
	connVars := func(group string, c *Connection, use *project.ConnectionUse) {
		if c == nil || use == nil {
			return
		}
		for _, v := range use.Variables {
			f := c.Field(v.Field)
			if f == nil {
				continue
			}
			vis := VisPlain
			if f.Secret || v.Secret {
				vis = VisSecret
			}
			add(group, join(GroupConnections, c.Name)+"#"+f.Name, &Var{Key: v.Name, Value: f.Value, Managed: managedOf(v), Vis: vis, Changed: c.Changed}, or(v.File, use.File), &Target{Conn: c, Field: f.Name})
		}
	}
	if site != nil {
		sk := d.SiteKinds[site.Kind]
		for _, x := range d.Derived {
			switch x.From {
			case "site.provider":
				derived(x.Name, sk.Provider, join(base, GroupSites, site.Name, EntrySite)+"#"+x.Name, &Target{Site: site})
			case "site.state-backend":
				derived(x.Name, site.StateBackend, join(base, GroupSites, site.Name, EntrySite)+"#"+x.Name, &Target{Site: site})
			}
		}
		isSite := func(h project.Home) bool { return h.Kind == project.HomeSite && h.SiteKind == site.Kind }
		for _, x := range site.Vars {
			add("cluster", join(base, GroupSites, site.Name, x.Key), x, fileOf(d, isSite, x.Key), &Target{Var: x, Owner: &site.Vars, Site: site})
		}
		connVars("account", site.Connection, sk.Connection)
		connVars("state", site.State, sk.State)
	}
	for _, p := range e.Products {
		dp := d.Product(p.Name)
		if dp != nil && dp.PlaceVariable != "" {
			derived(dp.PlaceVariable, p.Place, join(base, GroupProducts, p.Name, EntryProduct)+"#"+dp.PlaceVariable, &Target{Product: p})
		}
	}
	for _, p := range e.Products {
		dp := d.Product(p.Name)
		isProduct := func(h project.Home) bool { return h.Kind == project.HomeProduct && h.Product == p.Name }
		for _, x := range p.Vars {
			add(p.Name, join(base, GroupProducts, p.Name, x.Key), x, fileOf(d, isProduct, x.Key), &Target{Var: x, Owner: &p.Vars, Product: p})
		}
		ps := p.Site
		if ps == nil {
			ps = site
		}
		if ps != nil {
			isSub := func(h project.Home) bool {
				return h.Kind == project.HomeProductSub && h.Product == p.Name && h.SiteKind == ps.Kind
			}
			sub := p.Sub[ps.Kind]
			for _, x := range sub {
				add(p.Name+"-"+ps.Kind, join(base, GroupProducts, p.Name, ps.Kind, x.Key), x, fileOf(d, isSub, x.Key), &Target{Var: x, Product: p, Site: ps})
			}
		}
		if dp != nil {
			for _, c := range p.Connections {
				for i := range dp.Connections {
					if dp.Connections[i].Kind == c.Kind {
						connVars(p.Name+"-"+c.Kind, c, &dp.Connections[i])
						break
					}
				}
			}
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.ok != b.ok {
			return a.ok
		}
		if a.ok && a.rank != b.rank {
			return a.rank < b.rank
		}
		return a.seq < b.seq
	})
	for _, ce := range list {
		it.Entries = append(it.Entries, ce.e)
	}
	files := append([]*File(nil), e.Files...)
	for _, s := range e.Sites {
		files = append(files, s.Files...)
	}
	for _, f := range files {
		mode := f.Mode
		if mode == 0 {
			mode = 0o600
		}
		it.Files[f.Rel] = &model.FileEntry{Data: append([]byte(nil), f.Data...), Mode: mode, Sha: model.SHA256(f.Data), Managed: orDefault(f.Managed, ManagedSystem), Changed: f.Changed,
			Vis: orDefault(f.Vis, VisSealed), Scope: it.Key(), Key: f.Rel}
	}
	for stem, data := range e.Layouts {
		it.Blobs[stem] = append([]byte(nil), data...)
		it.BlobPaths[model.BlobEntry(model.SecEnvs, e.Name, stem)] = true // the path the layout before the model gave it (the writer knows it)
	}
	return it
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func managedOf(v project.Variable) string {
	if v.System() {
		return ManagedSystem
	}
	return ManagedOwner
}
