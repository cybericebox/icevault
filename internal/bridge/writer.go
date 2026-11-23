package bridge

import (
	"fmt"
	"strings"

	"github.com/cybericebox/icevault/internal/kinds"
	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// Writer lets the commands of the layout before the vault model (import, recover, import-hcp, visibility --apply, the session's write-back,
// external serve) work on a migrated vault unchanged: they read the projection of the model (Snapshot) and write through the model.Writer they
// always used; Writer turns each write into a change of the model, and Commit writes the model into the vault through its one write path
// (vmodel.Sync) and saves. A path the projection made (an entry of it) is the thing it stands for; a path the old code builds for something new
// (<root>/environments/<env>/<group>/<KEY>, .../files/<rel>, .../.blobs/<stem>, external/<system>/...) is placed by the project
// description.
type Writer struct {
	v     *vault.Vault
	m     *vmodel.Vault
	d     *project.Description
	plat  *render.Project
	snap  *vmodel.CompatSnapshot
	made  map[string]*vmodel.Target // paths this writer made, by the path the old code gave them
	files map[string]*pendingFile
	dirty bool
}

type pendingFile struct {
	env    *vmodel.Environment
	site   *vmodel.Site
	rel    string
	layout string
	other  *vmodel.Other
	file   *vmodel.File
}

// NewWriter loads the model of a migrated vault and its projection.
func NewWriter(v *vault.Vault, d *project.Description, plat *render.Project) (*Writer, error) {
	if err := vmodel.CheckWritable(v); err != nil {
		return nil, err
	}
	m, err := vmodel.Load(v)
	if err != nil {
		return nil, err
	}
	w := &Writer{v: v, m: m, d: d, plat: plat, made: map[string]*vmodel.Target{}, files: map[string]*pendingFile{}}
	w.project()
	return w, nil
}

// Order of the projection: the manifest order.
func (w *Writer) options() vmodel.CompatOptions {
	rank := map[string]int{}
	n := 0
	for _, rel := range w.plat.ManifestFiles() {
		for _, r := range w.plat.Manifest(rel) {
			if _, ok := rank[r.Key]; !ok {
				rank[r.Key] = n
			}
			n++
		}
	}
	return vmodel.CompatOptions{Order: func(k string) (int, bool) { r, ok := rank[k]; return r, ok }}
}

func (w *Writer) project() { w.snap = vmodel.CompatWith(w.m, w.d, w.options()) }

// Changed marks the model as changed by the caller (a command that edits it directly), so Commit saves it.
func (w *Writer) Changed() { w.dirty = true }

// retired: a path below a retired group of the projection (what a run replaced, kept by the layout before the model); the model keeps no such
// copy (the vault's recycle bin has the replaced entry), so writes there are dropped.
func retired(path string) bool { return strings.Contains("/"+path+"/", "/"+model.Retired+"/") }

// Model is the model the writer changes.
func (w *Writer) Model() *vmodel.Vault { return w.m }

// Compat is the projection as it is now.
func (w *Writer) Compat() *vmodel.CompatSnapshot { return w.snap }

// Snapshot is the projection the old code reads.
func (w *Writer) Snapshot() (*model.Snapshot, error) { return w.snap.Snap, nil }

// Commit writes the model into the vault and saves it, when something changed.
func (w *Writer) Commit() error {
	if !w.dirty {
		return nil
	}
	if err := vmodel.Sync(w.v, w.m); err != nil {
		return err
	}
	if err := w.v.Save(); err != nil {
		return err
	}
	w.dirty = false
	return nil
}

func (w *Writer) target(path string) *vmodel.Target {
	if t := w.made[path]; t != nil {
		return t
	}
	return w.snap.Targets[path]
}

func (w *Writer) Mkdir(string) error { return nil }

// meta is what the notes of an old entry say.
type meta struct {
	managed, vis, desc string
	labels             []string
}

func parseMeta(notes string) meta {
	n := model.ParseNotes(notes)
	return meta{managed: n["managed-by"], vis: n["visibility"], desc: model.HintOf(notes), labels: model.ParseLabels(n["labels"])}
}

func (w *Writer) setValue(t *vmodel.Target, value string) error {
	switch {
	case t.Conn != nil:
		f := t.Conn.Field(t.Field)
		if f == nil {
			t.Conn.Set(t.Field, value, render.LooksSecret(t.Field))
		} else {
			f.Value = value
		}
	case t.Derived != "":
		w.setDerived(t, value)
	case t.Shared && t.Env != nil:
		if t.Var.Value == value {
			return nil
		}
		// a value of the environment's own replaces the imported one for this environment only
		nv := &vmodel.Var{Key: t.Var.Key, Value: value, Managed: t.Var.Managed, Vis: t.Var.Vis, Description: t.Var.Description, Labels: t.Var.Labels}
		t.Env.General = append(t.Env.General, nv)
		*t = vmodel.Target{Env: t.Env, Var: nv, Owner: &t.Env.General}
	case t.Var != nil:
		t.Var.Value = value
	default:
		return nil
	}
	w.dirty = true
	return nil
}

func (w *Writer) setDerived(t *vmodel.Target, value string) {
	switch {
	case t.Product != nil:
		t.Product.Place = value
		t.Product.Enabled = value != "none"
	case t.Site != nil && t.Derived == derivedFrom(w.d, "site.state-backend"):
		t.Site.StateBackend = value
	case t.Site != nil:
		if k := w.d.SiteKindOf(value); k != "" && k != t.Site.Kind {
			t.Site.Kind = k
			t.Site.Connection = nil // a site of another kind runs on another account: chosen again
		}
	}
}

func derivedFrom(d *project.Description, from string) string {
	for _, x := range d.Derived {
		if x.From == from {
			return x.Name
		}
	}
	return ""
}

func (w *Writer) setMeta(t *vmodel.Target, mt meta) {
	if t.Var == nil || t.Shared {
		return
	}
	if mt.managed != "" {
		t.Var.Managed = mt.managed
	}
	if mt.vis != "" {
		t.Var.Vis = mt.vis
	}
	t.Var.Description = mt.desc
	t.Var.Labels = append([]string(nil), mt.labels...)
	w.dirty = true
}

func (w *Writer) SetPassword(entry, password string) error {
	if retired(entry) {
		return nil
	}
	t := w.target(entry)
	if t == nil {
		if pf := w.files[entry]; pf != nil {
			return nil
		}
		return fmt.Errorf("%s: not an entry of the vault", entry)
	}
	return w.setValue(t, password)
}

func (w *Writer) SetNotes(entry, notes string) error {
	if retired(entry) {
		return nil
	}
	if t := w.target(entry); t != nil {
		w.setMeta(t, parseMeta(notes))
		if t.Conn != nil && parseMeta(notes).vis != "" {
			if f := t.Conn.Field(t.Field); f != nil {
				f.Secret = parseMeta(notes).vis != vmodel.VisPlain
				w.dirty = true
			}
		}
		return nil
	}
	if pf := w.files[entry]; pf != nil {
		return nil
	}
	return fmt.Errorf("%s: not an entry of the vault", entry)
}

func removeVar(list *[]*vmodel.Var, x *vmodel.Var) {
	out := (*list)[:0]
	for _, v := range *list {
		if v != x {
			out = append(out, v)
		}
	}
	*list = out
}

func (w *Writer) remove(t *vmodel.Target) {
	switch {
	case t.Conn != nil:
		var keep []*vmodel.Field
		for _, f := range t.Conn.Fields {
			if f.Name != t.Field {
				keep = append(keep, f)
			}
		}
		t.Conn.Fields = keep
	case t.Shared && t.Env != nil:
		var keep []*vmodel.Var
		for _, s := range t.Env.Imports {
			if s != t.Var {
				keep = append(keep, s)
			}
		}
		t.Env.Imports = keep
	case t.Owner != nil:
		removeVar(t.Owner, t.Var)
	case t.Product != nil && t.Site != nil && t.Var != nil:
		l := t.Product.Sub[t.Site.Kind]
		removeVar(&l, t.Var)
		t.Product.Sub[t.Site.Kind] = l
	case t.Var != nil:
		removeVar(&w.m.Shared, t.Var)
	default:
		return
	}
	w.dirty = true
}

func (w *Writer) Remove(entry string) error {
	if t := w.target(entry); t != nil {
		w.remove(t)
		delete(w.made, entry)
		return nil
	}
	if pf := w.files[entry]; pf != nil {
		w.dropFile(pf)
		delete(w.files, entry)
		return nil
	}
	return nil
}

// Move: the old code moves an entry only into retired/ (what a run replaced or removed); in the model it is gone (the vault keeps it in the
// recycle bin). A file moved there goes too.
func (w *Writer) Move(entry, group string) error {
	if !strings.Contains("/"+group+"/", "/"+model.Retired+"/") {
		return nil
	}
	return w.Remove(entry)
}

func (w *Writer) SetTitle(entry, title string) error {
	if retired(entry) {
		return nil
	}
	if t := w.target(entry); t != nil && t.Var != nil && !t.Shared {
		t.Var.Key = title
		w.dirty = true
		return nil
	}
	// a file renamed before it moves to retired (what a run removed): the new path stands for the same file, so the move drops it
	pf := w.files[entry]
	if pf == nil {
		pf = w.existingFile(entry)
	}
	if pf != nil {
		dir := ""
		if i := strings.LastIndex(entry, "/"); i >= 0 {
			dir = entry[:i+1]
		}
		w.files[dir+title] = pf
	}
	return nil
}

func (w *Writer) Attach(entry string, data []byte, _ bool) error {
	if retired(entry) {
		return nil
	}
	pf := w.files[entry]
	if pf == nil {
		if t := w.target(entry); t != nil {
			return nil // a variable has no attachment
		}
		if pf = w.existingFile(entry); pf == nil {
			return fmt.Errorf("%s: not an entry of the vault", entry)
		}
		w.files[entry] = pf
	}
	cp := append([]byte(nil), data...)
	switch {
	case pf.layout != "":
		pf.env.Layouts[pf.layout] = cp
	case pf.other != nil:
		pf.other.Data = cp
	case pf.file != nil:
		pf.file.Data = cp
	}
	w.dirty = true
	return nil
}

func (w *Writer) dropFile(pf *pendingFile) {
	switch {
	case pf.layout != "":
		delete(pf.env.Layouts, pf.layout)
	case pf.other != nil:
		var keep []*vmodel.Other
		for _, o := range w.m.Other {
			if o != pf.other {
				keep = append(keep, o)
			}
		}
		w.m.Other = keep
	case pf.file != nil:
		rm := func(fs []*vmodel.File) []*vmodel.File {
			var keep []*vmodel.File
			for _, f := range fs {
				if f != pf.file {
					keep = append(keep, f)
				}
			}
			return keep
		}
		if pf.site != nil {
			pf.site.Files = rm(pf.site.Files)
		} else {
			pf.env.Files = rm(pf.env.Files)
		}
	}
	w.dirty = true
}

// existingFile finds the file, layout or extra of an old path the projection shows (the old code builds those paths from the item and the rel).
func (w *Writer) existingFile(entry string) *pendingFile {
	parts := strings.Split(strings.TrimPrefix(entry, model.Group+"/"), "/")
	if len(parts) >= 2 && parts[0] == model.Files {
		rel := strings.Join(parts[1:], "/")
		for _, o := range w.m.Other {
			if o.Extra == rel {
				return &pendingFile{other: o}
			}
		}
		return nil
	}
	if len(parts) < 4 || parts[0] != model.SecEnvs {
		return nil
	}
	e := w.m.Env(parts[1])
	if e == nil {
		return nil
	}
	switch parts[2] {
	case model.Blobs:
		if _, ok := e.Layouts[parts[3]]; ok {
			return &pendingFile{env: e, layout: parts[3]}
		}
	case model.Files:
		rel := strings.Join(parts[3:], "/")
		for _, f := range e.Files {
			if f.Rel == rel {
				return &pendingFile{env: e, file: f, rel: rel}
			}
		}
		for _, s := range e.Sites {
			for _, f := range s.Files {
				if f.Rel == rel || "sites/"+s.Name+"/"+f.Rel == rel {
					return &pendingFile{env: e, site: s, file: f, rel: f.Rel}
				}
			}
		}
	}
	return nil
}

// Add makes an entry the old code needs: an update when the thing exists (the projection groups some variables differently from the layout
// before the model), else a new variable, file, layout, connection field, shared value or Other entry, placed by the description.
func (w *Writer) Add(entry, notes string, password *string) error {
	pw := ""
	if password != nil {
		pw = *password
	}
	if t := w.target(entry); t != nil {
		if err := w.setValue(t, pw); err != nil {
			return err
		}
		w.setMeta(t, parseMeta(notes))
		return nil
	}
	if pf := w.existingFile(entry); pf != nil {
		w.files[entry] = pf
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(entry, model.Group+"/"), "/")
	title := parts[len(parts)-1]
	if strings.HasPrefix(title, ".") && len(parts) <= 4 && (title == model.SectionMeta || title == model.ItemMeta || title == model.GroupMeta) {
		return nil // the structure of the layout before the model: the model has its own
	}
	mt := parseMeta(notes)
	x := &vmodel.Var{Key: title, Value: pw, Description: mt.desc, Managed: orText(mt.managed, vmodel.ManagedOwner), Vis: orText(mt.vis, vmodel.VisSecret), Labels: mt.labels}
	if len(parts) >= 2 && parts[0] == model.Files {
		o := &vmodel.Other{Title: flat("files/" + strings.Join(parts[1:], "/")), Extra: strings.Join(parts[1:], "/"), Notes: "An extra file (export --file)."}
		w.m.Other = append(w.m.Other, o)
		w.files[entry] = &pendingFile{other: o}
		w.dirty = true
		return nil
	}
	if len(parts) < 3 {
		return w.toOther(entry, x, "")
	}
	section, item, rest := parts[0], parts[1], parts[2:len(parts)-1]
	switch section {
	case model.SecEnvs:
		e := w.envOf(item)
		if len(rest) > 0 && rest[0] == model.Retired {
			return nil
		}
		if len(rest) > 0 && rest[0] == model.Blobs {
			w.files[entry] = &pendingFile{env: e, layout: title}
			e.Layouts[title] = nil
			return nil
		}
		if len(rest) > 0 && rest[0] == model.Files {
			rel := strings.Join(append(append([]string{}, rest[1:]...), title), "/")
			mode := model.ParseNotes(notes)["mode"]
			f := &vmodel.File{Rel: rel, Mode: parseMode(mode), Managed: orText(mt.managed, vmodel.ManagedSystem), Vis: orText(mt.vis, vmodel.VisSealed)}
			pf := &pendingFile{env: e, file: f, rel: rel}
			if strings.HasPrefix(rel, "sites/") {
				if p := strings.SplitN(rel, "/", 3); len(p) == 3 {
					f.Rel, rel = p[2], p[2]
				}
			}
			if w.plat.SiteBound(rel) && len(e.Sites) > 0 {
				pf.site = e.Sites[0]
				pf.site.Files = append(pf.site.Files, f)
			} else {
				e.Files = append(e.Files, f)
			}
			w.files[entry] = pf
			w.dirty = true
			return nil
		}
		w.placeVar(entry, e, x)
		return nil
	case model.SecGlobal:
		if s := w.m.SharedVar(x.Key); s != nil {
			s.Value = x.Value
			w.made[entry] = &vmodel.Target{Var: s}
		} else {
			w.m.Shared = append(w.m.Shared, x)
			w.made[entry] = &vmodel.Target{Var: x}
		}
		w.dirty = true
		return nil
	case model.SecExternal, model.SecSites:
		if c, field := w.connFor(item, x.Key); c != nil {
			c.Set(field, x.Value, x.Vis != vmodel.VisPlain)
			w.made[entry] = &vmodel.Target{Conn: c, Field: field}
			w.dirty = true
			return nil
		}
	}
	return w.toOther(entry, x, section+"/"+item)
}

func parseMode(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0o600
		}
		n = n*8 + int(c-'0')
	}
	if n == 0 {
		return 0o600
	}
	return n
}

func (w *Writer) toOther(entry string, x *vmodel.Var, from string) error {
	o := &vmodel.Other{Title: x.Key, Value: x.Value, Notes: strings.TrimSpace("From " + from + ".\n" + x.Description)}
	w.m.Other = append(w.m.Other, o)
	w.made[entry] = &vmodel.Target{Var: &vmodel.Var{Key: x.Key}}
	w.dirty = true
	return nil
}

// envOf returns an environment of the model, made (with a site main of the kind of the first site kind of the description) when it is new.
func (w *Writer) envOf(name string) *vmodel.Environment {
	if e := w.m.Env(name); e != nil {
		return e
	}
	e := &vmodel.Environment{Name: name, Layouts: map[string][]byte{}}
	w.m.Envs = append(w.m.Envs, e)
	w.dirty = true
	return e
}

func (w *Writer) siteOf(e *vmodel.Environment, kind string) *vmodel.Site {
	if len(e.Sites) > 0 {
		return e.Sites[0]
	}
	if kind == "" {
		return nil
	}
	s := &vmodel.Site{Name: SiteName, Kind: kind}
	e.Sites = append(e.Sites, s)
	for _, p := range e.Products {
		if p.Site == nil {
			p.Site = s
		}
	}
	return s
}

func (w *Writer) productOf(e *vmodel.Environment, name string) *vmodel.Product {
	if p := e.Product(name); p != nil {
		return p
	}
	p := &vmodel.Product{Name: name, Enabled: true, Sub: map[string][]*vmodel.Var{}}
	if len(e.Sites) > 0 {
		p.Site = e.Sites[0]
	}
	e.Products = append(e.Products, p)
	return p
}

// placeVar puts a new variable of an environment where the description says, as the migration does; a key it does not know stays in General
// with its labels, so it renders into the same file as before.
func (w *Writer) placeVar(entry string, e *vmodel.Environment, x *vmodel.Var) {
	w.dirty = true
	rels := w.plat.EntryRels(&model.Entry{Key: x.Key, Labels: x.Labels, Vis: x.Vis}, nil)
	siteKind := ""
	if len(e.Sites) > 0 {
		siteKind = e.Sites[0].Kind
	}
	for _, rel := range rels {
		if dx := w.d.DerivedOf(rel, x.Key); dx != nil {
			t := &vmodel.Target{Env: e, Derived: x.Key}
			switch dx.From {
			case "site.provider":
				t.Site = w.siteOf(e, w.d.SiteKindOf(x.Value))
			case "site.state-backend":
				t.Site = w.siteOf(e, siteKind)
			}
			if t.Site != nil {
				w.setDerived(t, x.Value)
			}
			w.markDerived(e, x.Key)
			w.made[entry] = t
			return
		}
		if dp := w.d.ProductByPlace(x.Key); dp != nil && rel == w.d.GeneralFile() {
			p := w.productOf(e, dp.Name)
			t := &vmodel.Target{Env: e, Derived: x.Key, Product: p}
			w.setDerived(t, x.Value)
			w.markDerived(e, x.Key)
			w.made[entry] = t
			return
		}
	}
	for _, rel := range rels {
		homes := w.d.Homes(rel, x.Key)
		for i, h := range homes {
			switch h.Kind {
			case project.HomeSite, project.HomeSiteConnection, project.HomeSiteState, project.HomeProductSub:
				if h.SiteKind != siteKind {
					continue
				}
			}
			if t := w.place(e, h, x); t != nil {
				w.made[entry] = t
				if t.Conn != nil {
					w.shareConn(e, t.Conn, homes[i+1:])
				}
				return
			}
		}
	}
	e.General = append(e.General, x)
	w.made[entry] = &vmodel.Target{Env: e, Var: x, Owner: &e.General}
}

// shareConn links a connection to the other products whose variables of the same file use a connection of its kind (one DNS account for two
// products).
func (w *Writer) shareConn(e *vmodel.Environment, c *vmodel.Connection, others []project.Home) {
	for _, h := range others {
		if h.Kind != project.HomeProductConnection || h.Conn.Kind != c.Kind {
			continue
		}
		p := w.productOf(e, h.Product)
		have := false
		for _, pc := range p.Connections {
			have = have || pc.Kind == c.Kind
		}
		if !have {
			p.Connections = append(p.Connections, c)
		}
	}
}

func (w *Writer) markDerived(e *vmodel.Environment, name string) {
	if e.Derived != nil && !contains(e.Derived, name) {
		e.Derived = append(e.Derived, name)
	}
}

func (w *Writer) place(e *vmodel.Environment, h project.Home, x *vmodel.Var) *vmodel.Target {
	switch h.Kind {
	case project.HomeGeneral:
		if old := findVar(e.General, x.Key); old != nil {
			old.Value = x.Value
			return &vmodel.Target{Env: e, Var: old, Owner: &e.General}
		}
		e.General = append(e.General, x)
		return &vmodel.Target{Env: e, Var: x, Owner: &e.General}
	case project.HomeSite:
		s := e.Sites[0]
		if old := findVar(s.Vars, x.Key); old != nil {
			old.Value = x.Value
			return &vmodel.Target{Env: e, Var: old, Owner: &s.Vars, Site: s}
		}
		s.Vars = append(s.Vars, x)
		return &vmodel.Target{Env: e, Var: x, Owner: &s.Vars, Site: s}
	case project.HomeSiteConnection, project.HomeSiteState, project.HomeProductConnection:
		var c *vmodel.Connection
		s := e.Sites[0:min(1, len(e.Sites))]
		switch {
		case h.Kind == project.HomeSiteConnection && len(s) == 1:
			if s[0].Connection == nil {
				s[0].Connection = w.newConn(h.Conn)
			}
			c = s[0].Connection
		case h.Kind == project.HomeSiteState && len(s) == 1:
			if s[0].State == nil {
				s[0].State = w.anyConn(h.Conn)
			}
			c = s[0].State
		case h.Kind == project.HomeProductConnection:
			p := w.productOf(e, h.Product)
			for _, pc := range p.Connections {
				if pc.Kind == h.Conn.Kind {
					c = pc
				}
			}
			if c == nil {
				c = w.anyConn(h.Conn)
				p.Connections = append(p.Connections, c)
			}
		}
		if c == nil {
			return nil
		}
		c.Set(h.Var.Field, x.Value, x.Vis != vmodel.VisPlain || h.Var.Secret)
		return &vmodel.Target{Env: e, Conn: c, Field: h.Var.Field}
	case project.HomeProduct:
		p := w.productOf(e, h.Product)
		if old := findVar(p.Vars, x.Key); old != nil {
			old.Value = x.Value
			return &vmodel.Target{Env: e, Var: old, Owner: &p.Vars, Product: p}
		}
		p.Vars = append(p.Vars, x)
		return &vmodel.Target{Env: e, Var: x, Owner: &p.Vars, Product: p}
	case project.HomeProductSub:
		p := w.productOf(e, h.Product)
		s := e.Sites[0]
		if old := findVar(p.Sub[h.SiteKind], x.Key); old != nil {
			old.Value = x.Value
			return &vmodel.Target{Env: e, Var: old, Product: p, Site: s}
		}
		p.Sub[h.SiteKind] = append(p.Sub[h.SiteKind], x)
		return &vmodel.Target{Env: e, Var: x, Product: p, Site: s}
	}
	return nil
}

func findVar(vs []*vmodel.Var, key string) *vmodel.Var {
	for _, v := range vs {
		if v.Key == key {
			return v
		}
	}
	return nil
}

// newConn makes a connection for a use of the description (a name not taken).
func (w *Writer) newConn(use *project.ConnectionUse) *vmodel.Connection {
	name := use.Name
	if name == "" {
		k, _ := kinds.ConnectionKind(use.Kind)
		name = k.Title
	}
	base := name
	for i := 2; w.m.Connection(name) != nil; i++ {
		name = fmt.Sprintf("%s %d", base, i)
	}
	c := &vmodel.Connection{Name: name, Kind: use.Kind}
	w.m.Connections = append(w.m.Connections, c)
	return c
}

// anyConn is the one connection of the kind of a use (several products and environments share one DNS account), else a new one.
func (w *Writer) anyConn(use *project.ConnectionUse) *vmodel.Connection {
	for _, c := range w.m.Connections {
		if c.Kind == use.Kind {
			return c
		}
	}
	return w.newConn(use)
}

// connFor is the connection and field of a key of an item of the projection that holds an access (external/<serve-as>, or an item named
// after a connection kind).
func (w *Writer) connFor(item, key string) (*vmodel.Connection, string) {
	kind := ""
	keys := map[string]string{}
	if use := w.d.Served(item); use != nil {
		kind = use.Kind
		for _, v := range use.Variables {
			keys[v.Name] = v.Field
		}
	}
	if kind == "" {
		if _, ok := kinds.ConnectionKind(item); ok && item != kinds.Other {
			kind = item
		}
	}
	if kind == "" {
		return nil, ""
	}
	field := keys[key]
	use := &project.ConnectionUse{Kind: kind}
	w.d.Walk(func(h project.Home) {
		if h.Conn != nil && h.Conn.Kind == kind {
			if use.Name == "" {
				use = h.Conn
			}
			if field == "" && h.Var.Name == key {
				field = h.Var.Field
			}
		}
	})
	if field == "" {
		field = key // a field of the connection's own (every kind takes free fields)
	}
	for _, c := range w.m.Connections {
		if c.Kind == kind && vmodel.Slug(c.Name) == item {
			return c, field
		}
	}
	return w.anyConn(use), field
}
