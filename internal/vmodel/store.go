package vmodel

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cybericebox/icevault/pkg/vault"
)

// The KDBX layout of the model. Paths are below the root group of the database.
//
//	Shared/<KEY>                                  one entry per shared variable
//	Connections/<name>                            one entry per connection: IceVault.Kind, the fields of the kind as custom fields
//	Environments/<env>/.environment               the environment: IceVault.Title, IceVault.Imports (UUIDs of Shared entries), IceVault.Derived
//	Environments/<env>/General/<KEY>              one entry per variable
//	Environments/<env>/Sites/<name>/.site         the site: IceVault.Kind, IceVault.Connection, IceVault.State (UUIDs), IceVault.StateBackend
//	Environments/<env>/Sites/<name>/<KEY>         its settings
//	Environments/<env>/Sites/<name>/Files/<path>  files of the site (attachment "content")
//	Environments/<env>/Products/<name>/.product   the product: IceVault.Enabled, IceVault.Place, IceVault.Site, IceVault.Connections (UUIDs)
//	Environments/<env>/Products/<name>/<KEY>      its own variables
//	Environments/<env>/Products/<name>/<kind>/<KEY>  the variables used only on a site of that kind
//	Environments/<env>/Files/<path>               files of the environment (attachment "content")
//	Environments/<env>/.layouts/<stem>            the stored layouts of the project's files (attachment "content")
//	Other/<title>                                 free entries
//
// A variable is an entry: the title is the key, the password the value, the notes its description; IceVault.Managed, IceVault.Visibility and
// IceVault.Labels are custom fields. References are entry UUIDs, so renaming never breaks them.
const (
	GroupShared      = "Shared"
	GroupConnections = "Connections"
	GroupEnvs        = "Environments"
	GroupOther       = "Other"
	GroupGeneral     = "General"
	GroupSites       = "Sites"
	GroupProducts    = "Products"
	GroupFiles       = "Files"
	GroupLayouts     = ".layouts"
	EntryEnv         = ".environment"
	EntrySite        = ".site"
	EntryProduct     = ".product"
	Attachment       = "content"

	fKind         = "IceVault.Kind"
	fManaged      = "IceVault.Managed"
	fVis          = "IceVault.Visibility"
	fLabels       = "IceVault.Labels"
	fTitle        = "IceVault.Title"
	fImports      = "IceVault.Imports"
	fDerived      = "IceVault.Derived"
	fConnection   = "IceVault.Connection"
	fState        = "IceVault.State"
	fStateBackend = "IceVault.StateBackend"
	fEnabled      = "IceVault.Enabled"
	fPlace        = "IceVault.Place"
	fSite         = "IceVault.Site"
	fConnections  = "IceVault.Connections"
	fMode         = "IceVault.Mode"
	fExtra        = "IceVault.Extra"
)

// ModelGroups are the top-level groups of the model.
var ModelGroups = []string{GroupShared, GroupConnections, GroupEnvs, GroupOther}

// ErrNewerFormat is the refusal to write a vault whose format this tool does not know.
var ErrNewerFormat = errors.New("the vault is in a newer format of the vault model than this IceVault knows: it is opened for reading only; update IceVault to change it")

// FormatOf is the format version of the vault: 0 for the layout before the model, -1 for a value that is not a number (treated as unknown).
func FormatOf(v *vault.Vault) int {
	s := v.MetaValue(FormatKey)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return -1
	}
	return n
}

// IsModel reports whether the vault is in the vault model (any format version, known or not).
func IsModel(v *vault.Vault) bool { return FormatOf(v) != 0 }

// CheckWritable refuses a vault this tool must not write: a format it does not know.
func CheckWritable(v *vault.Vault) error {
	if f := FormatOf(v); f != 0 && f != Format {
		return ErrNewerFormat
	}
	return nil
}

func join(parts ...string) string { return strings.Join(parts, "/") }

func fieldsOf(v *vault.Vault, path string) map[string]vault.Field {
	f, err := v.Fields(path)
	if err != nil {
		return map[string]vault.Field{}
	}
	return f
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func stamp(i vault.EntryInfo) string { return i.Modified.UTC().Format("2006-01-02T15:04:05Z") }

func readVar(v *vault.Vault, i vault.EntryInfo) (*Var, error) {
	p := join(i.Group, i.Title)
	e, err := v.Get(p)
	if err != nil {
		return nil, err
	}
	f := fieldsOf(v, p)
	out := &Var{UUID: i.UUID, Key: i.Title, Value: string(e.Password), Description: e.Notes, Managed: orDefault(f[fManaged].Value, ManagedOwner),
		Vis: orDefault(f[fVis].Value, VisSecret), Labels: splitList(f[fLabels].Value), Changed: stamp(i), Expires: dayOf(i)}
	wipe(e.Password)
	return out, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// readVars reads the variable entries of a group (entries whose title starts with a dot are the group's own).
func readVars(v *vault.Vault, group string) ([]*Var, error) {
	if !v.HasGroup(group) {
		return nil, nil
	}
	infos, err := v.Entries(group)
	if err != nil {
		return nil, err
	}
	var out []*Var
	for _, i := range infos {
		if strings.HasPrefix(i.Title, ".") {
			continue
		}
		x, err := readVar(v, i)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, nil
}

func readFiles(v *vault.Vault, group string) ([]*File, error) {
	if !v.HasGroup(group) {
		return nil, nil
	}
	var out []*File
	err := v.Walk(group, func(i vault.EntryInfo) error {
		p := join(i.Group, i.Title)
		data, err := v.Attachment(p, Attachment)
		if err != nil {
			data = nil
		}
		f := fieldsOf(v, p)
		mode, perr := strconv.ParseInt(orDefault(f[fMode].Value, "0600"), 8, 32)
		if perr != nil {
			mode = 0o600
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(i.Group, group), "/")
		out = append(out, &File{UUID: i.UUID, Rel: strings.TrimPrefix(rel+"/"+i.Title, "/"), Data: data, Mode: int(mode), Managed: orDefault(f[fManaged].Value, ManagedSystem),
			Vis: orDefault(f[fVis].Value, VisSealed), Changed: stamp(i)})
		return nil
	})
	return out, err
}

// Load reads the model from an open vault. A vault before the model gives an error; a newer format is read as far as this tool understands it and
// marked ReadOnly. What is broken (a reference to a missing entry) is listed in Problems.
func Load(v *vault.Vault) (*Vault, error) {
	f := FormatOf(v)
	if f == 0 {
		return nil, errors.New("the vault holds no vault model: a vault of the layout before it (IceVault 0.2) is moved with IceVault 0.4 first")
	}
	m := &Vault{Format: f, ReadOnly: f != Format}
	prob := func(format string, a ...any) { m.Problems = append(m.Problems, fmt.Sprintf(format, a...)) }
	var err error
	if m.Shared, err = readVars(v, GroupShared); err != nil {
		return nil, err
	}
	sharedByUUID := map[string]*Var{}
	for _, s := range m.Shared {
		sharedByUUID[s.UUID] = s
	}
	connByUUID := map[string]*Connection{}
	if v.HasGroup(GroupConnections) {
		infos, err := v.Entries(GroupConnections)
		if err != nil {
			return nil, err
		}
		for _, i := range infos {
			p := join(GroupConnections, i.Title)
			e, err := v.Get(p)
			if err != nil {
				return nil, err
			}
			fs := fieldsOf(v, p)
			c := &Connection{UUID: i.UUID, Name: i.Title, Kind: fs[fKind].Value, Description: e.Notes, Changed: stamp(i)}
			wipe(e.Password)
			names := make([]string, 0, len(fs))
			for n := range fs {
				if !strings.HasPrefix(n, "IceVault.") {
					names = append(names, n)
				}
			}
			sort.Strings(names)
			for _, n := range names {
				exp := fs[fExpiresPrefix+n].Value
				if _, err := ParseDay(exp); err != nil {
					prob("connection %s field %s: the expiry is not a date (YYYY-MM-DD) and is ignored", c.Name, n)
					exp = ""
				}
				c.Fields = append(c.Fields, &Field{Name: n, Value: fs[n].Value, Secret: fs[n].Protected, Expires: exp})
			}
			if d := dayOf(i); d != "" && connExpiry(c) == "" {
				importEntryExpiry(c, d)
			}
			m.Connections = append(m.Connections, c)
			connByUUID[c.UUID] = c
		}
	}
	conn := func(where, uuid string) *Connection {
		if uuid == "" {
			return nil
		}
		c := connByUUID[uuid]
		if c == nil {
			prob("%s: refers to a connection that is not in the vault", where)
		}
		return c
	}
	if v.HasGroup(GroupEnvs) {
		envNames, err := v.Groups(GroupEnvs)
		if err != nil {
			return nil, err
		}
		for _, name := range envNames {
			e, err := loadEnv(v, name, sharedByUUID, conn, prob)
			if err != nil {
				return nil, err
			}
			m.Envs = append(m.Envs, e)
		}
	}
	if v.HasGroup(GroupOther) {
		err := v.Walk(GroupOther, func(i vault.EntryInfo) error {
			p := join(i.Group, i.Title)
			e, err := v.Get(p)
			if err != nil {
				return err
			}
			fs := fieldsOf(v, p)
			o := &Other{UUID: i.UUID, Title: strings.TrimPrefix(p, GroupOther+"/"), Value: string(e.Password), Notes: e.Notes, Extra: fs[fExtra].Value, Expires: dayOf(i)}
			wipe(e.Password)
			if d, err := v.Attachment(p, Attachment); err == nil {
				o.Data = d
			}
			if md, err := strconv.ParseInt(orDefault(fs[fMode].Value, "0600"), 8, 32); err == nil {
				o.Mode = int(md)
			}
			m.Other = append(m.Other, o)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

func loadEnv(v *vault.Vault, name string, sharedByUUID map[string]*Var, conn func(string, string) *Connection, prob func(string, ...any)) (*Environment, error) {
	base := join(GroupEnvs, name)
	e := &Environment{Name: name, Layouts: map[string][]byte{}}
	if u, err := v.UUIDOf(join(base, EntryEnv)); err == nil {
		e.UUID = u
		fs := fieldsOf(v, join(base, EntryEnv))
		e.Title = fs[fTitle].Value
		for _, u := range splitList(fs[fImports].Value) {
			if s := sharedByUUID[u]; s != nil {
				e.Imports = append(e.Imports, s)
			} else {
				prob("environment %s: imports a shared variable that is not in the vault", name)
			}
		}
		if d, ok := fs[fDerived]; ok {
			e.Derived = splitList(d.Value)
			if e.Derived == nil {
				e.Derived = []string{}
			}
		}
	}
	var err error
	if e.General, err = readVars(v, join(base, GroupGeneral)); err != nil {
		return nil, err
	}
	if e.Files, err = readFiles(v, join(base, GroupFiles)); err != nil {
		return nil, err
	}
	if lay := join(base, GroupLayouts); v.HasGroup(lay) {
		infos, err := v.Entries(lay)
		if err != nil {
			return nil, err
		}
		for _, i := range infos {
			if d, err := v.Attachment(join(lay, i.Title), Attachment); err == nil {
				e.Layouts[i.Title] = d
			}
		}
	}
	siteByUUID := map[string]*Site{}
	if g := join(base, GroupSites); v.HasGroup(g) {
		names, err := v.Groups(g)
		if err != nil {
			return nil, err
		}
		for _, sn := range names {
			sg := join(g, sn)
			s := &Site{Name: sn}
			if u, err := v.UUIDOf(join(sg, EntrySite)); err == nil {
				s.UUID = u
				fs := fieldsOf(v, join(sg, EntrySite))
				where := "environment " + name + " site " + sn
				s.Kind, s.StateBackend = fs[fKind].Value, fs[fStateBackend].Value
				s.Connection, s.State = conn(where, fs[fConnection].Value), conn(where+" (state)", fs[fState].Value)
				siteByUUID[u] = s
			} else {
				prob("environment %s site %s: no %s entry", name, sn, EntrySite)
			}
			if s.Vars, err = readVars(v, sg); err != nil {
				return nil, err
			}
			if s.Files, err = readFiles(v, join(sg, GroupFiles)); err != nil {
				return nil, err
			}
			e.Sites = append(e.Sites, s)
		}
	}
	if g := join(base, GroupProducts); v.HasGroup(g) {
		names, err := v.Groups(g)
		if err != nil {
			return nil, err
		}
		for _, pn := range names {
			pg := join(g, pn)
			p := &Product{Name: pn, Enabled: true, Sub: map[string][]*Var{}}
			where := "environment " + name + " product " + pn
			if u, err := v.UUIDOf(join(pg, EntryProduct)); err == nil {
				p.UUID = u
				fs := fieldsOf(v, join(pg, EntryProduct))
				p.Enabled, p.Place = fs[fEnabled].Value != "no", fs[fPlace].Value
				if su := fs[fSite].Value; su != "" {
					if p.Site = siteByUUID[su]; p.Site == nil {
						prob("%s: refers to a site that is not in the environment", where)
					}
				}
				for _, cu := range splitList(fs[fConnections].Value) {
					if c := conn(where, cu); c != nil {
						p.Connections = append(p.Connections, c)
					}
				}
			} else {
				prob("%s: no %s entry", where, EntryProduct)
			}
			if p.Vars, err = readVars(v, pg); err != nil {
				return nil, err
			}
			subs, err := v.Groups(pg)
			if err != nil {
				return nil, err
			}
			for _, sk := range subs {
				if p.Sub[sk], err = readVars(v, join(pg, sk)); err != nil {
					return nil, err
				}
			}
			e.Products = append(e.Products, p)
		}
	}
	return e, nil
}

// Write puts the whole model into a vault that does not hold one yet (the migration, a new vault) and marks the format. Nothing is saved: the
// caller saves. The UUIDs of the objects are set from the entries made.
func Write(v *vault.Vault, m *Vault) error {
	if err := CheckWritable(v); err != nil {
		return err
	}
	for _, g := range ModelGroups {
		if v.HasGroup(g) {
			return fmt.Errorf("the vault already has a group %s: the model is written only into a vault without one", g)
		}
	}
	return Sync(v, m)
}

// Sync makes the model tree of the vault what m says: the one write path of the model. Every object with a UUID is the entry of that UUID (moved
// when its name or place changed, its content set; a real change keeps the old version in the entry's history); an object without one is made
// and gets the UUID of its new entry; an entry of the model tree that m no longer has goes to the recycle bin; a group left empty is removed.
// Nothing is saved: the caller saves.
func Sync(v *vault.Vault, m *Vault) error {
	if err := CheckWritable(v); err != nil {
		return err
	}
	if errs := m.Check(); len(errs) > 0 {
		return fmt.Errorf("the model is not valid: %s", strings.Join(errs, "; "))
	}
	s := &syncer{v: v, at: map[string]string{}, byPath: map[string]string{}, want: map[string]bool{}, keepGroups: map[string]bool{}}
	for _, g := range ModelGroups {
		if err := v.MakeGroup(g); err != nil {
			return err
		}
		s.keepGroups[g] = true
		if err := v.Walk(g, func(i vault.EntryInfo) error {
			s.at[i.UUID] = join(i.Group, i.Title)
			s.byPath[join(i.Group, i.Title)] = i.UUID
			return nil
		}); err != nil {
			return err
		}
	}
	s.plan(m)
	if err := s.apply(); err != nil {
		return err
	}
	v.SetMetaValue(FormatKey, strconv.Itoa(Format))
	return nil
}

// one entry the model wants
type wanted struct {
	uuid    *string
	group   string
	title   string
	notes   string
	pw      string
	fields  map[string]vault.Field
	expires string // the expiry date of the entry (YYYY-MM-DD), "" = never
	data    []byte // attachment "content" (nil: none)
	free    bool   // the custom fields not named are removed (a connection: its fields are the model's)
	byPath  bool   // no UUID of its own in the model: the entry at its path is it (a stored layout)
	after   func() // runs once the entry exists (references to its UUID)
}

type syncer struct {
	v          *vault.Vault
	at         map[string]string // uuid -> path now
	byPath     map[string]string // path now -> uuid
	want       map[string]bool   // paths of the model
	keepGroups map[string]bool
	list       []*wanted
}

func (s *syncer) add(w *wanted) {
	s.list = append(s.list, w)
	p := join(w.group, w.title)
	if w.byPath {
		*w.uuid = s.byPath[p]
	}
	s.want[p] = true
	for g := w.group; g != ""; g = parentOf(g) {
		s.keepGroups[g] = true
	}
}

func parentOf(g string) string {
	if i := strings.LastIndex(g, "/"); i >= 0 {
		return g[:i]
	}
	return ""
}

func varFields(x *Var) map[string]vault.Field {
	return map[string]vault.Field{fManaged: {Value: orDefault(x.Managed, ManagedOwner)}, fVis: {Value: orDefault(x.Vis, VisSecret)}, fLabels: {Value: strings.Join(x.Labels, ",")}}
}

func (s *syncer) varEntry(group string, x *Var) {
	s.add(&wanted{uuid: &x.UUID, group: group, title: x.Key, notes: x.Description, pw: x.Value, fields: varFields(x), expires: x.Expires})
}

func (s *syncer) fileEntries(group string, files []*File) {
	for _, f := range files {
		dir, name := group, f.Rel
		if i := strings.LastIndex(f.Rel, "/"); i >= 0 {
			dir, name = join(group, f.Rel[:i]), f.Rel[i+1:]
		}
		mode := f.Mode
		if mode == 0 {
			mode = 0o600
		}
		data := f.Data
		if data == nil {
			data = []byte{}
		}
		s.add(&wanted{uuid: &f.UUID, group: dir, title: name, data: data, fields: map[string]vault.Field{fMode: {Value: fmt.Sprintf("%04o", mode)},
			fManaged: {Value: orDefault(f.Managed, ManagedSystem)}, fVis: {Value: orDefault(f.Vis, VisSealed)}}})
	}
}

func (s *syncer) plan(m *Vault) {
	for _, x := range m.Shared {
		s.varEntry(GroupShared, x)
	}
	for _, c := range m.Connections {
		fs := map[string]vault.Field{fKind: {Value: c.Kind}}
		for _, f := range c.Fields {
			fs[f.Name] = vault.Field{Value: f.Value, Protected: f.Secret}
			if f.Expires != "" {
				fs[fExpiresPrefix+f.Name] = vault.Field{Value: f.Expires}
			}
		}
		s.add(&wanted{uuid: &c.UUID, group: GroupConnections, title: c.Name, notes: c.Description, fields: fs, free: true, expires: connExpiry(c)})
	}
	for _, e := range m.Envs {
		base := join(GroupEnvs, e.Name)
		for _, g := range []string{GroupGeneral, GroupSites, GroupProducts} {
			s.keepGroups[join(base, g)] = true
		}
		for _, x := range e.General {
			s.varEntry(join(base, GroupGeneral), x)
		}
		for _, st := range e.Sites {
			sg := join(base, GroupSites, st.Name)
			w := &wanted{uuid: &st.UUID, group: sg, title: EntrySite}
			w.after = func() {
				w.fields = map[string]vault.Field{fKind: {Value: st.Kind}, fConnection: {Value: connUUID(st.Connection)}, fState: {Value: connUUID(st.State)}, fStateBackend: {Value: st.StateBackend}}
			}
			s.add(w)
			for _, x := range st.Vars {
				s.varEntry(sg, x)
			}
			s.fileEntries(join(sg, GroupFiles), st.Files)
		}
		for _, p := range e.Products {
			pg := join(base, GroupProducts, p.Name)
			w := &wanted{uuid: &p.UUID, group: pg, title: EntryProduct}
			w.after = func() {
				on, site := "yes", ""
				if !p.Enabled {
					on = "no"
				}
				if p.Site != nil {
					site = p.Site.UUID
				}
				w.fields = map[string]vault.Field{fEnabled: {Value: on}, fPlace: {Value: p.Place}, fSite: {Value: site}, fConnections: {Value: uuids(p.Connections, connUUID)}}
			}
			s.add(w)
			for _, x := range p.Vars {
				s.varEntry(pg, x)
			}
			for _, sk := range sortedKeys(p.Sub) {
				s.keepGroups[join(pg, sk)] = true
				for _, x := range p.Sub[sk] {
					s.varEntry(join(pg, sk), x)
				}
			}
		}
		s.fileEntries(join(base, GroupFiles), e.Files)
		for _, stem := range sortedKeys(e.Layouts) {
			s.add(&wanted{uuid: new(string), group: join(base, GroupLayouts), title: stem, data: e.Layouts[stem], byPath: true})
		}
		w := &wanted{uuid: &e.UUID, group: base, title: EntryEnv}
		w.after = func() {
			w.fields = map[string]vault.Field{fTitle: {Value: e.Title}, fImports: {Value: uuids(e.Imports, func(x *Var) string { return x.UUID })}}
			if e.Derived != nil {
				w.fields[fDerived] = vault.Field{Value: strings.Join(e.Derived, ",")}
			}
		}
		s.add(w)
	}
	titles := map[string]bool{}
	for _, o := range m.Other {
		title := o.Title
		for n := 2; titles[title]; n++ {
			title = fmt.Sprintf("%s (%d)", o.Title, n)
		}
		titles[title] = true
		o.Title = title
		group, name := GroupOther, title
		if i := strings.LastIndex(title, "/"); i >= 0 {
			group, name = join(GroupOther, title[:i]), title[i+1:]
		}
		fs := map[string]vault.Field{fExtra: {Value: o.Extra}}
		if o.Mode != 0 && o.Mode != 0o600 {
			fs[fMode] = vault.Field{Value: fmt.Sprintf("%04o", o.Mode)}
		}
		s.add(&wanted{uuid: &o.UUID, group: group, title: name, notes: o.Notes, pw: o.Value, fields: fs, data: o.Data, expires: o.Expires})
	}
}

// apply: what the model no longer has goes to the recycle bin; entries that move go through a parking group first (so two names can swap); then
// every entry is made or set; the references are written last, when every UUID is known; empty groups go.
func (s *syncer) apply() error {
	v := s.v
	keep := map[string]bool{}
	for _, w := range s.list {
		if *w.uuid != "" {
			keep[*w.uuid] = true
		}
	}
	for u, p := range s.at {
		if !keep[u] {
			if err := v.Remove(p); err != nil {
				return err
			}
			delete(s.at, u)
		}
	}
	const parking = GroupOther + "/.icevault-moving"
	for _, w := range s.list {
		u := *w.uuid
		cur, ok := s.at[u]
		if !ok || u == "" || cur == join(w.group, w.title) {
			continue
		}
		if err := v.MakeGroup(parking); err != nil {
			return err
		}
		if err := v.Move(cur, join(parking, u)); err != nil {
			return err
		}
		s.at[u] = join(parking, u)
	}
	for _, w := range s.list {
		p := join(w.group, w.title)
		u := *w.uuid
		if cur, ok := s.at[u]; ok && u != "" && cur != p {
			if err := v.MakeGroup(w.group); err != nil {
				return err
			}
			if err := v.Move(cur, p); err != nil {
				return err
			}
		}
		if err := v.Put(vault.Entry{Group: w.group, Title: w.title, Notes: w.notes, Password: []byte(w.pw)}); err != nil {
			return err
		}
		id, err := v.UUIDOf(p)
		if err != nil {
			return err
		}
		*w.uuid = id
		if w.data != nil {
			if err := v.SetAttachment(p, Attachment, w.data); err != nil {
				return err
			}
		}
	}
	for _, w := range s.list {
		if w.after != nil {
			w.after()
		}
		p := join(w.group, w.title)
		day, err := ParseDay(w.expires)
		if err != nil {
			return err
		}
		if err := v.SetExpiry(p, day); err != nil {
			return err
		}
		if len(w.fields) > 0 {
			if err := v.SetFields(p, w.fields); err != nil {
				return err
			}
		}
		if w.free {
			have, err := v.Fields(p)
			if err != nil {
				return err
			}
			for n := range have {
				if _, ok := w.fields[n]; !ok {
					if err := v.RemoveField(p, n); err != nil {
						return err
					}
				}
			}
		}
	}
	for _, g := range ModelGroups {
		paths, err := v.GroupPaths(g)
		if err != nil {
			return err
		}
		for i := len(paths) - 1; i >= 0; i-- {
			if s.keepGroups[paths[i]] {
				continue
			}
			if es, err := v.Entries(paths[i]); err == nil && len(es) == 0 {
				if sub, _ := v.Groups(paths[i]); len(sub) == 0 {
					if err := v.RemoveEmptyGroup(paths[i]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func uuids[T any](xs []T, id func(T) string) string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, id(x))
	}
	return strings.Join(out, ",")
}

func connUUID(c *Connection) string {
	if c == nil {
		return ""
	}
	return c.UUID
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
