package render

import (
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cybericebox/icevault/internal/model"
)

// Source is the plaintext tree an import reads (<plaintext>/<env> of the checkout): no
// disk access in this package. FSSource adapts an fs.FS.
type Source interface {
	Files() ([]string, error) // relative paths ("/" separators) of the regular files, sorted
	Read(rel string) ([]byte, error)
	Mode(rel string) (int, error) // permission bits
}

// FSSource is a Source over an fs.FS rooted at the tree (os.DirFS(dir) in production).
type FSSource struct{ FS fs.FS }

func (s FSSource) Files() ([]string, error) {
	var out []string
	err := fs.WalkDir(s.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() { // symbolic links are not followed or listed
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}
func (s FSSource) Read(rel string) ([]byte, error) { return fs.ReadFile(s.FS, rel) }
func (s FSSource) Mode(rel string) (int, error) {
	fi, err := fs.Stat(s.FS, rel)
	if err != nil {
		return 0, err
	}
	return int(fi.Mode().Perm()), nil
}

// Options of an import / sync.
type Options struct {
	Env           string
	Tree          Source
	Extra         map[string][]byte // single files that live elsewhere (the committed settings of the environment), by rel; mode 0600
	DryRun        bool
	Site          string
	RetireMissing bool
	Now           func() string
	Say           func(string) // progress lines "[i/n] rel" (never a value)
}

// Report is what a sync did (names only).
type Report struct {
	Lines                              []string
	Added, Changed, Removed, Unchanged int
	Blocked, Retired                   []string
	CommentsCleaned                    []string // variables whose comment had a reserved or hidden line dropped
}

// Note adds a line "  <what padded to 9> <name>".
func (r *Report) Note(what, name string) {
	r.Lines = append(r.Lines, fmt.Sprintf("  %-9s %s", what, name))
}

// the operations of one variable in a sync
const (
	opAdd    = "add"
	opAddRef = "addref"
	opEdit   = "edit"
	opRm     = "rm"
)

type ipair struct {
	op, name, value, managed, epath string
	scope                           model.ItemKey
	group                           string
}

// syncer holds the state of one sync: the vault writer, the snapshot (mutated
// as items and links are made) and the groups made.
type syncer struct {
	w      model.Writer
	snap   *model.Snapshot
	p      *Project
	dry    bool
	groups map[string]bool
	rep    *Report
	now    func() string
}

func (s *syncer) ensureGroups(entry string) error {
	parts := strings.Split(entry, "/")
	parts = parts[:len(parts)-1]
	for i := 1; i <= len(parts); i++ {
		g := strings.Join(parts[:i], "/")
		if !s.groups[g] {
			if !s.dry {
				if err := s.w.Mkdir(g); err != nil {
					return err
				}
			}
			s.groups[g] = true
		}
	}
	return nil
}

func (s *syncer) ensureSection(section, title string, order int) error { // order < 0: none
	if _, ok := s.snap.Sections[section]; ok {
		return nil
	}
	system := section == model.SecEnvs
	if title == "" && system {
		title = "Environments"
	}
	if system {
		order = 0
	} else if order < 0 {
		order = 1000
	}
	entry := model.SectionEntry(section)
	if !s.dry {
		if err := s.ensureGroups(entry); err != nil {
			return err
		}
		o := order
		if o >= 1000 {
			o = -1
		}
		if err := func() error {
			nts, err := model.SectionNotes(title, o, system, model.StateActive)
			if err != nil {
				return err
			}
			return s.w.Add(entry, nts, nil)
		}(); err != nil {
			return err
		}
	}
	s.snap.Sections[section] = &model.SectionMetaInfo{Title: title, Order: order, System: system, State: model.StateActive}
	return nil
}

func (s *syncer) ensureItem(section, name, title string) (*model.Item, error) {
	it := s.snap.Make(section, name)
	if it.HasMeta {
		return it, nil
	}
	if err := s.ensureSection(section, "", -1); err != nil {
		return nil, err
	}
	it.HasMeta, it.Title = true, title
	if !s.dry {
		entry := model.ItemEntry(section, name)
		if err := s.ensureGroups(entry); err != nil {
			return nil, err
		}
		if err := func() error {
			nts, err := model.ItemNotes(it)
			if err != nil {
				return err
			}
			return s.w.Add(entry, nts, nil)
		}(); err != nil {
			return nil, err
		}
	}
	return it, nil
}

// EnvTreeFiles classifies the files of a source plus the extra files.
func (p *Project) EnvTreeFiles(src Source, extra map[string][]byte) (covered map[string]Covered, skipped, unknown []string, err error) {
	var rels, ex []string
	if src != nil {
		if rels, err = src.Files(); err != nil {
			return
		}
	}
	for rel := range extra {
		ex = append(ex, rel)
	}
	sort.Strings(ex)
	covered, skipped, unknown = p.TreeFiles(rels, ex)
	// a path becomes part of the notes and of the layout of the vault: every
	// segment of a kept file must be a plain name (no line break, no invisible
	// character, no space or quote). The error names the path escaped.
	bad := make([]string, 0)
	for rel := range covered {
		if !model.ValidRel(rel) {
			bad = append(bad, rel)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		err = &model.StoreError{Msg: fmt.Sprintf("refused: %q is not a plain file name (letters, digits, . _ - only, per path part): rename it, nothing was imported", bad[0])}
	}
	return
}

// SafeName is a name from a filesystem made safe to print: unchanged when it is
// plain, else quoted with escapes.
func SafeName(s string) string {
	plain := utf8.ValidString(s)
	for _, r := range s {
		if r == '\n' || r == '\t' || r == 0x7f || r < 0x20 || model.HiddenRune(r) {
			plain = false
		}
	}
	if plain {
		return s
	}
	return strconv.QuoteToASCII(s)
}

func safeNames(l []string) []string {
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = SafeName(s)
	}
	return out
}

func checkImportNames(o Options) error {
	if !model.NameRE.MatchString(o.Env) {
		return &model.StoreError{Msg: fmt.Sprintf("refused: %q is not an environment name (a-z 0-9 _ -, up to 32)", o.Env)}
	}
	if o.Site != "" && !model.NameRE.MatchString(o.Site) {
		return &model.StoreError{Msg: fmt.Sprintf("refused: %q is not a site name (a-z 0-9 _ -, up to 32)", o.Site)}
	}
	return nil
}

func orEmptyLayout(ef *EnvFile) *EnvFile {
	if ef != nil {
		return ef
	}
	return newEnvFile(EmptyLayout())
}

// SyncTree makes the vault equal to the secret files of the tree of
// environment o.Env: only what differs from snap (the vault as it was read) is
// written. A variable that exists in the resolved namespace of the environment
// (its own entries or a linked item's) is updated where it lives. A new one goes
// into the environment item with the label of its file (the writer of the vault
// model places it where the description says). Rules: an OWNER entry that has
// a value is never changed or removed by a command (reported in Blocked); a
// SYSTEM entry that is replaced or removed is first kept in retired/ with
// retired-at and needed-until, never deleted; an environment never removes an
// entry of a linked item. RetireMissing: system file entries of the environment
// that are no longer in the tree are moved to retired too.
func (p *Project) SyncTree(w model.Writer, snap *model.Snapshot, o Options) (*Report, error) {
	rep := &Report{}
	if err := checkImportNames(o); err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = model.NowUTC
	}
	covered, _, _, err := p.EnvTreeFiles(o.Tree, o.Extra)
	if err != nil {
		return nil, err
	}
	s := &syncer{w: w, snap: snap, p: p, dry: o.DryRun, groups: map[string]bool{}, rep: rep, now: o.Now}
	for g := range snap.Groups {
		s.groups[g] = true
	}
	stamp := o.Now()
	read := func(rel string) ([]byte, int, error) {
		if b, ok := o.Extra[rel]; ok {
			return b, 0o600, nil
		}
		b, err := o.Tree.Read(rel)
		if err != nil {
			return nil, 0, err
		}
		m, err := o.Tree.Mode(rel)
		return b, m, err
	}
	rels := make([]string, 0, len(covered))
	for rel := range covered {
		rels = append(rels, rel)
	}
	// the general file first: its settings say what the environment is (the provider of its site, the places of the products), which the writer
	// of the model needs before it places the variables of the site and the products
	sort.Slice(rels, func(i, j int) bool {
		gi, gj := rels[i] == p.Conf(), rels[j] == p.Conf()
		if gi != gj {
			return gi
		}
		return rels[i] < rels[j]
	})

	type parsedFile struct {
		layout Layout
		vars   []Var
		text   string
	}
	parsed := map[string]parsedFile{}
	for _, rel := range rels {
		if covered[rel].Kind == KindEnv {
			b, _, err := read(rel)
			if err != nil {
				return nil, err
			}
			l, vs, err := ParseEnvChecked(rel, string(b))
			if err != nil {
				return nil, err
			}
			parsed[rel] = parsedFile{l, vs, string(b)}
		}
	}
	envItem, err := s.ensureItem(model.SecEnvs, o.Env, "")
	if err != nil {
		return nil, err
	}
	envScope := model.ItemKey{Section: model.SecEnvs, Name: o.Env}
	base, err := p.View(snap, o.Env, o.Site)
	if err != nil {
		return nil, err
	}
	retireVar := func(scope model.ItemKey, group, name, value string) error {
		if o.DryRun {
			return nil
		}
		entry := model.ItemRoot(scope.Section, scope.Name) + "/" + model.Retired + "/" + group + "/" + name + "@" + stamp
		if err := s.ensureGroups(entry); err != nil {
			return err
		}
		v := value
		if err := func() error {
			nts, err := model.RetiredNotes(group+"/"+name, model.SHA256([]byte(value)), 0o600, stamp, p.NeededUntil(name))
			if err != nil {
				return err
			}
			return w.Add(entry, nts, &v)
		}(); err != nil {
			return err
		}
		rep.Retired = append(rep.Retired, group+"/"+name)
		return nil
	}
	retireFile := func(rel string, fe *model.FileEntry, move bool) error {
		if o.DryRun {
			return nil
		}
		root := model.ItemRoot(envScope.Section, envScope.Name)
		if fe.Scope != (model.ItemKey{}) {
			root = model.ItemRoot(fe.Scope.Section, fe.Scope.Name)
		}
		stored := fe.Key
		if stored == "" {
			stored = rel // a file of a site is stored under sites/<site>/<rel>
		}
		title := strings.ReplaceAll(rel, "/", "~") + "@" + stamp
		dest := root + "/" + model.Retired + "/" + title
		if err := s.ensureGroups(dest); err != nil {
			return err
		}
		if move {
			src := root + "/" + model.Files + "/" + stored
			if err := w.SetTitle(src, title); err != nil {
				return err
			}
			where := ""
			if i := strings.LastIndex(stored, "/"); i >= 0 {
				where = stored[:i] + "/"
			}
			if err := w.Move(root+"/"+model.Files+"/"+where+title, root+"/"+model.Retired); err != nil {
				return err
			}
		} else {
			if err := w.Add(dest, "managed-by=retired", nil); err != nil {
				return err
			}
			if err := w.Attach(dest, fe.Data, false); err != nil {
				return err
			}
		}
		if err := func() error {
			nts, err := model.RetiredNotes(rel, fe.Sha, fe.Mode, stamp, p.NeededUntil(rel))
			if err != nil {
				return err
			}
			return w.SetNotes(dest, nts)
		}(); err != nil {
			return err
		}
		rep.Retired = append(rep.Retired, rel)
		return nil
	}

	total := len(rels)
	tick := func(i int, rel string) {
		if !o.DryRun && o.Say != nil {
			o.Say(fmt.Sprintf("[%d/%d] %s", i, total, rel))
		}
	}
	for idx, rel := range rels {
		c := covered[rel]
		i := idx + 1
		if c.Kind == KindEnv {
			pf := parsed[rel]
			old := base.Env[rel]
			ref := orEmptyLayoutFile(old)
			mine := ref.Variables
			comments := map[string]string{}
			var names []string
			for _, v := range pf.vars {
				comments[v.Name] = v.Notes
				names = append(names, v.Name)
			}
			var ops []ipair
			var blocked []string
			for _, v := range pf.vars {
				name := v.Name
				m := ref.Managed[name]
				if m == "" {
					m = p.VarManagedIn(rel, name)
				}
				newValue := StoredValue(v.Value, m)
				if cur, in := mine.Get(name); in {
					if cur != newValue {
						if m == model.ManagedOwner && cur != "" {
							blocked = append(blocked, name)
						} else {
							sc, ok := ref.Scope[name]
							if !ok {
								sc = envScope
							}
							ops = append(ops, ipair{opEdit, name, newValue, m, ref.Path[name], sc, ref.Group[name]})
						}
					}
				} else {
					group := GroupOf(rel)
					ops = append(ops, ipair{opAdd, name, newValue, p.VarManagedIn(rel, name), model.VarEntry(envScope.Section, envScope.Name, group, name), envScope, group})
				}
			}
			for _, name := range mine.Order {
				if contains(names, name) || ref.Scope[name] != envScope {
					continue
				}
				mg := ref.Managed[name]
				if mg == "" {
					mg = model.ManagedOwner
				}
				if mg == model.ManagedOwner && mine.M[name] != "" {
					blocked = append(blocked, name)
				} else {
					ops = append(ops, ipair{opRm, name, "", mg, ref.Path[name], ref.Scope[name], ref.Group[name]})
				}
			}
			layEntry := model.BlobEntry(model.SecEnvs, o.Env, StemOf(rel))
			layExists := envItem.BlobPaths[layEntry]
			// the layout is unchanged when the stored one still renders this very file (lines a linked item adds are appended, they are not layout)
			values := VarsOf(pf.vars)
			layChanged := !layExists || RenderEnv(p.Positioned(ref.Layout, values, rel), values) != pf.text
			if old != nil && len(ops) == 0 && len(blocked) == 0 && !layChanged {
				rep.Unchanged++
				continue
			}
			if old == nil {
				rep.Note("new", rel)
				rep.Added++
			} else if len(ops) > 0 || layChanged {
				set := map[string]bool{}
				for _, op := range ops {
					set[op.op+" "+op.name] = true
				}
				list := make([]string, 0, len(set))
				for k := range set {
					list = append(list, k)
				}
				sort.Strings(list)
				if len(list) == 0 {
					list = []string{"layout"}
				}
				rep.Note("changed", rel+": "+strings.Join(list, ", "))
				rep.Changed++
			}
			for _, name := range blocked {
				rep.Blocked = append(rep.Blocked, rel+"/"+name)
			}
			if o.DryRun {
				continue
			}
			if !layExists {
				if err := s.ensureGroups(layEntry); err != nil {
					return nil, err
				}
				if err := w.Add(layEntry, "", nil); err != nil {
					return nil, err
				}
				if err := w.Attach(layEntry, []byte(CanonJSON(pf.layout)), false); err != nil {
					return nil, err
				}
				envItem.BlobPaths[layEntry] = true
			} else if layChanged {
				if err := w.Attach(layEntry, []byte(CanonJSON(pf.layout)), true); err != nil {
					return nil, err
				}
			}
			for _, op := range ops {
				if op.op == opAdd || op.op == opAddRef {
					if err := s.ensureGroups(op.epath); err != nil {
						return nil, err
					}
					var labels []string
					if op.scope == envScope {
						labels = LabelsFor(rel)
					}
					desc, cleaned := model.SafeDescription(comments[op.name])
					if cleaned {
						rep.CommentsCleaned = append(rep.CommentsCleaned, rel+"/"+op.name)
					}
					val := op.value
					if err := func() error {
						nts, err := model.EntryNotes(op.managed, p.DefaultVisibility(rel, op.name, op.managed), labels, desc, "")
						if err != nil {
							return err
						}
						return w.Add(op.epath, nts, &val)
					}(); err != nil {
						return nil, err
					}
					continue
				}
				if cur, in := mine.Get(op.name); op.managed == model.ManagedSystem && in && cur != "" {
					if err := retireVar(op.scope, op.group, op.name, cur); err != nil {
						return nil, err
					}
				}
				if op.op == opEdit {
					if err := w.SetPassword(op.epath, op.value); err != nil {
						return nil, err
					}
				} else if err := w.Remove(op.epath); err != nil {
					return nil, err
				}
			}
			tick(i, rel)
		} else {
			data, mode, err := read(rel)
			if err != nil {
				return nil, err
			}
			sha := model.SHA256(data)
			oldF := base.Files[rel]
			scope := envScope
			if oldF != nil && oldF.Scope != (model.ItemKey{}) {
				scope = oldF.Scope
			}
			if oldF != nil && oldF.Sha == sha {
				rep.Unchanged++
				continue
			}
			if oldF != nil && oldF.Managed == model.ManagedOwner && len(oldF.Data) > 0 {
				rep.Blocked = append(rep.Blocked, "files/"+rel)
				continue
			}
			if oldF != nil {
				rep.Note("changed", rel)
				rep.Changed++
			} else {
				rep.Note("new", rel)
				rep.Added++
			}
			if o.DryRun {
				continue
			}
			stored := rel
			if oldF != nil && oldF.Key != "" {
				stored = oldF.Key
			} else if o.Site != "" && p.SiteBound(rel) {
				stored = "sites/" + o.Site + "/" + rel
			}
			entry := model.FileEntryPath(scope.Section, scope.Name, stored)
			if oldF != nil && p.RetireFile(rel) {
				if err := retireFile(rel, oldF, false); err != nil {
					return nil, err
				}
			}
			managed := model.ManagedOwner
			if c.Rule != nil {
				managed = c.Rule.Managed
			}
			if oldF == nil {
				if err := s.ensureGroups(entry); err != nil {
					return nil, err
				}
				if err := func() error {
					nts, err := model.PendingFileNotes(stored, managed)
					if err != nil {
						return err
					}
					return w.Add(entry, nts, nil)
				}(); err != nil {
					return nil, err
				}
			}
			if err := w.Attach(entry, data, oldF != nil); err != nil {
				return nil, err
			}
			if err := func() error {
				nts, err := model.FileNotes(stored, sha, mode, o.Now(), managed, model.VisSealed)
				if err != nil {
					return err
				}
				return w.SetNotes(entry, nts)
			}(); err != nil {
				return nil, err
			}
			tick(i, rel)
		}
	}
	if o.RetireMissing {
		frels := make([]string, 0, len(base.Files))
		for rel := range base.Files {
			frels = append(frels, rel)
		}
		sort.Strings(frels)
		for _, rel := range frels {
			fe := base.Files[rel]
			if _, in := covered[rel]; !in && fe.Managed == model.ManagedSystem && fe.Scope == envScope && p.RetireFile(rel) {
				rep.Note(model.StateRetired, rel)
				if err := retireFile(rel, fe, true); err != nil {
					return nil, err
				}
			}
		}
	}
	return rep, nil
}

func orEmptyLayoutFile(ef *EnvFile) *EnvFile { return orEmptyLayout(ef) }

// ImportTree is the command `import`: SyncTree plus the checks and the text
// of the report (recording the info file is the caller's).
// label names the tree in the "holds no secret files" error (a path).
func (p *Project) ImportTree(w model.Writer, snap *model.Snapshot, o Options, label string) (*Report, []string, error) {
	if err := checkImportNames(o); err != nil {
		return nil, nil, err
	}
	covered, skipped, unknown, err := p.EnvTreeFiles(o.Tree, o.Extra)
	if err != nil {
		return nil, nil, err
	}
	if len(covered) == 0 {
		return nil, nil, &model.StoreError{Msg: label + " holds no secret files to import"}
	}
	rep, err := p.SyncTree(w, snap, o)
	if err != nil {
		return nil, nil, err
	}
	var out []string
	out = append(out, rep.Lines...)
	if len(rep.Blocked) > 0 {
		out = append(out, fmt.Sprintf("  %d owner entry(ies) differ from the file and were left as they are (change them in the app): %s", len(rep.Blocked), strings.Join(head(rep.Blocked, 10), ", ")))
	}
	if len(rep.Retired) > 0 {
		out = append(out, fmt.Sprintf("  replaced system value(s) kept as retired: %s", strings.Join(head(rep.Retired, 10), ", ")))
	}
	if len(rep.CommentsCleaned) > 0 {
		out = append(out, fmt.Sprintf("  the comment of %d variable(s) had a reserved or hidden line that was not kept: %s", len(rep.CommentsCleaned), strings.Join(head(rep.CommentsCleaned, 10), ", ")))
	}
	verb := "imported"
	if o.DryRun {
		verb = "would import"
	}
	tail := fmt.Sprintf("%s: %d new, %d changed; %d unchanged; %d left out on purpose", verb, rep.Added, rep.Changed, rep.Unchanged, len(skipped))
	if len(unknown) > 0 {
		tail += fmt.Sprintf(", %d not covered (no rule of the project description keeps them): %s", len(unknown), strings.Join(safeNames(head(unknown, 6)), ", "))
	}
	out = append(out, tail)
	return rep, out, nil
}

func head(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

// ImportExtra is the import of one extra file kept under <root>/files/<rel>
// (a database dump, say): it returns the report lines and whether it did
// (or would do) anything.
func ImportExtra(w model.Writer, snap *model.Snapshot, rel string, data []byte, mode int, dry bool, now func() string) ([]string, bool, error) {
	if now == nil {
		now = model.NowUTC
	}
	sha := model.SHA256(data)
	old := snap.Extras[rel]
	if old != nil && old.Sha == sha {
		return []string{"imported: 0 new, 0 changed; 1 unchanged"}, false, nil
	}
	what, n, c := "new", 1, 0
	if old != nil {
		what, n, c = "changed", 0, 1
	}
	lines := []string{fmt.Sprintf("  %-9s %s", what, rel)}
	if !dry {
		s := &syncer{w: w, snap: snap, groups: map[string]bool{}}
		for g := range snap.Groups {
			s.groups[g] = true
		}
		entry := model.Group + "/" + model.Files + "/" + rel
		if err := s.ensureGroups(entry); err != nil {
			return nil, false, err
		}
		if old == nil {
			if err := func() error {
				nts, err := model.PendingFileNotes(rel, model.ManagedOwner)
				if err != nil {
					return err
				}
				return w.Add(entry, nts, nil)
			}(); err != nil {
				return nil, false, err
			}
		}
		if err := w.Attach(entry, data, old != nil); err != nil {
			return nil, false, err
		}
		if err := func() error {
			nts, err := model.FileNotes(rel, sha, mode, now(), model.ManagedOwner, model.VisSealed)
			if err != nil {
				return err
			}
			return w.SetNotes(entry, nts)
		}(); err != nil {
			return nil, false, err
		}
	}
	verb := "imported"
	if dry {
		verb = "would import"
	}
	lines = append(lines, fmt.Sprintf("%s: %d new, %d changed", verb, n, c))
	return lines, true, nil
}
