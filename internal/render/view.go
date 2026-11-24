package render

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
)

// EnvFile is one settings file of an environment: its stored layout and the
// values of the resolved namespace, per variable.
type EnvFile struct {
	Layout    Layout
	Variables *Vars
	Notes     map[string]string
	Managed   map[string]string
	Changed   map[string]string
	Refs      map[string]bool // the entry is a KeePass field reference (the value is the resolved one)
	Group     map[string]string
	Vis       map[string]string
	Title     map[string]string
	Scope     map[string]model.ItemKey
	Path      map[string]string
	Res       map[string]*model.Resolved
}

func newEnvFile(l Layout) *EnvFile {
	return &EnvFile{Layout: l, Variables: NewVars(), Notes: map[string]string{}, Managed: map[string]string{}, Changed: map[string]string{}, Refs: map[string]bool{},
		Group: map[string]string{}, Vis: map[string]string{}, Title: map[string]string{}, Scope: map[string]model.ItemKey{}, Path: map[string]string{}, Res: map[string]*model.Resolved{}}
}

// View is the resolved namespace of an environment laid out per settings file.
type View struct {
	Env    map[string]*EnvFile
	Files  map[string]*model.FileEntry
	Errors []model.ResolveError
}

// Rels lists the settings files of the view, sorted.
func (v *View) Rels() []string {
	out := make([]string, 0, len(v.Env))
	for r := range v.Env {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// LayoutOf is the stored layout of a settings file: the blob <stem> of the item.
func LayoutOf(it *model.Item, rel string) (Layout, error) {
	if it == nil {
		return EmptyLayout(), nil
	}
	raw := it.Blobs[StemOf(rel)]
	if len(raw) == 0 {
		return EmptyLayout(), nil
	}
	l, err := ParseLayoutJSON(raw)
	if err != nil {
		return Layout{}, &model.StoreError{Msg: fmt.Sprintf("%s/%s: the layout entry is damaged", it.Name, StemOf(rel))}
	}
	return l, nil
}

// HasLayouts: the settings files the item has a stored layout for.
func (p *Project) HasLayouts(it *model.Item) map[string]bool {
	out := map[string]bool{}
	if it == nil {
		return out
	}
	for stem := range it.Blobs {
		if rel := p.RelOfStem(stem); rel != "" {
			out[rel] = true
		}
	}
	return out
}

// View lays the resolved namespace of env out per settings file. The
// environment's own entries come first, then the linked items in list order.
// For a key in a file the NARROWEST entry wins: an entry of the environment
// narrowed to that file (a block, label file:) > an entry of the environment
// without a narrowing label > the entries of the linked items in list order; an
// EMPTY entry never beats a filled one. With a site the groups limited to other
// sites are left out, the ones limited to this site come first and the site's
// own credentials item comes last; values with references come out expanded
// and Errors lists what could not be resolved (see RequireResolved).
func (p *Project) View(snap *model.Snapshot, env, site string) (*View, error) {
	it := snap.Item(model.SecEnvs, env)
	if it == nil {
		return &View{Env: map[string]*EnvFile{}, Files: map[string]*model.FileEntry{}}, nil
	}
	res := snap.Resolve(model.SecEnvs, env, site, p.SiteBound)
	have := p.HasLayouts(it)
	own := model.ItemKey{Section: model.SecEnvs, Name: env}
	seq := map[model.ItemKey]int{}
	for i, s := range res.Sources {
		seq[s] = i
	}
	rank := func(h *model.Resolved) int {
		if (model.ItemKey{Section: h.Section, Name: h.Item}) == own {
			if p.EntryScope(h.Entry) == "block" {
				return 0
			}
			return 1
		}
		return 2 + seq[model.ItemKey{Section: h.Section, Name: h.Item}]
	}
	linesOf := map[string]map[string]bool{}
	layouts := map[string]Layout{}
	for rel := range have {
		l, err := LayoutOf(it, rel)
		if err != nil {
			return nil, err
		}
		layouts[rel] = l
		ks := map[string]bool{}
		for _, x := range l.Lines {
			if !x.IsLit {
				ks[x.K] = true
			}
		}
		linesOf[rel] = ks
	}
	type ck struct{ rel, key string }
	var order []ck
	cands := map[ck][]*model.Resolved{}
	for _, key := range res.Order {
		for _, h := range res.Holders[key] {
			rels := p.EntryRels(h.Entry, have)
			if (model.ItemKey{Section: h.Section, Name: h.Item}) == own && rank(h) == 1 {
				var narrowed []string
				for _, r := range rels {
					if linesOf[r][key] {
						narrowed = append(narrowed, r)
					}
				}
				if len(narrowed) > 0 {
					rels = narrowed
				}
			}
			for _, rel := range rels {
				k := ck{rel, key}
				if _, ok := cands[k]; !ok {
					order = append(order, k)
				}
				cands[k] = append(cands[k], h)
			}
		}
	}
	out := map[string]*EnvFile{}
	for _, k := range order {
		hs := cands[k]
		best := hs[0]
		for _, h := range hs[1:] {
			if less(h.Entry.Value == "", rank(h), best.Entry.Value == "", rank(best)) {
				best = h
			}
		}
		e := best.Entry
		ef := out[k.rel]
		if ef == nil {
			l, ok := layouts[k.rel]
			if !ok {
				l = EmptyLayout()
			}
			ef = newEnvFile(l)
			out[k.rel] = ef
		}
		ef.Variables.Set(k.key, e.Value)
		ef.Notes[k.key], ef.Managed[k.key], ef.Changed[k.key], ef.Group[k.key] = e.Notes, e.Managed, e.Changed, e.Group
		title := e.Title
		if title == "" {
			title = k.key
		}
		ef.Vis[k.key], ef.Title[k.key], ef.Scope[k.key] = e.Vis, title, model.ItemKey{Section: best.Section, Name: best.Item}
		ef.Path[k.key], ef.Res[k.key] = e.Path, best
		if e.Ref {
			ef.Refs[k.key] = true
		}
	}
	files := map[string]*model.FileEntry{}
	for k, v := range res.Files {
		files[k] = v
	}
	return &View{Env: out, Files: files, Errors: res.Errors}, nil
}

func less(aEmpty bool, aRank int, bEmpty bool, bRank int) bool {
	if aEmpty != bEmpty {
		return !aEmpty
	}
	return aRank < bRank
}

// RequireResolved stops (StoreError) when the view has references that cannot
// be resolved: nothing is rendered from it. The message names every entry and why.
func RequireResolved(v *View) error {
	if len(v.Errors) == 0 {
		return nil
	}
	var parts []string
	for i, e := range v.Errors {
		if i == 10 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s/%s/%s/%s: %s", e.R.Section, e.R.Item, e.R.Entry.Group, e.R.Entry.Key, e.Msg))
	}
	more := ""
	if len(v.Errors) > 10 {
		more = fmt.Sprintf(" (and %d more)", len(v.Errors)-10)
	}
	return &model.StoreError{Msg: "a reference cannot be resolved, nothing is written: " + strings.Join(parts, "; ") + more}
}

// TypeProblem is a filled variable whose value does not fit the type the description declares for it. It names the variable and the rule, never
// the value.
type TypeProblem struct{ File, Name, Rule string }

// Words says the problem in words for a report.
func (t TypeProblem) Words() string {
	switch t.Rule {
	case project.RuleBool:
		return "must be true or false"
	case project.RuleInt:
		return "must be a whole number"
	case project.RuleEmail:
		return "must be an email address"
	case project.RuleURL:
		return "must be a URL with a scheme and a host"
	case project.RuleDomain:
		return "must be a domain name"
	case project.RuleEnum:
		return "must be one of its choices"
	}
	return "does not match its pattern"
}

func (t TypeProblem) String() string { return t.File + "/" + t.Name + " " + t.Words() }

// TypeProblems lists, in file order, the filled variables of the (resolved) view that break the type the description declares. An empty value is
// not set and fits; a reference was resolved by View, so the text it came to is checked.
func (p *Project) TypeProblems(v *View) []TypeProblem {
	var out []TypeProblem
	for _, rel := range v.Rels() {
		ef := v.Env[rel]
		for _, name := range ef.Variables.Order {
			if rule := p.D.ValueProblem(name, ef.Variables.M[name]); rule != "" {
				out = append(out, TypeProblem{rel, name, rule})
			}
		}
	}
	return out
}

// RequireTyped stops (StoreError) when a value does not fit its type: nothing is rendered. The message names the variables and the rules, never a value.
func RequireTyped(problems []TypeProblem) error {
	if len(problems) == 0 {
		return nil
	}
	var parts []string
	for i, t := range problems {
		if i == 10 {
			parts = append(parts, fmt.Sprintf("and %d more", len(problems)-10))
			break
		}
		parts = append(parts, t.String())
	}
	return &model.StoreError{Msg: "a value does not fit its type, nothing is written: " + strings.Join(parts, "; ")}
}

// Positioned is the layout with a line for every manifest key of values that
// the stored layout lacks (a key a linked item brought): it goes right after
// the nearest preceding manifest key that has a line, else before the nearest
// following one, as the manifest orders them. A key the manifest does not know
// is left to RenderEnv, which appends it.
func (p *Project) Positioned(l Layout, values *Vars, rel string) Layout {
	have := map[string]bool{}
	for _, it := range l.Lines {
		if !it.IsLit {
			have[it.K] = true
		}
	}
	var order []string
	for _, r := range p.manifest[rel] {
		order = append(order, r.Key)
	}
	var missing []string
	for _, k := range order {
		if _, ok := values.Get(k); ok && !have[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		return l
	}
	lines := append([]LayoutLine(nil), l.Lines...)
	indexOf := func(key string) int {
		for i, it := range lines {
			if !it.IsLit && it.K == key {
				return i
			}
		}
		return -1
	}
	for _, k := range missing {
		pos := 0
		for i, o := range order {
			if o == k {
				pos = i
				break
			}
		}
		nl := LayoutLine{K: k, S: "a"}
		before := -1
		for i := pos - 1; i >= 0; i-- {
			if ix := indexOf(order[i]); ix >= 0 {
				before = ix
				break
			}
		}
		if before >= 0 {
			lines = append(lines[:before+1], append([]LayoutLine{nl}, lines[before+1:]...)...)
			continue
		}
		for _, n := range order[pos+1:] {
			if ix := indexOf(n); ix >= 0 {
				lines = append(lines[:ix], append([]LayoutLine{nl}, lines[ix:]...)...)
				break
			}
		}
	}
	return Layout{V: l.V, Lines: lines}
}

// Effective: ({name: value}, {name: source}) of one settings file of an
// environment; the source is SourceEnvironment, or section/item of the linked item.
func (p *Project) Effective(snap *model.Snapshot, env, rel, site string) (*Vars, map[string]string, error) {
	v, err := p.View(snap, env, site)
	if err != nil {
		return nil, nil, err
	}
	values, source := NewVars(), map[string]string{}
	if ef := v.Env[rel]; ef != nil {
		for _, name := range ef.Variables.Order {
			values.Set(name, ef.Variables.M[name])
			sc, ok := ef.Scope[name]
			if !ok || sc == (model.ItemKey{Section: model.SecEnvs, Name: env}) {
				source[name] = SourceEnvironment
			} else {
				source[name] = sc.String()
			}
		}
	}
	return values, source, nil
}

// Settings are the values of the environment's general settings file in the vault ({} when it has none; for a pair, with the groups of that
// site); an empty value is as good as none.
func (p *Project) Settings(snap *model.Snapshot, env, site string) (map[string]string, error) {
	vals, _, err := p.Effective(snap, env, p.Conf(), site)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, k := range vals.Order {
		if vals.M[k] != "" {
			out[k] = vals.M[k]
		}
	}
	return out, nil
}

// EnvNames lists the live environments, sorted.
func EnvNames(snap *model.Snapshot) []string {
	var out []string
	for _, it := range snap.All() {
		if it.Section == model.SecEnvs && it.State != model.StateRetired {
			out = append(out, it.Name)
		}
	}
	sort.Strings(out)
	return out
}

// AllSettings: {env: values} for every environment that has settings in the vault.
func (p *Project) AllSettings(snap *model.Snapshot) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for _, n := range EnvNames(snap) {
		s, err := p.Settings(snap, n, "")
		if err != nil {
			return nil, err
		}
		if len(s) > 0 {
			out[n] = s
		}
	}
	return out, nil
}

// Holds: the environment has entries or files in the vault.
func Holds(snap *model.Snapshot, env string) bool {
	it := snap.Item(model.SecEnvs, env)
	return it != nil && (len(it.Entries) > 0 || len(it.Files) > 0)
}

// RenderedFile is a file of the rendered tree.
type RenderedFile struct {
	Rel  string
	Mode int
	Data []byte
}

// Render is the tree the scripts expect for env (without
// the disk): a settings file is its stored layout with the values of the
// resolved namespace; the files come as stored. withConf includes
// the general settings file. A reference that does not resolve stops it. Sorted by path:
// settings files first, then the files.
func (p *Project) Render(snap *model.Snapshot, env, site string, withConf bool) ([]RenderedFile, error) {
	d, err := p.View(snap, env, site)
	if err != nil {
		return nil, err
	}
	if err := RequireResolved(d); err != nil {
		return nil, err
	}
	if err := RequireTyped(p.TypeProblems(d)); err != nil {
		return nil, err
	}
	var out []RenderedFile
	for _, rel := range d.Rels() {
		if rel == p.Conf() && !withConf {
			continue
		}
		ef := d.Env[rel]
		mode := 0o600
		if r := p.EnvRule(rel); r != nil {
			mode = r.Mode
		}
		out = append(out, RenderedFile{rel, mode, []byte(RenderEnv(p.Positioned(ef.Layout, ef.Variables, rel), ef.Variables))})
	}
	rels := make([]string, 0, len(d.Files))
	for rel := range d.Files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		fe := d.Files[rel]
		mode := fe.Mode
		if r := p.FileRule(rel); r != nil {
			mode = r.Mode
		}
		out = append(out, RenderedFile{rel, mode, fe.Data})
	}
	return out, nil
}

// ---- checklist

// CreateSpec describes the entry the screen can make for a missing key.
type CreateSpec struct {
	Key, Group, Description, Visibility string
	Labels                              []string
}

// ChecklistRow is a manifest key with its state.
type ChecklistRow struct {
	Key, File, Group string
	State            string // present | empty | missing | broken
	Required         bool
	Hint             string
	Managed          string
	Source           string
	Section, Item    string
	GroupIn          string
	Create           *CreateSpec
}

// WarnMsg is a translatable warning.
type WarnMsg struct {
	Code   string
	Params map[string]string
}

// Checklist is what deploy needs from an environment.
type Checklist struct {
	Environment, Provider string
	Needed                int
	Rows                  []ChecklistRow
	Warnings              []string
	WarningMsgs           []WarnMsg
}

// checklistRels: the settings files deploy reads (Uses.FileUnused); a file read in part is kept for the keys it reads (the rows are narrowed
// by Uses.KeyUnused).
func (p *Project) checklistRels(u Uses) []string {
	var out []string
	for _, r := range p.D.Files {
		if _, ok := p.manifest[r]; ok {
			if why := u.FileUnused(r); why == "" || why == UnusedPartly {
				out = append(out, r)
			}
		}
	}
	return out
}

// Checklist: for environment env, the manifest keys of the files it uses
// (Places.FileUnused) with their state (present, empty, missing), the hint text
// of the manifest and where an existing entry lives. Required: NeededNow (the
// template says REQUIRED:, or NEEDED FOR: with a sibling of the feature set) and
// managed by the owner. Needed = the required ones that are not present.
func (p *Project) Checklist(snap *model.Snapshot, env, site string) (*Checklist, error) {
	settings, err := p.Settings(snap, env, site)
	if err != nil {
		return nil, err
	}
	provider := p.ProviderName(snap, env)
	res := snap.Resolve(model.SecEnvs, env, site, nil)
	v, err := p.View(snap, env, site)
	if err != nil {
		return nil, err
	}
	type fk struct{ rel, name string }
	found := map[fk]*model.Resolved{}
	for rel, ef := range v.Env {
		for name, r := range ef.Res {
			found[fk{rel, name}] = r
		}
	}
	c := &Checklist{Environment: env, Provider: provider}
	uses := p.UsesFrom(settings)
	for _, rel := range p.checklistRels(uses) {
		isSet := func(k string) bool { r := found[fk{rel, k}]; return r != nil && r.Entry.Value != "" }
		for _, row := range p.manifest[rel] {
			if uses.KeyUnused(rel, row.Key) != "" {
				continue
			}
			r := found[fk{rel, row.Key}]
			managed := p.VarManagedIn(rel, row.Key)
			state := "missing"
			if r != nil {
				state = "empty"
				if r.Entry.Value != "" {
					state = "present"
				}
			}
			grp := GroupOf(rel)
			need := p.NeededNow(rel, row.Key, isSet) || p.RequiredNow(rel, row.Key, uses.Get)
			cr := ChecklistRow{Key: row.Key, File: rel, Group: grp, State: state, Required: need && managed == model.ManagedOwner, Hint: row.Comment, Managed: managed}
			if r != nil {
				cr.Managed, cr.Source, cr.Section, cr.Item, cr.GroupIn = r.Entry.Managed, r.Source(), r.Section, r.Item, r.Entry.Group
			}
			if r == nil && managed == model.ManagedOwner {
				vis := model.VisPlain
				if row.Secret {
					vis = model.VisSecret
				}
				cr.Create = &CreateSpec{Key: row.Key, Group: grp, Labels: LabelsFor(rel), Description: row.Comment, Visibility: vis}
			}
			c.Rows = append(c.Rows, cr)
		}
	}
	seen := map[string]bool{}
	for _, e := range res.Errors {
		if seen[e.R.Entry.Path] {
			continue
		}
		seen[e.R.Entry.Path] = true
		c.Rows = append(c.Rows, ChecklistRow{Key: e.R.Entry.Key, Group: e.R.Entry.Group, State: "broken", Required: true, Hint: e.Msg, Managed: e.R.Entry.Managed,
			Source: e.R.Source(), Section: e.R.Section, Item: e.R.Item, GroupIn: e.R.Entry.Group})
	}
	for _, r := range c.Rows {
		if r.Required && r.State != "present" {
			c.Needed++
		}
	}
	return c, nil
}

// ---- local development files of the apps

// AppExample is the example file of an app when the description names none.
const AppExample = ".env.example"

var appVarRE = regexp.MustCompile(`^(#\s*)?([A-Z][A-Z0-9_]*)=(.*)$`)

// AppVar is a row of an app's example file.
type AppVar struct {
	Name    string
	Active  bool
	Example string
}

// AppVariables lists the rows (active or commented) of an app's example file that the app takes: a name with the app's prefix, one of its
// plain names or one of its aliases.
func AppVariables(a *project.App, exampleText string) []AppVar {
	var found []AppVar
	seen := map[string]bool{}
	for _, line := range strings.Split(exampleText, "\n") {
		m := appVarRE.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil || seen[m[2]] {
			continue
		}
		_, alias := a.Aliases[m[2]]
		if (a.Prefix != "" && strings.HasPrefix(m[2], a.Prefix)) || contains(a.Plain, m[2]) || alias {
			seen[m[2]] = true
			found = append(found, AppVar{m[2], m[1] == "", strings.TrimSpace(m[3])})
		}
	}
	return found
}

// AppReport is a (name, source) pair: names and sources only are ever shown.
type AppReport struct{ Name, Source string }

// AppFileText is the settings file an app needs for local development, from the settings file the description feeds it from, and the report.
func (p *Project) AppFileText(snap *model.Snapshot, env string, a *project.App, exampleText, site string) (string, []AppReport, error) {
	v, err := p.View(snap, env, site)
	if err != nil {
		return "", nil, err
	}
	if err := RequireResolved(v); err != nil {
		return "", nil, err
	}
	values, _, err := p.Effective(snap, env, a.From, site)
	if err != nil {
		return "", nil, err
	}
	var report []AppReport
	if a.All {
		var b strings.Builder
		for _, k := range values.Order {
			if val := values.M[k]; val != "" {
				b.WriteString(k + "=" + val + "\n")
				report = append(report, AppReport{k, "vault"})
			}
		}
		return b.String(), report, nil
	}
	var lines []string
	for _, av := range AppVariables(a, exampleText) {
		keys := a.Aliases[av.Name]
		if keys == nil {
			if a.Prefix != "" && strings.HasPrefix(av.Name, a.Prefix) {
				keys = []string{strings.TrimPrefix(av.Name, a.Prefix)}
			} else {
				keys = []string{av.Name}
			}
		}
		key := ""
		for _, k := range keys {
			if values.M[k] != "" {
				key = k
				break
			}
		}
		switch {
		case key != "":
			lines = append(lines, av.Name+"="+values.M[key])
			report = append(report, AppReport{av.Name, "vault " + key})
		case av.Active:
			lines = append(lines, av.Name+"="+av.Example)
			src := "example value"
			if av.Example == "" {
				src = "empty"
			}
			report = append(report, AppReport{av.Name, src})
		}
	}
	return strings.Join(lines, "\n") + "\n", report, nil
}

// ---- the audits (names only, never a value)

// VisibilityRow is a row of the visibility audit.
type VisibilityRow struct {
	Item, Group, Key, Current, Proposed, Verdict string
	Entry                                        *model.Entry
}

// VisibilityRows is the audit of the visibility of the OWNER variables an
// environment sees (its own and its linked items'). Verdict: change, kept-owner,
// kept-differs, kept-sealed. Only entries whose current and
// proposed visibility differ are listed. Values are never read.
func (p *Project) VisibilityRows(snap *model.Snapshot, env string) ([]VisibilityRow, error) {
	it := snap.Item(model.SecEnvs, env)
	if it == nil {
		return nil, &model.StoreError{Msg: fmt.Sprintf("the vault has no environment '%s'", env)}
	}
	var rows []VisibilityRow
	for _, item := range append([]*model.Item{it}, snap.Linked(model.SecEnvs, env)...) {
		for _, e := range item.Entries {
			if e.Managed != model.ManagedOwner {
				continue
			}
			want := p.ProposedVisibility(e.Key)
			if e.Vis == want {
				continue
			}
			var verdict string
			switch {
			case e.Vis == model.VisSealed:
				verdict = "kept-sealed"
			case e.VisBy == model.ManagedOwner:
				verdict = "kept-owner"
			case e.Vis != p.LegacyVisibility(e.Key):
				verdict = "kept-differs"
			default:
				verdict = "change"
			}
			rows = append(rows, VisibilityRow{item.Ref(), e.Group, e.Key, e.Vis, want, verdict, e})
		}
	}
	return rows, nil
}

// ViewRow is a row of the names-only table of `view`.
type ViewRow struct {
	File, Name, Source, Managed, State, Changed, Notes string
	value                                              string
	need                                               bool
}

// Missing: the row is an entry the environment needs and that is empty.
func (r ViewRow) Missing() bool { return r.need && r.value == "" }

// rowNeeded: NeededNow for a key of the manifest; a key it does not list is needed when its own notes say REQUIRED: (Needed).
func (p *Project) rowNeeded(rel, key, notes string, isSet func(string) bool) bool {
	for _, r := range p.manifest[rel] {
		if r.Key == key {
			return p.NeededNow(rel, key, isSet)
		}
	}
	return Needed(notes, "")
}

// ViewRows lists the variables of one environment (linked items included), or
// of one item when item is non-nil.
func (p *Project) ViewRows(snap *model.Snapshot, env string, item *model.ItemKey, site string) ([]ViewRow, error) {
	var rows []ViewRow
	if item != nil {
		if it := snap.Item(item.Section, item.Name); it != nil {
			isSet := func(k string) bool {
				for _, o := range it.Entries {
					if o.Key == k && o.Value != "" {
						return true
					}
				}
				return false
			}
			for _, e := range it.Entries {
				rel := p.EntryRel(e)
				need := p.rowNeeded(rel, e.Key, e.Notes, isSet)
				if rel == "" {
					rel = "stored/" + e.Group
				}
				rows = append(rows, ViewRow{rel, e.Key, item.String(), e.Managed, stateOf(e.Value), e.Changed, e.Notes, e.Value, need})
			}
		}
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].File != rows[j].File {
				return rows[i].File < rows[j].File
			}
			return rows[i].Name < rows[j].Name
		})
		return rows, nil
	}
	d, err := p.View(snap, env, site)
	if err != nil {
		return nil, err
	}
	uses := p.UsesOf(snap, env)
	for _, rel := range d.Rels() {
		ef := d.Env[rel]
		isSet := func(k string) bool { return ef.Variables.M[k] != "" }
		for _, name := range ef.Variables.Order {
			val := ef.Variables.M[name]
			sc, ok := ef.Scope[name]
			src := SourceEnvironment
			if ok && sc != (model.ItemKey{Section: model.SecEnvs, Name: env}) {
				src = sc.String()
			}
			managed := ef.Managed[name]
			if managed == "" {
				managed = model.ManagedOwner
			}
			need := uses.KeyUnused(rel, name) == "" && (p.rowNeeded(rel, name, ef.Notes[name], isSet) || p.RequiredNow(rel, name, uses.Get))
			rows = append(rows, ViewRow{rel, name, src, managed, stateOf(val), ef.Changed[name], ef.Notes[name], val, need})
		}
	}
	return rows, nil
}

func stateOf(v string) string {
	if v == "" {
		return "empty"
	}
	return "set"
}

// Status is the drift/status summary of an environment in the vault (names and
// counts only, never a value).
type Status struct {
	Settings, Variables, OtherFiles, Retired int
	Uses                                     []string
	BrokenLinks                              []string
	Shadowed                                 []string
	TypeProblems                             []TypeProblem
	Files                                    []StatusFile
}

// StatusFile is one settings file of the status.
type StatusFile struct {
	Rel       string
	Variables int
	FromLinks int
	Empty     []string
	Vars      []StatusVar
}

// StatusVar is a variable with its source and who manages it.
type StatusVar struct{ Name, Source, Managed string }

// StatusOf computes what `status --env E` shows from the vault (the part that
// needs no disk).
func (p *Project) StatusOf(snap *model.Snapshot, env, site string) (*Status, error) {
	d, err := p.View(snap, env, site)
	if err != nil {
		return nil, err
	}
	st := &Status{Settings: len(d.Env), OtherFiles: len(d.Files), TypeProblems: p.TypeProblems(d)}
	if it := snap.Item(model.SecEnvs, env); it != nil {
		st.Retired = len(it.Retired)
	}
	for _, l := range snap.Linked(model.SecEnvs, env) {
		st.Uses = append(st.Uses, l.Ref())
	}
	for _, b := range snap.BrokenLinks(model.SecEnvs, env) {
		st.BrokenLinks = append(st.BrokenLinks, b.String())
	}
	for _, pr := range snap.Resolve(model.SecEnvs, env, "", nil).Shadowed {
		st.Shadowed = append(st.Shadowed, fmt.Sprintf("%s/%s/%s (the value of %s is used)", pr.Loser.Source(), pr.Loser.Entry.Group, pr.Loser.Entry.Key, pr.Winner.Source()))
	}
	for _, rel := range d.Rels() {
		ef := d.Env[rel]
		sf := StatusFile{Rel: rel, Variables: ef.Variables.Len()}
		st.Variables += sf.Variables
		for _, n := range ef.Variables.Order {
			src := SourceEnvironment
			if sc := ef.Scope[n]; sc != (model.ItemKey{Section: model.SecEnvs, Name: env}) {
				src = sc.Section + "/" + sc.Name
				sf.FromLinks++
			}
			if ef.Variables.M[n] == "" {
				sf.Empty = append(sf.Empty, n)
			}
			m := ef.Managed[n]
			if m == "" {
				m = model.ManagedOwner
			}
			sf.Vars = append(sf.Vars, StatusVar{n, src, m})
		}
		sort.Strings(sf.Empty)
		st.Files = append(st.Files, sf)
	}
	return st, nil
}

// Drift compares the rendered tree of a vault environment with files on disk
// (rel -> sha256 of what is there): the names that differ, are missing on disk
// or exist only on disk. It reads no value.
func Drift(rendered []RenderedFile, onDisk map[string]string) (changed, missing, extra []string) {
	want := map[string]bool{}
	for _, f := range rendered {
		want[f.Rel] = true
		got, ok := onDisk[f.Rel]
		switch {
		case !ok:
			missing = append(missing, f.Rel)
		case got != model.SHA256(f.Data):
			changed = append(changed, f.Rel)
		}
	}
	for rel := range onDisk {
		if !want[rel] {
			extra = append(extra, rel)
		}
	}
	sort.Strings(changed)
	sort.Strings(missing)
	sort.Strings(extra)
	return
}
