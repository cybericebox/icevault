package model

import (
	"fmt"
	"sort"
	"strings"
)

// ReferencesIn lists [(name, key)] a value refers to (an escaped "$${{" is text).
func ReferencesIn(value string) [][2]string {
	var out [][2]string
	for _, m := range ReferenceRE.FindAllStringSubmatch(value, -1) {
		if m[1] == "" {
			out = append(out, [2]string{m[2], m[3]})
		}
	}
	return out
}

type target struct {
	e   *Entry
	msg string
}

func (s *Snapshot) target(name, key, site string) target {
	type holder struct {
		it *Item
		e  *Entry
	}
	var holders []holder
	var what string
	if name == GlobalRef {
		for _, it := range s.All() {
			if it.Section == SecGlobal && it.State != StateRetired {
				for _, e := range it.Entries {
					if e.Key == key {
						holders = append(holders, holder{it, e})
					}
				}
			}
		}
		what = GlobalRef + "." + key
	} else {
		it := s.Items[ItemKey{SecExternal, name}]
		if it == nil || it.State == StateRetired {
			return target{msg: fmt.Sprintf("no external system '%s' (reference %s.%s)", name, name, key)}
		}
		if site != "" && len(it.OnlySites) > 0 && !contains(it.OnlySites, site) {
			return target{msg: fmt.Sprintf("the external system '%s' is not allowed on site '%s' (only on %s)", name, site, strings.Join(it.OnlySites, ", "))}
		}
		for _, e := range it.Entries {
			if e.Key == key {
				holders = append(holders, holder{it, e})
			}
		}
		what = name + "." + key
	}
	var ok []holder
	for _, h := range holders {
		if a, _ := s.GroupApplies(h.it.Section, h.it.Name, h.e.Group, site); a {
			ok = append(ok, h)
		}
	}
	switch {
	case len(ok) == 0:
		return target{msg: "no value " + what}
	case len(ok) > 1:
		return target{msg: fmt.Sprintf("%s exists %d times: a key is unique there", what, len(ok))}
	}
	return target{e: ok[0].e}
}

// Target is the Entry a reference <name>.<key> points to for a site, or a message when it cannot be used.
func (s *Snapshot) Target(name, key, site string) (*Entry, string) {
	t := s.target(name, key, site)
	return t.e, t.msg
}

// Expand returns the value with its references replaced, the visibility (the
// strictest of the value's own and every target's) and the errors. A reference
// that cannot be resolved gives an error and an empty text; a cycle names its chain.
func (s *Snapshot) Expand(value, vis, site string) (string, string, []string) {
	return s.expand(value, vis, site, nil)
}

func (s *Snapshot) expand(value, vis, site string, stack []string) (string, string, []string) {
	var out strings.Builder
	var errs []string
	pos := 0
	for _, loc := range ReferenceRE.FindAllStringSubmatchIndex(value, -1) {
		out.WriteString(value[pos:loc[0]])
		pos = loc[1]
		whole := value[loc[0]:loc[1]]
		if loc[2] >= 0 { // escaped: "$${{ ... }}" is the literal "${{ ... }}"
			out.WriteString(whole[1:])
			continue
		}
		name, key := value[loc[4]:loc[5]], value[loc[6]:loc[7]]
		ref := name + "." + key
		chain := func() string { return strings.Join(append(append([]string{}, stack...), ref), " -> ") }
		if contains(stack, ref) {
			errs = append(errs, "cycle: "+chain())
			continue
		}
		if len(stack) >= MaxRefDepth {
			errs = append(errs, fmt.Sprintf("references go deeper than %d: %s", MaxRefDepth, chain()))
			continue
		}
		t := s.target(name, key, site)
		if t.e == nil {
			errs = append(errs, t.msg)
			continue
		}
		text, tvis, e2 := s.expand(t.e.Value, t.e.Vis, site, append(append([]string{}, stack...), ref))
		errs = append(errs, e2...)
		if VisRank(tvis) > VisRank(vis) {
			vis = tvis
		}
		out.WriteString(text)
	}
	out.WriteString(value[pos:])
	return out.String(), vis, errs
}

// Referencing lists the (item, entry) whose value refers to <name>.<key>.
func (s *Snapshot) Referencing(name, key string) []Holder {
	var out []Holder
	for _, it := range s.All() {
		for _, e := range it.Entries {
			for _, r := range ReferencesIn(e.Value) {
				if r[0] == name && r[1] == key {
					out = append(out, Holder{it, e})
					break
				}
			}
		}
	}
	return out
}

// Holder pairs an item with one of its entries.
type Holder struct {
	Item  *Item
	Entry *Entry
}

// Resolved is an entry with the item it came from.
type Resolved struct {
	Entry         *Entry
	Section, Item string
}

func (r *Resolved) Source() string { return r.Section + "/" + r.Item }

// Pair is (winner, loser).
type Pair struct{ Winner, Loser *Resolved }

// ShadowedFile names a file that two scopes both hold with different content.
type ShadowedFile struct {
	Rel          string
	Winner, Lose ItemKey
}

// ResolveError is a reference that cannot be resolved.
type ResolveError struct {
	R   *Resolved
	Msg string
}

// Resolution is the merged namespace of one environment. For each key the
// entries of ONE item win: the first item in precedence order that has a value
// for it, and when every holder is empty the first holder. An empty entry never
// shadows a filled one.
type Resolution struct {
	Sources       []ItemKey
	ByKey         map[string][]*Resolved
	Holders       map[string][]*Resolved
	Order         []string
	Shadowed      []Pair // two non-empty entries with different values
	Emptied       []Pair // an empty entry that a filled one in another item stands in for
	Files         map[string]*FileEntry
	ShadowedFiles []ShadowedFile
	Errors        []ResolveError
}

// Get is the winning entry of a key; with several (one key in several groups of
// the winning item) the first that carries label, else the first.
func (r *Resolution) Get(key, label string) *Resolved {
	rs := r.ByKey[key]
	if label != "" {
		for _, x := range rs {
			if contains(x.Entry.Labels, label) {
				return x
			}
		}
	}
	if len(rs) > 0 {
		return rs[0]
	}
	return nil
}

// Entries lists the winning entries in key order.
func (r *Resolution) Entries() []*Resolved {
	var out []*Resolved
	for _, k := range r.Order {
		out = append(out, r.ByKey[k]...)
	}
	return out
}

// Resolve is the merged namespace of an item (an environment) for a site ("" =
// none): its own entries, then every linked item in order, then the site's own
// credentials item. With a site, a group limited to other sites is left out and
// a group limited to this site comes before the unlimited ones. Values with
// references come out expanded. Files kept under sites/<site>/<rel> are the file
// <rel> of that pair and beat the environment's own; siteBound(rel) says which
// files belong to one site (hidden at environment level once there are two sites).
func (s *Snapshot) Resolve(section, name, site string, siteBound func(rel string) bool) *Resolution {
	res := &Resolution{ByKey: map[string][]*Resolved{}, Holders: map[string][]*Resolved{}, Files: map[string]*FileEntry{}}
	it := s.Items[ItemKey{section, name}]
	if it == nil {
		return res
	}
	files := map[string][]*FileEntry{}
	var fileOrder []string
	addFile := func(rel string, fe *FileEntry, front bool) {
		if _, ok := files[rel]; !ok {
			fileOrder = append(fileOrder, rel)
		}
		if front {
			files[rel] = append([]*FileEntry{fe}, files[rel]...)
		} else {
			files[rel] = append(files[rel], fe)
		}
	}
	sources := append([]*Item{it}, s.Linked(section, name)...)
	if site != "" {
		if si := s.Items[ItemKey{SecSites, site}]; si != nil && si.State != StateRetired {
			found := false
			for _, x := range sources {
				found = found || x == si
			}
			if !found {
				sources = append(sources, si)
			}
		}
	}
	for _, src := range sources {
		if site != "" && src != it && src.Section != SecSites && len(src.OnlySites) > 0 && !contains(src.OnlySites, site) {
			continue
		}
		res.Sources = append(res.Sources, src.Key())
		type ranked struct {
			rank int
			e    *Entry
		}
		var rk []ranked
		for _, e := range src.Entries {
			ok, restricted := s.GroupApplies(src.Section, src.Name, e.Group, site)
			if ok {
				r := 1
				if restricted && site != "" {
					r = 0
				}
				rk = append(rk, ranked{r, e})
			}
		}
		sort.SliceStable(rk, func(i, j int) bool { return rk[i].rank < rk[j].rank })
		for _, x := range rk {
			if _, ok := res.Holders[x.e.Key]; !ok {
				res.Order = append(res.Order, x.e.Key)
			}
			res.Holders[x.e.Key] = append(res.Holders[x.e.Key], &Resolved{x.e, src.Section, src.Name})
		}
		rels := make([]string, 0, len(src.Files))
		for rel := range src.Files {
			rels = append(rels, rel)
		}
		sort.Strings(rels)
		for _, rel := range rels {
			fe := src.Files[rel]
			if strings.HasPrefix(rel, "sites/") {
				parts := strings.SplitN(rel, "/", 3)
				if site == "" || len(parts) < 3 || parts[1] != site {
					continue
				}
				addFile(parts[2], fe, true)
				continue
			}
			if site != "" && siteBound != nil && siteBound(rel) && len(s.SitesOf(name)) > 1 && src == it {
				continue
			}
			addFile(rel, fe, false)
		}
	}
	same := func(a *Resolved, sec, item string) bool { return a.Section == sec && a.Item == item }
	for _, key := range res.Order {
		hs := res.Holders[key]
		win := hs[0]
		for _, h := range hs {
			if h.Entry.Value != "" {
				win = h
				break
			}
		}
		var mine []*Resolved
		for _, h := range hs {
			if same(h, win.Section, win.Item) {
				mine = append(mine, h)
			}
		}
		res.ByKey[key] = mine
		lead := mine[0]
		for _, h := range mine {
			if h.Entry.Value != "" {
				lead = h
				break
			}
		}
		for _, h := range hs {
			if same(h, win.Section, win.Item) {
				continue
			}
			if h.Entry.Value == "" && lead.Entry.Value != "" {
				res.Emptied = append(res.Emptied, Pair{lead, h})
			} else if h.Entry.Value != "" && lead.Entry.Value != "" && h.Entry.Value != lead.Entry.Value {
				res.Shadowed = append(res.Shadowed, Pair{lead, h})
			}
		}
	}
	for _, rel := range fileOrder {
		fes := files[rel]
		win := fes[0]
		for _, f := range fes {
			if len(f.Data) > 0 {
				win = f
				break
			}
		}
		res.Files[rel] = win
		for _, f := range fes {
			if f != win && len(f.Data) > 0 && len(win.Data) > 0 && f.Sha != win.Sha {
				res.ShadowedFiles = append(res.ShadowedFiles, ShadowedFile{rel, win.Scope, f.Scope})
			}
		}
	}
	done := map[*Resolved]*Resolved{}
	effective := func(r *Resolved) *Resolved {
		if !strings.Contains(r.Entry.Value, "${{") {
			return r
		}
		if n, ok := done[r]; ok {
			return n
		}
		text, vis, errs := s.Expand(r.Entry.Value, r.Entry.Vis, site)
		cp := *r.Entry
		raw := r.Entry.Value
		cp.Value, cp.Vis, cp.Raw = text, vis, &raw
		n := &Resolved{&cp, r.Section, r.Item}
		for _, m := range errs {
			res.Errors = append(res.Errors, ResolveError{n, m})
		}
		done[r] = n
		return n
	}
	// keys in order so the errors come out deterministically
	for _, key := range res.Order {
		hs := res.Holders[key]
		for i, r := range hs {
			hs[i] = effective(r)
		}
	}
	for _, key := range res.Order {
		rs := res.ByKey[key]
		for i, r := range rs {
			rs[i] = effective(r)
		}
	}
	return res
}
