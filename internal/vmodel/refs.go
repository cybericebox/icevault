package vmodel

import (
	"fmt"
	"strings"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
)

// References in the values of the model: ${{ shared.KEY }} (a shared variable), ${{ <system>.KEY }} (a field of a connection the description serves
// under that name) and ${{ self.KEY }} (a variable of the environment the value lives in). They are resolved by internal/model on the projection of
// the environment (Compat), the one resolution the export, the checklist and the preview of the window share. A shared value or a connection field
// has no environment: self is an error there.

// Place says where a variable lives: Env nil is the shared level; Site and Product narrow it down inside an environment (Kind is the site kind of a
// product's subgroup).
type Place struct {
	Env     *Environment
	Site    *Site
	Product *Product
	Kind    string
}

// previewMark is the description of the draft variable of a preview: it is found again by it after the resolution.
const previewMark = "\x00icevault-preview"

func (p Place) get() []*Var {
	switch {
	case p.Env == nil:
		return nil
	case p.Product != nil && p.Kind != "":
		return p.Product.Sub[p.Kind]
	case p.Product != nil:
		return p.Product.Vars
	case p.Site != nil:
		return p.Site.Vars
	}
	return p.Env.General
}

func (p Place) set(l []*Var) {
	switch {
	case p.Product != nil && p.Kind != "":
		if l == nil {
			delete(p.Product.Sub, p.Kind)
		} else {
			p.Product.Sub[p.Kind] = l
		}
	case p.Product != nil:
		p.Product.Vars = l
	case p.Site != nil:
		p.Site.Vars = l
	default:
		p.Env.General = l
	}
}

// siteOf is the site the pair of a value is made with: its own site, its product's, or the only one of the environment.
func (p Place) siteOf() *Site {
	switch {
	case p.Site != nil:
		return p.Site
	case p.Product != nil && p.Product.Site != nil:
		return p.Product.Site
	case len(p.Env.Sites) == 1:
		return p.Env.Sites[0]
	}
	return nil
}

func descOf(d *project.Description) *project.Description {
	if d == nil {
		return &project.Description{}
	}
	return d
}

// projectEnv lays the environment out for one site (an environment with two sites is projected once per site) and calls fn on the result;
// draft, when given, stands in for the variable of that key in place (a new variable when there is none). Everything is put back after fn.
func projectEnv(m *Vault, d *project.Description, e *Environment, site *Site, draft *Var, place Place, fn func(cs *CompatSnapshot)) {
	oldSites := e.Sites
	if len(e.Sites) > 1 || (site == nil && len(e.Sites) == 1) {
		e.Sites = nil
		if site != nil {
			e.Sites = []*Site{site}
		}
	}
	var oldList []*Var
	if draft != nil {
		place.Env = e
		oldList = place.get()
		l := make([]*Var, 0, len(oldList)+1)
		replaced := false
		for _, x := range oldList {
			if x.Key == draft.Key {
				l, replaced = append(l, draft), true
				continue
			}
			l = append(l, x)
		}
		if !replaced {
			l = append(l, draft)
		}
		if place.Product != nil && place.Kind != "" && place.Product.Sub == nil {
			place.Product.Sub = map[string][]*Var{}
		}
		place.set(l)
	}
	defer func() {
		e.Sites = oldSites
		if draft != nil {
			place.set(oldList)
		}
	}()
	cs := CompatWith(&Vault{Shared: m.Shared, Connections: m.Connections, Envs: []*Environment{e}}, descOf(d), CompatOptions{})
	fn(cs)
}

// RefInfo is one reference of a value: the system it names (self, shared or a served connection), the key, and whether it resolves.
type RefInfo struct {
	System, Key string
	OK          bool
	Why         string // the first error that names the reference
}

// Preview is what a value with references comes to: its resolved text (to be shown only when Vis is plain), the strictest visibility, the
// references with their state, the errors, and the references that made the visibility stricter than the value's own.
type Preview struct {
	Text    string
	Vis     string
	Refs    []RefInfo
	Errors  []string
	Because []string
}

func refInfos(value string, errs []string) []RefInfo {
	var out []RefInfo
	for _, r := range model.ReferencesIn(value) {
		ref := r[0] + "." + r[1]
		info := RefInfo{r[0], r[1], true, ""}
		for _, e := range errs {
			if strings.Contains(e, ref) && info.OK {
				info.OK, info.Why = false, e
			}
		}
		out = append(out, info)
	}
	return out
}

// PreviewValue resolves a value as it would be if it were the variable key at place with visibility vis. Nothing is changed in m.
func (m *Vault) PreviewValue(d *project.Description, p Place, key, value, vis string) Preview {
	pv := m.expand(d, p, key, value, vis)
	if pv.Vis != VisPlain { // a secret or sealed result is never handed out: the page shows the text only when it is plain
		pv.Text = ""
	}
	return pv
}

// expand is PreviewValue with the text kept whatever its visibility (the export needs it).
func (m *Vault) expand(d *project.Description, p Place, key, value, vis string) Preview {
	vis = orDefault(vis, VisSecret)
	pv := Preview{Text: value, Vis: vis}
	if !strings.Contains(value, "${{") {
		return pv
	}
	var snap *model.Snapshot
	var res *model.Resolution
	var errs []string
	if p.Env == nil { // shared: no environment
		snap = CompatWith(&Vault{Shared: m.Shared, Connections: m.Connections}, descOf(d), CompatOptions{}).Snap
		pv.Text, pv.Vis, errs = snap.Expand(value, vis, "")
		if model.VisRank(vis) > model.VisRank(pv.Vis) {
			pv.Vis = vis
		}
	} else {
		draft := &Var{Key: key, Value: value, Vis: vis, Managed: ManagedOwner, Description: previewMark}
		projectEnv(m, d, p.Env, p.siteOf(), draft, p, func(cs *CompatSnapshot) {
			snap = cs.Snap
			res = snap.Resolve(model.SecEnvs, p.Env.Name, "", nil)
			for _, h := range res.Holders[key] {
				if h.Entry.Description != previewMark {
					continue
				}
				pv.Text, pv.Vis = h.Entry.Value, h.Entry.Vis
				for _, re := range res.Errors {
					if re.R == h {
						errs = append(errs, re.Msg)
					}
				}
			}
		})
	}
	pv.Errors, pv.Refs = errs, refInfos(value, errs)
	for _, r := range pv.Refs {
		if !r.OK {
			continue
		}
		tv := ""
		if r.System == model.SelfRef {
			if res != nil {
				if rs := res.ByKey[r.Key]; len(rs) == 1 {
					tv = rs[0].Entry.Vis
				}
			}
		} else if snap != nil {
			if e, _ := snap.Target(r.System, r.Key, ""); e != nil {
				tv = e.Vis
			}
		}
		if model.VisRank(tv) > model.VisRank(vis) {
			pv.Because = append(pv.Because, r.System+"."+r.Key)
		}
	}
	if len(errs) > 0 {
		pv.Text = ""
	}
	return pv
}

// RefTarget is a variable a reference can point to, with no value.
type RefTarget struct {
	System, Key, Title, Description string
	Vis                             string
}

// RefTargets lists what a value at place can refer to: the variables of its environment (self), the shared variables and the served connections.
func (m *Vault) RefTargets(d *project.Description, p Place) []RefTarget {
	var out []RefTarget
	seen := map[string]bool{}
	add := func(t RefTarget) {
		if !seen[t.System+"."+t.Key] {
			seen[t.System+"."+t.Key] = true
			out = append(out, t)
		}
	}
	if p.Env != nil {
		projectEnv(m, d, p.Env, p.siteOf(), nil, p, func(cs *CompatSnapshot) {
			if it := cs.Snap.Items[model.ItemKey{Section: model.SecEnvs, Name: p.Env.Name}]; it != nil {
				for _, en := range it.Entries {
					add(RefTarget{model.SelfRef, en.Key, "", en.Description, en.Vis})
				}
			}
		})
	}
	for _, x := range m.Shared {
		add(RefTarget{model.GlobalRef, x.Key, "", x.Description, orDefault(x.Vis, VisSecret)})
	}
	cs := CompatWith(&Vault{Shared: m.Shared, Connections: m.Connections}, descOf(d), CompatOptions{})
	for _, it := range cs.Snap.All() {
		if it.Section != model.SecExternal {
			continue
		}
		for _, en := range it.Entries {
			add(RefTarget{it.Name, en.Key, it.Title, en.Description, en.Vis})
		}
	}
	return out
}

// Broken is a reference of a variable that does not resolve: where the variable is (general, site or product, with the name of the site or
// product), its key and the reason.
type Broken struct {
	Where, Name, Key, Msg string
}

// BrokenRefs lists the references of an environment that do not resolve, for every site (the pair of the environment and the site).
func (m *Vault) BrokenRefs(d *project.Description, e *Environment) []Broken {
	var out []Broken
	seen := map[string]bool{}
	sites := e.Sites
	if len(sites) <= 1 {
		sites = []*Site{nil}
	}
	base := join(GroupEnvs, e.Name) + "/"
	for _, s := range sites {
		projectEnv(m, d, e, s, nil, Place{Env: e}, func(cs *CompatSnapshot) {
			for _, re := range cs.Snap.Resolve(model.SecEnvs, e.Name, "", nil).Errors {
				seg := strings.Split(strings.TrimPrefix(re.R.Entry.Path, base), "/")
				b := Broken{Where: "general", Key: re.R.Entry.Key, Msg: re.Msg}
				switch {
				case seg[0] == GroupSites && len(seg) > 2:
					b.Where, b.Name = "site", seg[1]
				case seg[0] == GroupProducts && len(seg) > 2:
					b.Where, b.Name = "product", seg[1]
				case seg[0] == GroupConnections:
					continue // a connection field: checked on its own
				}
				if id := b.Where + "/" + b.Name + "/" + b.Key + "/" + b.Msg; !seen[id] {
					seen[id] = true
					out = append(out, b)
				}
			}
		})
	}
	return out
}

// expandBatches resolves the references in the values of the batches of an environment in place; a reference that does not resolve is an error
// naming the variable, so nothing is written with it.
func (m *Vault) expandBatches(d *project.Description, e *Environment, out []*Batch) error {
	for _, b := range out {
		var p Place
		switch b.Kind {
		case BatchGeneral:
			p = Place{Env: e}
		case BatchSite:
			p = Place{Env: e, Site: e.Site(b.Title)}
		case BatchProduct:
			p = Place{Env: e, Product: e.Product(b.Title)}
		default:
			continue
		}
		for i, v := range b.Vars {
			if !strings.Contains(v.Value, "${{") {
				continue
			}
			q := p
			if q.Product != nil && q.Product.Site != nil && findVar(q.Product.Vars, v.Key) == nil && findVar(q.Product.Sub[q.Product.Site.Kind], v.Key) != nil {
				q.Kind = q.Product.Site.Kind
			}
			pv := m.expand(d, q, v.Key, v.Value, v.Vis)
			if len(pv.Errors) > 0 {
				return fmt.Errorf("%s %s: %s", b.Name, v.Key, strings.Join(pv.Errors, "; "))
			}
			b.Vars[i].Value, b.Vars[i].Vis = pv.Text, pv.Vis
		}
	}
	return nil
}
