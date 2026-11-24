package vmodel

import (
	"strings"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
)

// Resolved is what a stored value with references comes to: the text (to be handed to the page only when Vis is plain and nothing is wrong), the
// strictest visibility, the references with their state and the errors. Varies is set when the value lives in no site of an environment with
// several sites and the sites give different answers.
type Resolved struct {
	Text   string
	Vis    string
	Refs   []RefInfo
	Errors []string
	Varies bool
}

// Resolutions is the resolution of every value that has a reference, made in one pass per environment (per site) and one for the shared level.
type Resolutions struct {
	Shared map[*Var]*Resolved
	Fields map[*Field]*Resolved
	Env    map[*Environment]map[*Var]*Resolved
}

func hasRef(v string) bool { return strings.Contains(v, "${{") }

func same(a, b *Resolved) bool {
	return a.Text == b.Text && a.Vis == b.Vis && strings.Join(a.Errors, "|") == strings.Join(b.Errors, "|")
}

// ResolveAll resolves every stored value that has a reference, for the tables of the model page: one projection and one resolution per environment
// and site, never one per row. Nothing is changed in m.
func (m *Vault) ResolveAll(d *project.Description) *Resolutions {
	out := &Resolutions{Shared: map[*Var]*Resolved{}, Fields: map[*Field]*Resolved{}, Env: map[*Environment]map[*Var]*Resolved{}}
	var snap *model.Snapshot
	expand := func(value, vis string) *Resolved {
		if snap == nil {
			snap = CompatWith(&Vault{Shared: m.Shared, Connections: m.Connections}, descOf(d), CompatOptions{}).Snap
		}
		vis = orDefault(vis, VisSecret)
		text, v, errs := snap.Expand(value, vis, "")
		if model.VisRank(vis) > model.VisRank(v) {
			v = vis
		}
		if len(errs) > 0 {
			text = ""
		}
		return &Resolved{Text: text, Vis: v, Refs: refInfos(value, errs), Errors: errs}
	}
	for _, x := range m.Shared {
		if hasRef(x.Value) {
			out.Shared[x] = expand(x.Value, x.Vis)
		}
	}
	for _, c := range m.Connections {
		for _, f := range c.Fields {
			if hasRef(f.Value) {
				vis := VisPlain
				if f.Secret {
					vis = VisSecret
				}
				out.Fields[f] = expand(f.Value, vis)
			}
		}
	}
	for _, e := range m.Envs {
		if r := m.resolveEnv(d, e); len(r) > 0 {
			out.Env[e] = r
		}
	}
	return out
}

func envVars(e *Environment) (all []*Var, bySite map[*Var]*Site) {
	bySite = map[*Var]*Site{}
	all = append(all, e.General...)
	all = append(all, e.Imports...)
	for _, s := range e.Sites {
		all = append(all, s.Vars...)
		for _, x := range s.Vars {
			bySite[x] = s
		}
	}
	for _, p := range e.Products {
		all = append(all, p.Vars...)
		for _, x := range p.Vars {
			bySite[x] = p.Site
		}
		for _, l := range p.Sub {
			all = append(all, l...)
			for _, x := range l {
				bySite[x] = p.Site
			}
		}
	}
	return all, bySite
}

// resolveEnv resolves the variables of one environment: once per site (once when it has at most one). A value that belongs to no site and gets
// different answers from the sites is marked Varies.
func (m *Vault) resolveEnv(d *project.Description, e *Environment) map[*Var]*Resolved {
	all, bySite := envVars(e)
	need := false
	for _, x := range all {
		need = need || hasRef(x.Value)
	}
	if !need {
		return nil
	}
	sites := e.Sites
	if len(sites) == 0 {
		sites = []*Site{nil}
	}
	per := make([]map[*Var]*Resolved, len(sites))
	for i, s := range sites {
		per[i] = m.resolveEnvAt(d, e, s)
	}
	if len(sites) == 1 {
		return per[0]
	}
	out := map[*Var]*Resolved{}
	for _, x := range all {
		if !hasRef(x.Value) {
			continue
		}
		var first *Resolved
		agree := true
		for i, s := range sites {
			r := per[i][x]
			if r == nil {
				continue
			}
			if own := bySite[x]; own != nil && own != s {
				continue // a value of one site is read in that site only
			}
			if first == nil {
				first = r
			} else if !same(first, r) {
				agree = false
			}
		}
		switch {
		case first == nil:
		case agree:
			out[x] = first
		default:
			cp := *first
			cp.Text, cp.Varies = "", true
			out[x] = &cp
		}
	}
	return out
}

func (m *Vault) resolveEnvAt(d *project.Description, e *Environment, site *Site) map[*Var]*Resolved {
	out := map[*Var]*Resolved{}
	projectEnv(m, d, e, site, nil, Place{Env: e}, func(cs *CompatSnapshot) {
		res := cs.Snap.Resolve(model.SecEnvs, e.Name, "", nil)
		errs := map[*model.Resolved][]string{}
		for _, re := range res.Errors {
			errs[re.R] = append(errs[re.R], re.Msg)
		}
		for _, key := range res.Order {
			for _, h := range res.Holders[key] {
				if h.Section != model.SecEnvs || h.Item != e.Name {
					continue
				}
				t := cs.Targets[h.Entry.Path]
				if t == nil || t.Var == nil || !hasRef(t.Var.Value) {
					continue
				}
				r := &Resolved{Text: h.Entry.Value, Vis: h.Entry.Vis, Errors: errs[h], Refs: refInfos(t.Var.Value, errs[h])}
				if len(r.Errors) > 0 {
					r.Text = ""
				}
				out[t.Var] = r
			}
		}
	})
	return out
}

// ResolveValue is PreviewValue with the text kept whatever its visibility: for the one value a person asks to see (the page checks the rules
// first). A value of General that the sites resolve differently comes back with Sites set and no text.
func (m *Vault) ResolveValue(d *project.Description, p Place, key, value, vis string) Preview {
	return m.expand(d, p, key, value, vis)
}
