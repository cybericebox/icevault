package vmodel

import (
	"sort"
	"strings"

	"github.com/cybericebox/icevault/internal/model"
)

// SharedUsers lists what uses the shared variable x, in the order of the environments: an environment that imports it ("prod"), or holds
// values that refer to it as ${{ shared.KEY }} in General, a site or a product ("prod (SOCIAL_CLIENT_ID, MAIL_FROM)"; an import under the same
// key and a reference in the same environment give one line, with the keys of the values), then the other shared variables ("shared (KEY)") and
// the connection fields ("Connection (field)") that refer to it. A value that refers to another value which refers to x is not listed: the
// holder of the reference itself is.
func (m *Vault) SharedUsers(x *Var) []string {
	refers := func(value string) bool {
		for _, r := range model.ReferencesIn(value) {
			if r[0] == model.GlobalRef && r[1] == x.Key {
				return true
			}
		}
		return false
	}
	var out []string
	for _, e := range m.Envs {
		imported := false
		for _, s := range e.Imports {
			if s == x {
				imported = true
			}
		}
		seen := map[string]bool{}
		var keys []string
		visit := func(vs []*Var) {
			for _, v := range vs {
				if refers(v.Value) && !seen[v.Key] {
					seen[v.Key] = true
					keys = append(keys, v.Key)
				}
			}
		}
		visit(e.General)
		for _, s := range e.Sites {
			visit(s.Vars)
		}
		for _, p := range e.Products {
			visit(p.Vars)
			subs := make([]string, 0, len(p.Sub))
			for k := range p.Sub {
				subs = append(subs, k)
			}
			sort.Strings(subs)
			for _, k := range subs {
				visit(p.Sub[k])
			}
		}
		switch {
		case len(keys) > 0:
			out = append(out, e.Name+" ("+strings.Join(keys, ", ")+")")
		case imported:
			out = append(out, e.Name)
		}
	}
	for _, s := range m.Shared {
		if s != x && refers(s.Value) {
			out = append(out, model.GlobalRef+" ("+s.Key+")")
		}
	}
	for _, c := range m.Connections {
		for _, f := range c.Fields {
			if refers(f.Value) {
				out = append(out, c.Name+" ("+f.Name+")")
			}
		}
	}
	return out
}
