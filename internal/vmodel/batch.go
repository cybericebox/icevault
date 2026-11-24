package vmodel

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cybericebox/icevault/internal/project"
)

// Export per run, in batches. A run asks for an environment and a selection (one site, one product, or everything); the
// answer is one batch per thing selected, kept apart so that two products on two cloud accounts never collide on one variable name. A batch holds
// variables under the names the project description gives them and names the batches it refers to (a product its site and connections).

// Batch kinds.
const (
	BatchGeneral    = "general"
	BatchSite       = "site"
	BatchProduct    = "product"
	BatchConnection = "connection"
)

// BatchVar is one variable of a batch.
type BatchVar struct {
	Key   string
	Value string
	Vis   string
}

// Batch is one batch of an export. Vars carry the values; everything else is the index (no value).
type Batch struct {
	Name           string     `json:"name"`
	Kind           string     `json:"kind"`
	Title          string     `json:"title"`
	SiteKind       string     `json:"site_kind,omitempty"`
	ConnectionKind string     `json:"connection_kind,omitempty"`
	Enabled        *bool      `json:"enabled,omitempty"`
	Place          string     `json:"place,omitempty"`
	Site           string     `json:"site,omitempty"`
	Connections    []string   `json:"connections,omitempty"`
	State          string     `json:"state,omitempty"`
	StateBackend   string     `json:"state_backend,omitempty"`
	Variables      []string   `json:"variables"`
	Vars           []BatchVar `json:"-"`
}

func (b *Batch) set(key, value, vis string) {
	for i := range b.Vars {
		if b.Vars[i].Key == key {
			b.Vars[i].Value, b.Vars[i].Vis = value, vis
			return
		}
	}
	b.Vars = append(b.Vars, BatchVar{key, value, vis})
	b.Variables = append(b.Variables, key)
}

// Selection is what a run asks for: one site, one product, or All.
type Selection struct {
	Site, Product string
	All           bool
}

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

// Slug is the batch name part of a connection name: lower case, every run of other characters one dash.
func Slug(name string) string {
	return strings.Trim(slugRE.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

type batcher struct {
	m     *Vault
	d     *project.Description
	e     *Environment
	out   []*Batch
	conns map[*Connection]*Batch
	names map[string]bool
}

func (b *batcher) name(n string) string {
	base, i := n, 2
	for b.names[n] {
		n = fmt.Sprintf("%s-%d", base, i)
		i++
	}
	b.names[n] = true
	return n
}

// connection makes (or returns) the batch of a connection and adds the variables of one use of it.
func (b *batcher) connection(c *Connection, use *project.ConnectionUse) string {
	if c == nil {
		return ""
	}
	bt := b.conns[c]
	if bt == nil {
		bt = &Batch{Name: b.name("connection-" + Slug(c.Name)), Kind: BatchConnection, Title: c.Name, ConnectionKind: c.Kind, Variables: []string{}}
		b.conns[c] = bt
		b.out = append(b.out, bt)
	}
	if use != nil {
		for _, v := range use.Variables {
			if f := c.Field(v.Field); f != nil {
				vis := VisPlain
				if f.Secret || v.Secret {
					vis = VisSecret
				}
				bt.set(v.Name, f.Value, vis)
			}
		}
	}
	return bt.Name
}

func (b *batcher) site(s *Site) string {
	sk := b.d.SiteKinds[s.Kind]
	bt := &Batch{Name: b.name("site-" + s.Name), Kind: BatchSite, Title: s.Name, SiteKind: s.Kind, StateBackend: s.StateBackend, Variables: []string{}}
	b.out = append(b.out, bt)
	for _, x := range s.Vars {
		bt.set(x.Key, x.Value, x.Vis)
	}
	if s.Connection != nil {
		bt.Connections = []string{b.connection(s.Connection, sk.Connection)}
	}
	if s.State != nil {
		bt.State = b.connection(s.State, sk.State)
	}
	return bt.Name
}

func (b *batcher) product(p *Product, siteBatch map[*Site]string) {
	on := p.Enabled
	bt := &Batch{Name: b.name("product-" + p.Name), Kind: BatchProduct, Title: p.Name, Enabled: &on, Place: p.Place, Variables: []string{}}
	b.out = append(b.out, bt)
	for _, x := range p.Vars {
		bt.set(x.Key, x.Value, x.Vis)
	}
	if p.Site != nil {
		for _, x := range p.Sub[p.Site.Kind] {
			bt.set(x.Key, x.Value, x.Vis)
		}
		if siteBatch[p.Site] == "" {
			siteBatch[p.Site] = b.site(p.Site)
		}
		bt.Site = siteBatch[p.Site]
	}
	dp := b.d.Product(p.Name)
	for _, c := range p.Connections {
		var use *project.ConnectionUse
		if dp != nil {
			for i := range dp.Connections {
				if dp.Connections[i].Kind == c.Kind {
					use = &dp.Connections[i]
					break
				}
			}
		}
		bt.Connections = append(bt.Connections, b.connection(c, use))
	}
}

// Batches answers a run: General first, then what the selection names, then the connections they use. A name that the environment does not have
// is an error naming what it has.
func Batches(m *Vault, d *project.Description, env string, sel Selection) ([]*Batch, error) {
	e := m.Env(env)
	if e == nil {
		return nil, fmt.Errorf("the vault has no environment '%s' (it has: %s)", env, strings.Join(m.EnvNames(), ", "))
	}
	b := &batcher{m: m, d: d, e: e, conns: map[*Connection]*Batch{}, names: map[string]bool{}}
	g := &Batch{Name: b.name(BatchGeneral), Kind: BatchGeneral, Title: "General", Variables: []string{}}
	for _, x := range e.GeneralValues() {
		g.set(x.Key, x.Value, x.Vis)
	}
	b.out = append(b.out, g)
	siteBatch := map[*Site]string{}
	switch {
	case sel.All:
		for _, s := range e.Sites {
			siteBatch[s] = b.site(s)
		}
		for _, p := range e.Products {
			if p.Enabled {
				b.product(p, siteBatch)
			}
		}
	case sel.Site != "":
		s := e.Site(sel.Site)
		if s == nil {
			return nil, fmt.Errorf("'%s' has no site '%s' (it has: %s)", env, sel.Site, names(e.Sites, func(s *Site) string { return s.Name }))
		}
		b.site(s)
	case sel.Product != "":
		p := e.Product(sel.Product)
		if p == nil {
			return nil, fmt.Errorf("'%s' has no product '%s' (it has: %s)", env, sel.Product, names(e.Products, func(p *Product) string { return p.Name }))
		}
		b.product(p, siteBatch)
	default:
		return nil, fmt.Errorf("a run names --site, --product or --all")
	}
	// connections after the things that use them, in the order they were first used
	var head, tail []*Batch
	for _, x := range b.out {
		if x.Kind == BatchConnection {
			tail = append(tail, x)
		} else {
			head = append(head, x)
		}
	}
	out := append(head, tail...)
	if err := m.expandBatches(d, e, out); err != nil {
		return nil, fmt.Errorf("a reference does not resolve in %s", err)
	}
	return out, nil
}

func names[T any](xs []T, n func(T) string) string {
	var out []string
	for _, x := range xs {
		out = append(out, n(x))
	}
	if len(out) == 0 {
		return PlaceNone
	}
	return strings.Join(out, ", ")
}
