package vmodel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cybericebox/icevault/internal/kinds"
	"github.com/cybericebox/icevault/internal/project"
)

// The owner's setup of an environment from the project description: CreateEnv makes an environment with its site and products, FillMissing
// gives an environment every variable the description says it needs and the owner fills in, as an empty entry (the hint of the description,
// secret or plain as it says). Neither ever writes a value, and neither changes an entry that exists: a variable the system makes (managed:
// system, generated) is left to the project's own init, a variable whose condition does not hold for this environment and a file the
// environment does not read are skipped. The command line (icevault env) and the window (m-env-fill) both call these: one write path.

var placeRE = regexp.MustCompile(`^[A-Za-z0-9_:-]{1,64}$`)

// PlaceNone is the place of a product that runs nowhere.
const PlaceNone = "none"

// SiteName is the name of the site CreateEnv makes.
const SiteName = "main"

// ProductPlan is a product of a new environment and where it runs ("" = the default of the description).
type ProductPlan struct {
	Name  string
	Place string
}

// EnvPlan is what CreateEnv makes: one site of SiteKind and the products listed (the other products of the description are made switched off).
type EnvPlan struct {
	SiteKind string
	Products []ProductPlan
}

// Added is one empty entry that was made: where (general, site main, product portal, connection GCP project, ...), the variable and its file.
type Added struct {
	Where, Key, File string
	Secret           bool
}

// FillReport is what CreateEnv or FillMissing did: names only, never a value.
type FillReport struct {
	Added  []Added
	Made   []string // connections made (name (kind))
	Linked []string // existing connections linked (name (kind))
}

// PlanProblems checks a plan against the description before anything is asked or written: the problems, or nil.
func PlanProblems(d *project.Description, p EnvPlan) []string {
	var errs []string
	if _, ok := d.SiteKinds[p.SiteKind]; !ok {
		var ks []string
		for k := range d.SiteKinds {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		errs = append(errs, fmt.Sprintf("the project description has no site kind %q (one of %s)", p.SiteKind, strings.Join(ks, ", ")))
	} else if _, ok := kinds.SiteKind(p.SiteKind); !ok {
		errs = append(errs, fmt.Sprintf("%q is not a site kind of the tool", p.SiteKind))
	}
	seen := map[string]bool{}
	for _, x := range p.Products {
		dp := d.Product(x.Name)
		switch {
		case dp == nil:
			errs = append(errs, fmt.Sprintf("the project description has no product %q (one of %s)", x.Name, strings.Join(productNames(d), ", ")))
		case seen[x.Name]:
			errs = append(errs, fmt.Sprintf("product %s is named twice", x.Name))
		case x.Place == "" && dp.PlaceVariable != "" && placeOff(d.Conditions.Defaults[dp.PlaceVariable]):
			errs = append(errs, fmt.Sprintf("product %s runs nowhere by default (%s=%s): give its place, %s=PLACE", x.Name, dp.PlaceVariable,
				orNone(d.Conditions.Defaults[dp.PlaceVariable]), x.Name))
		case x.Place != "" && dp.PlaceVariable == "":
			errs = append(errs, fmt.Sprintf("product %s has no place variable in the project description: name it without =PLACE", x.Name))
		case x.Place != "" && !placeRE.MatchString(x.Place):
			errs = append(errs, fmt.Sprintf("%q is not a place (letters, digits, -, _ and :)", x.Place))
		}
		seen[x.Name] = true
	}
	return errs
}

func orNone(s string) string {
	if s == "" {
		return "(empty)"
	}
	return s
}

func placeOff(v string) bool { return v == "" || v == PlaceNone }

func productNames(d *project.Description) []string {
	var out []string
	for _, p := range d.Products {
		out = append(out, p.Name)
	}
	return out
}

// CreateEnv makes the environment name from the plan and fills it (FillMissing). committed are the committed settings of the environment in
// the checkout (nil when none): they decide the conditions together with what the model writes.
func CreateEnv(m *Vault, d *project.Description, name string, p EnvPlan, committed map[string]string) (*FillReport, error) {
	if !EnvNameRE.MatchString(name) {
		return nil, fmt.Errorf("%q is not an environment name", name)
	}
	if m.Env(name) != nil {
		return nil, fmt.Errorf("the vault holds the environment %s already: icevault env fill-missing --env %s adds what it lacks", name, name)
	}
	if errs := PlanProblems(d, p); len(errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	site := &Site{Name: SiteName, Kind: p.SiteKind}
	e := &Environment{Name: name, Layouts: map[string][]byte{}, Sites: []*Site{site}}
	want := map[string]string{}
	for _, x := range p.Products {
		want[x.Name] = x.Place
	}
	for _, dp := range d.Products {
		place, on := want[dp.Name]
		pr := &Product{Name: dp.Name, Enabled: on, Place: place, Sub: map[string][]*Var{}}
		if on {
			pr.Site = site
		} else {
			pr.Place = PlaceNone
		}
		e.Products = append(e.Products, pr)
	}
	m.Envs = append(m.Envs, e)
	return FillMissing(m, d, name, committed)
}

// FillMissing adds to the environment every owner variable the description says it needs, as an empty entry, and links (or makes) the
// connections its site and its products need. It changes no entry that exists and writes no value.
func FillMissing(m *Vault, d *project.Description, name string, committed map[string]string) (*FillReport, error) {
	e := m.Env(name)
	if e == nil {
		return nil, fmt.Errorf("the vault holds no environment %s: icevault env create --env %s makes it", name, name)
	}
	rep := &FillReport{}
	get := d.Getter(settingsOf(e, d, committed))
	skip := map[string]bool{}
	for _, x := range d.Derived {
		skip[x.Name] = true
	}
	for _, p := range d.Products {
		if p.PlaceVariable != "" {
			skip[p.PlaceVariable] = true
		}
	}
	needed := func(v project.Variable, file string) bool {
		if v.System() || skip[v.Name] || !d.KeyUsed(file, v.Name, get) {
			return false
		}
		if v.When != "" {
			c, err := project.ParseWhen(v.When)
			if err != nil || !c.Holds(get) {
				return false
			}
		}
		return true
	}
	present := map[string]bool{} // a key the environment holds anywhere (General, an import, a site, a product) is never made again
	mark := func(vs []*Var) {
		for _, x := range vs {
			present[x.Key] = true
		}
	}
	mark(e.General)
	mark(e.Imports)
	for _, s := range e.Sites {
		mark(s.Vars)
	}
	for _, p := range e.Products {
		mark(p.Vars)
		for _, vs := range p.Sub {
			mark(vs)
		}
	}
	addVar := func(where string, list *[]*Var, v project.Variable, file string) {
		if !needed(v, file) || present[v.Name] {
			return
		}
		present[v.Name] = true
		vis := VisPlain
		if v.Secret {
			vis = VisSecret
		}
		*list = append(*list, &Var{Key: v.Name, Description: hintOf(v), Managed: ManagedOwner, Vis: vis})
		rep.Added = append(rep.Added, Added{Where: where, Key: v.Name, File: file, Secret: v.Secret})
	}
	addFields := func(c *Connection, use *project.ConnectionUse) {
		for _, v := range use.Variables {
			file := or(v.File, use.File)
			if v.Field == "" || !needed(v, file) || c.Field(v.Field) != nil {
				continue
			}
			c.Fields = append(c.Fields, &Field{Name: v.Field, Secret: v.Secret})
			rep.Added = append(rep.Added, Added{Where: "connection " + c.Name, Key: v.Name, File: file, Secret: v.Secret})
		}
	}
	for _, v := range d.General.Variables {
		addVar("general", &e.General, v, or(v.File, d.General.File))
	}
	for _, s := range e.Sites {
		sk, ok := d.SiteKinds[s.Kind]
		if !ok {
			continue
		}
		for _, v := range sk.Variables {
			addVar("site "+s.Name, &s.Vars, v, or(v.File, sk.File))
		}
		kind, _ := kinds.SiteKind(s.Kind)
		if use := sk.Connection; use != nil && use.Kind == kind.Connection {
			if s.Connection == nil {
				s.Connection = connFor(m, d, use, rep)
			}
			addFields(s.Connection, use)
		}
		if use := sk.State; use != nil && kind.State {
			if s.State == nil {
				s.State = connFor(m, d, use, rep)
			}
			addFields(s.State, use)
		}
	}
	for _, p := range e.Products {
		dp := d.Product(p.Name)
		if dp == nil || !p.Enabled || p.Place == PlaceNone {
			continue
		}
		for _, v := range dp.Variables {
			addVar("product "+p.Name, &p.Vars, v, or(v.File, dp.File))
		}
		site := p.Site
		if site == nil && len(e.Sites) == 1 {
			site = e.Sites[0]
		}
		if site != nil {
			if p.Sub == nil {
				p.Sub = map[string][]*Var{}
			}
			sub := p.Sub[site.Kind]
			for _, v := range dp.OnSiteKind[site.Kind] {
				addVar("product "+p.Name+" on "+site.Kind, &sub, v, or(v.File, dp.File))
			}
			if len(sub) > 0 {
				p.Sub[site.Kind] = sub
			}
		}
		for i := range dp.Connections {
			use := &dp.Connections[i]
			var c *Connection
			for _, x := range p.Connections {
				if x.Kind == use.Kind {
					c = x
				}
			}
			if c == nil {
				if use.Optional && !neededWhen(use, get) {
					continue
				}
				c = connFor(m, d, use, rep)
				p.Connections = append(p.Connections, c)
			}
			addFields(c, use)
		}
	}
	return rep, nil
}

// neededWhen says whether an optional connection is needed in this environment: a required-when of one of its variables holds (the rule the
// window's "missing for deploy" uses), so fill-missing makes it like a connection that is not optional.
func neededWhen(use *project.ConnectionUse, get func(string) string) bool {
	for _, v := range use.Variables {
		if v.Field == "" {
			continue
		}
		if w, err := project.ParseWhen(v.When); v.When != "" && (err != nil || w == nil || !w.Holds(get)) {
			continue // a variable that is not used here needs nothing
		}
		if cond, err := project.ParseWhen(v.RequiredWhen); err == nil && cond != nil && cond.Holds(get) {
			return true
		}
	}
	return false
}

// connFor is the connection a use links: the one of its name and kind, else the only one of its kind, else a new empty one (named by the use
// or the kind, made unique).
func connFor(m *Vault, d *project.Description, use *project.ConnectionUse, rep *FillReport) *Connection {
	k, _ := d.Kinds().Kind(use.Kind)
	name := or(use.Name, k.Title)
	if name == "" {
		name = use.Kind
	}
	if c := m.Connection(name); c != nil && c.Kind == use.Kind {
		rep.Linked = appendOnce(rep.Linked, c.Name+" ("+c.Kind+")")
		return c
	}
	var same []*Connection
	for _, c := range m.Connections {
		if c.Kind == use.Kind {
			same = append(same, c)
		}
	}
	if len(same) == 1 {
		rep.Linked = appendOnce(rep.Linked, same[0].Name+" ("+same[0].Kind+")")
		return same[0]
	}
	n := name
	for i := 2; m.Connection(n) != nil; i++ {
		n = fmt.Sprintf("%s %d", name, i)
	}
	c := &Connection{Name: n, Kind: use.Kind}
	m.Connections = append(m.Connections, c)
	rep.Made = append(rep.Made, c.Name+" ("+c.Kind+")")
	return c
}

func appendOnce(l []string, s string) []string {
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}

// settingsOf are the settings conditions read for an environment: the committed ones, then the values of its general variables, the derived
// variables of its site and the places of its products (the model wins over the checkout).
func settingsOf(e *Environment, d *project.Description, committed map[string]string) func(string) string {
	s := map[string]string{}
	for k, v := range committed {
		s[k] = v
	}
	for _, x := range append(append([]*Var(nil), e.Imports...), e.General...) {
		if x.Value != "" {
			s[x.Key] = x.Value
		}
	}
	if len(e.Sites) > 0 {
		site := e.Sites[0]
		if sk, ok := d.SiteKinds[site.Kind]; ok {
			for _, x := range d.Derived {
				switch x.From {
				case "site.provider":
					s[x.Name] = sk.Provider
				case "site.state-backend":
					if b := site.Backend(); b != "" {
						s[x.Name] = b
					}
				}
			}
		}
	}
	for _, p := range e.Products {
		if dp := d.Product(p.Name); dp != nil && dp.PlaceVariable != "" {
			switch {
			case !p.Enabled:
				s[dp.PlaceVariable] = PlaceNone
			case p.Place != "":
				s[dp.PlaceVariable] = p.Place
			}
		}
	}
	return func(k string) string { return s[k] }
}

// hintOf is the description of a new entry: the English help of the variable, else its label (one line).
func hintOf(v project.Variable) string {
	h := v.Help.In("en")
	if h == "" {
		h = v.Label.In("en")
	}
	return strings.Join(strings.Fields(h), " ")
}
