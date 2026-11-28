package cli

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cybericebox/icevault/internal/kinds"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// set: the command-line twin of the window's (and the agent API's) set-value and var-create for PLAIN values. It changes the plain variables of
// the vault model directly in the vault file. A secret, a system-managed or generated variable and a value that holds a reference are refused: those
// need the window. All keys are checked first; when one is refused nothing is written. The values printed are plain ones; a refused secret key
// prints only its name and the reason.

const (
	cmdSet      = "set"
	setMaxValue = 64 << 10
	scopeShared = "shared"
	refMark     = "${{"
)

type setPair struct{ key, value string }

type setArgs struct {
	env, scope string
	dryRun     bool
	base       string // the folder of the session directories (default: the temp directory), as session run --base
	pairs      []setPair
}

func parseSetArgs(e *Env, args []string) (setArgs, error) {
	var a setArgs
	pos, err := parse(cmdSet, args, e, 1<<20, func(fs *flag.FlagSet) {
		fs.StringVar(&a.env, "env", "", "")
		fs.StringVar(&a.scope, "scope", "", "")
		fs.BoolVar(&a.dryRun, "dry-run", false, "")
		fs.StringVar(&a.base, "base", "", "")
	})
	if err != nil {
		return a, err
	}
	if a.env == "" {
		return a, &parseErr{msg: "set needs --env E"}
	}
	if len(pos) == 0 {
		return a, &parseErr{msg: "set needs at least one KEY=VALUE"}
	}
	seen := map[string]bool{}
	for _, p := range pos {
		key, value, ok := strings.Cut(p, "=")
		switch {
		case !ok:
			return a, &parseErr{msg: fmt.Sprintf("set: %q is not KEY=VALUE (KEY= clears a value)", clipKey(p))}
		case !vmodel.KeyRE.MatchString(key):
			return a, &parseErr{msg: fmt.Sprintf("set: %q is not a variable name (letters, digits, _ . -, not starting with a digit)", clipKey(key))}
		case seen[key]:
			return a, &parseErr{msg: fmt.Sprintf("set: %s is given twice", key)}
		}
		seen[key] = true
		a.pairs = append(a.pairs, setPair{key, value})
	}
	return a, nil
}

// clipKey keeps what is echoed from the command line short (and never the part after an equals sign).
func clipKey(s string) string {
	s, _, _ = strings.Cut(s, "=")
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return s
}

// literalRefusal is what the value alone can be refused for ("" when it is fine).
func literalRefusal(value string) string {
	switch {
	case strings.Contains(value, refMark):
		return "the value holds a reference (" + refMark + "): references are set in the window"
	case strings.ContainsAny(value, "\n\r"):
		return "the value has a line break"
	case len(value) > setMaxValue:
		return "the value is too long"
	}
	return ""
}

// scopeEnv checks the form of a scope name and returns the environment it belongs to ("" for shared).
func scopeEnv(scope string) (string, error) {
	if scope == scopeShared {
		return "", nil
	}
	p := strings.Split(scope, "/")
	ok := len(p) >= 3 && p[0] == "env" && p[1] != ""
	if ok {
		switch p[2] {
		case "general":
			ok = len(p) == 3
		case "site":
			ok = len(p) == 4 && p[3] != ""
		case "product":
			ok = (len(p) == 4 || len(p) == 5) && p[3] != "" && (len(p) == 4 || p[4] != "")
		default:
			ok = false
		}
	}
	if !ok {
		return "", fail("--scope %q is not a scope: shared, env/E/general, env/E/site/NAME, env/E/product/NAME or env/E/product/NAME/SITEKIND", clipKey(scope))
	}
	return p[1], nil
}

// checkSet refuses before the password what the arguments alone can refuse.
func checkSet(e *Env, args []string) (int, bool, error) {
	a, err := parseSetArgs(e, args)
	if err != nil {
		return 2, true, err
	}
	if _, err := envContext(e, a.env); err != nil {
		return 1, true, err
	}
	if a.scope != "" {
		se, err := scopeEnv(a.scope)
		if err != nil {
			return 1, true, err
		}
		if se != "" && se != a.env {
			return 1, true, fail("--scope %s is not in the environment %s (--env)", a.scope, a.env)
		}
	}
	var bad []string
	for _, p := range a.pairs {
		if why := literalRefusal(p.value); why != "" {
			bad = append(bad, p.key+": "+why)
		}
	}
	if len(bad) > 0 {
		for _, b := range bad {
			fmt.Fprintf(e.Err, "icevault: set: %s\n", b)
		}
		return 1, true, fail("set: nothing was written (%d of %d refused)", len(bad), len(a.pairs))
	}
	return 0, false, nil
}

// scopeList is the list of variables a scope stands for, read and written back.
type scopeList struct {
	get func() []*vmodel.Var
	set func([]*vmodel.Var)
}

// listOf is the scope grammar of the window and the agent API (internal/mpage scope()).
func listOf(m *vmodel.Vault, name string) (*scopeList, error) {
	if name == scopeShared {
		return &scopeList{func() []*vmodel.Var { return m.Shared }, func(l []*vmodel.Var) { m.Shared = l }}, nil
	}
	p := strings.Split(name, "/")
	e := m.Env(p[1])
	if e == nil {
		return nil, fail("the vault holds no environment %s", p[1])
	}
	switch {
	case p[2] == "general":
		return &scopeList{func() []*vmodel.Var { return e.General }, func(l []*vmodel.Var) { e.General = l }}, nil
	case p[2] == "site":
		if s := e.Site(p[3]); s != nil {
			return &scopeList{func() []*vmodel.Var { return s.Vars }, func(l []*vmodel.Var) { s.Vars = l }}, nil
		}
		return nil, fail("%s has no site %s", p[1], p[3])
	case len(p) == 4:
		if pr := e.Product(p[3]); pr != nil {
			return &scopeList{func() []*vmodel.Var { return pr.Vars }, func(l []*vmodel.Var) { pr.Vars = l }}, nil
		}
		return nil, fail("%s has no product %s", p[1], p[3])
	}
	pr := e.Product(p[3])
	if pr == nil {
		return nil, fail("%s has no product %s", p[1], p[3])
	}
	if _, ok := kinds.SiteKind(p[4]); !ok {
		return nil, fail("%s is not a site kind", p[4])
	}
	k := p[4]
	return &scopeList{func() []*vmodel.Var { return pr.Sub[k] }, func(l []*vmodel.Var) {
		if pr.Sub == nil {
			pr.Sub = map[string][]*vmodel.Var{}
		}
		pr.Sub[k] = l
	}}, nil
}

// keyPlace is one place a variable of a key lives in.
type keyPlace struct {
	scope    string
	v        *vmodel.Var
	imported bool
}

// placesIn lists where a key lives in one environment (General, its imports, sites, products and their site-kind groups).
func placesIn(e *vmodel.Environment, key string) []keyPlace {
	var out []keyPlace
	add := func(scope string, vs []*vmodel.Var, imported bool) {
		for _, v := range vs {
			if v.Key == key {
				out = append(out, keyPlace{scope, v, imported})
			}
		}
	}
	base := "env/" + e.Name
	add(base+"/general", e.General, false)
	add(base+"/general", e.Imports, true)
	for _, s := range e.Sites {
		add(base+"/site/"+s.Name, s.Vars, false)
	}
	for _, p := range e.Products {
		add(base+"/product/"+p.Name, p.Vars, false)
		subs := make([]string, 0, len(p.Sub))
		for k := range p.Sub {
			subs = append(subs, k)
		}
		sort.Strings(subs)
		for _, k := range subs {
			add(base+"/product/"+p.Name+"/"+k, p.Sub[k], false)
		}
	}
	return out
}

// defaultVisibility is the visibility a variable of that name gets: what the description says, else the name rule (as the window's core).
func defaultVisibility(d *project.Description, key string) string {
	secret, found := false, false
	d.Walk(func(h project.Home) {
		if h.Var.Name == key {
			found = true
			secret = secret || h.Var.Secret
		}
	})
	if found {
		if secret {
			return vmodel.VisSecret
		}
		return vmodel.VisPlain
	}
	if render.LooksSecret(key) {
		return vmodel.VisSecret
	}
	return vmodel.VisPlain
}

// secretKey says whether a variable of that name is secret anywhere: by the description or the name rule, or as an entry of any place of the vault.
func secretKey(m *vmodel.Vault, d *project.Description, key string) bool {
	if defaultVisibility(d, key) != vmodel.VisPlain {
		return true
	}
	any := func(vs []*vmodel.Var) bool {
		for _, v := range vs {
			if v.Key == key && v.Vis != vmodel.VisPlain {
				return true
			}
		}
		return false
	}
	if any(m.Shared) {
		return true
	}
	for _, e := range m.Envs {
		if any(e.General) || any(e.Imports) {
			return true
		}
		for _, s := range e.Sites {
			if any(s.Vars) {
				return true
			}
		}
		for _, p := range e.Products {
			if any(p.Vars) {
				return true
			}
			for _, vs := range p.Sub {
				if any(vs) {
					return true
				}
			}
		}
	}
	return false
}

// systemKey says whether the description makes a variable of that name system-managed or generated.
func systemKey(d *project.Description, key string) bool {
	sys := false
	d.Walk(func(h project.Home) {
		if h.Var.Name == key && h.Var.System() {
			sys = true
		}
	})
	return sys
}

// described is where the description places a variable that the environment does not hold yet: a scope, or the reason there is none.
func described(m *vmodel.Vault, d *project.Description, env, key string) (scope string, why string) {
	e := m.Env(env)
	var found, conn string
	var cands []string
	d.Walk(func(h project.Home) {
		if h.Var.Name != key {
			return
		}
		found = key
		base := "env/" + env
		switch h.Kind {
		case project.HomeGeneral:
			cands = append(cands, base+"/general")
		case project.HomeSite:
			for _, s := range e.Sites {
				if s.Kind == h.SiteKind {
					cands = append(cands, base+"/site/"+s.Name)
				}
			}
		case project.HomeProduct, project.HomeProductSub:
			pr := e.Product(h.Product)
			if pr == nil || !pr.Enabled || pr.Place == vmodel.PlaceNone {
				return
			}
			if h.Kind == project.HomeProduct {
				cands = append(cands, base+"/product/"+pr.Name)
				return
			}
			site := pr.Site
			if site == nil && len(e.Sites) == 1 {
				site = e.Sites[0]
			}
			if site != nil && site.Kind == h.SiteKind {
				cands = append(cands, base+"/product/"+pr.Name+"/"+h.SiteKind)
			}
		default:
			if h.Conn != nil {
				conn = h.Conn.Kind
			}
		}
	})
	switch {
	case len(cands) == 1:
		return cands[0], ""
	case len(cands) > 1:
		sort.Strings(cands)
		return "", "the description places it in several scopes of " + env + " (" + strings.Join(cands, ", ") + "): give --scope"
	case conn != "":
		return "", "is a field of a connection (" + conn + "), not a variable of the environment: set it in the window"
	case found != "":
		return "", "the description names it, but " + env + " does not use it (its site kind or product is not there or is off): give --scope to create it anyway"
	}
	return "", "is not in the vault and not in the project description: give --scope"
}

// setAction is one checked change.
type setAction struct {
	pair    setPair
	scope   string
	list    *scopeList
	existed *vmodel.Var
	old     string
}

// planSet checks every pair against the model and returns the actions, or one line per refused key.
func planSet(m *vmodel.Vault, d *project.Description, a setArgs) ([]setAction, []string) {
	var acts []setAction
	var bad []string
	refuse := func(key, why string) { bad = append(bad, key+": "+why) }
	e := m.Env(a.env)
	if e == nil {
		return nil, []string{"the vault holds no environment " + a.env}
	}
	for _, p := range a.pairs {
		key := p.key
		scope := a.scope
		var imported []string
		places := placesIn(e, key)
		if scope == "" {
			var own []keyPlace
			for _, pl := range places {
				if pl.imported {
					imported = append(imported, pl.scope)
					continue
				}
				own = append(own, pl)
			}
			switch {
			case len(imported) > 0:
				refuse(key, "is a shared variable imported into "+imported[0]+": give --scope shared")
				continue
			case len(own) > 1:
				var names []string
				for _, pl := range own {
					names = append(names, pl.scope)
				}
				refuse(key, "is in several scopes ("+strings.Join(names, ", ")+"): give --scope")
				continue
			case len(own) == 1:
				scope = own[0].scope
			default:
				var why string
				if scope, why = described(m, d, a.env, key); why != "" {
					refuse(key, why)
					continue
				}
			}
		}
		list, err := listOf(m, scope)
		if err != nil {
			refuse(key, err.Error())
			continue
		}
		var x *vmodel.Var
		for _, v := range list.get() {
			if v.Key == key {
				x = v
			}
		}
		if x == nil && scope == "env/"+a.env+"/general" && a.scope != "" {
			imp := false
			for _, pl := range places {
				imp = imp || (pl.imported && pl.scope == scope)
			}
			if imp {
				refuse(key, "is a shared variable imported into "+scope+": give --scope shared")
				continue
			}
		}
		if secretKey(m, d, key) || (x != nil && x.Vis != vmodel.VisPlain) {
			refuse(key, "is a secret variable: set it in the window")
			continue
		}
		if systemKey(d, key) || (x != nil && x.Managed == vmodel.ManagedSystem) {
			refuse(key, "is managed by the system (made by the project's scripts): it is not set by hand")
			continue
		}
		if rule := d.ValueProblem(key, p.value); rule != "" {
			refuse(key, "the value breaks the type the description gives it (rule: "+rule+")")
			continue
		}
		if x == nil && scope != scopeShared {
			var others []string
			for _, pl := range places {
				others = append(others, pl.scope)
			}
			if len(others) > 0 {
				refuse(key, "would hide the same key in "+strings.Join(others, ", ")+": set that one, or give --scope of it")
				continue
			}
		}
		act := setAction{pair: p, scope: scope, list: list, existed: x}
		if x != nil {
			act.old = x.Value
		}
		acts = append(acts, act)
	}
	return acts, bad
}

// runSet is set on an unlocked vault of the vault model.
func runSet(e *Env, args []string, out io.Writer, v *vault.Vault, plat *render.Project) (int, error) {
	a, err := parseSetArgs(e, args)
	if err != nil {
		return 2, err
	}
	if _, err := envContext(e, a.env); err != nil {
		return 1, err
	}
	m, err := vmodel.Load(v)
	if err != nil {
		return 1, fail("%v", err)
	}
	if m.ReadOnly {
		return 1, fail("%v", vmodel.ErrNewerFormat)
	}
	acts, bad := planSet(m, plat.D, a)
	if len(bad) > 0 {
		for _, b := range bad {
			fmt.Fprintf(e.Err, "icevault: set: %s\n", b)
		}
		return 1, fail("set: nothing was written (%d of %d refused)", len(bad), len(a.pairs))
	}
	before, _ := sha256File(v.Path())
	changed := false
	for _, act := range acts {
		old, now := act.old, act.pair.value
		if act.existed == nil {
			old = "(new)"
			changed = true
			act.list.set(append(act.list.get(), &vmodel.Var{Key: act.pair.key, Value: now, Managed: vmodel.ManagedOwner, Vis: vmodel.VisPlain}))
		} else {
			if act.old != now {
				changed = true
				act.existed.Value = now
			}
			if old == "" {
				old = "(empty)"
			}
		}
		if now == "" {
			now = "(empty)"
		}
		fmt.Fprintf(out, "%s %s: %s -> %s\n", act.scope, act.pair.key, old, now)
	}
	if a.dryRun {
		fmt.Fprintln(out, "(dry run: nothing was written)")
		return 0, nil
	}
	if !changed {
		fmt.Fprintln(out, "nothing changed: every value is what it was")
		return 0, nil
	}
	if errs := m.Check(); len(errs) > 0 {
		return 1, fail("the model would not be valid: %s", strings.Join(errs, "; "))
	}
	if info, live := liveWriteSession(e, a.base, a.env); live {
		return 1, fail("set: nothing was written: a run of '%s' is in progress (PID %d) with a session that is written back into the vault when it ends, "+
			"and a change now would make that write-back fail; wait for the run to end and set again", a.env, info.PID)
	}
	if err := vmodel.Sync(v, m); err != nil {
		return 1, fail("%v", err)
	}
	if err := v.Save(); err != nil {
		return 1, fail("%v", err)
	}
	if mv, merr := openModelView(e, v, plat); merr == nil {
		refreshInfo(v.Path(), plat, mv.compat.Snap)
	}
	afterChange(v.Path(), before, out)
	return 0, nil
}
