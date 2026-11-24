package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// env create | env fill-missing: the owner's setup of an environment of the vault model from the project description (vmodel.CreateEnv,
// vmodel.FillMissing: the same write path as the window's "create missing entries"). Every owner variable the environment needs becomes an
// empty entry with its hint; no value is ever written, no entry that exists is touched, and what the system makes stays for the project's init.

const (
	cmdEnv      = "env"
	envCreate   = "create"
	envFill     = "fill-missing"
	envAdopt    = "adopt-connections"
	flagFromCO  = "from-checkout"
	flagProduct = "products"
)

type envArgs struct {
	sub, env, site, products string
	fromCheckout             bool
	dryRun                   bool
}

func parseEnvArgs(e *Env, args []string) (envArgs, error) {
	var a envArgs
	if len(args) == 0 || (args[0] != envCreate && args[0] != envFill && args[0] != envAdopt) {
		return a, &parseErr{msg: "env needs create, fill-missing or adopt-connections"}
	}
	a.sub = args[0]
	if _, err := parse("env "+a.sub, args[1:], e, 0, func(fs *flag.FlagSet) {
		fs.StringVar(&a.env, "env", "", "")
		fs.StringVar(&a.site, "site", "", "")
		fs.StringVar(&a.products, flagProduct, "", "")
		fs.BoolVar(&a.fromCheckout, flagFromCO, false, "")
		fs.BoolVar(&a.dryRun, "dry-run", false, "")
	}); err != nil {
		return a, err
	}
	if a.env == "" {
		return a, &parseErr{msg: "env " + a.sub + " needs --env E"}
	}
	if a.sub == envFill && (a.site != "" || a.products != "" || a.fromCheckout || a.dryRun) {
		return a, &parseErr{msg: "env fill-missing takes only --env E: the environment has its site and products"}
	}
	if a.sub == envAdopt && (a.site != "" || a.products != "" || a.fromCheckout) {
		return a, &parseErr{msg: "env adopt-connections takes only --env E and --dry-run"}
	}
	if a.sub == envCreate && a.dryRun {
		return a, &parseErr{msg: "--dry-run is for env adopt-connections"}
	}
	return a, nil
}

// envPlan is the plan of env create: --site and --products, or what the committed settings of the environment say (--from-checkout).
func envPlan(d *project.Description, a envArgs) (vmodel.EnvPlan, map[string]string, error) {
	committed, cerr := render.ReadSettings(d.CommittedFile(a.env))
	if a.fromCheckout && cerr != nil {
		return vmodel.EnvPlan{}, nil, fail("--from-checkout: %s cannot be read (%v)", d.CommittedFile(a.env), pathErrText(cerr))
	}
	if cerr != nil {
		committed = nil
	}
	p := vmodel.EnvPlan{SiteKind: a.site}
	get := d.Getter(func(k string) string { return committed[k] })
	if p.SiteKind == "" && a.fromCheckout {
		for _, x := range d.Derived {
			if x.From == "site.provider" {
				p.SiteKind = d.SiteKindOf(get(x.Name))
			}
		}
		if p.SiteKind == "" {
			return p, nil, fail("--from-checkout: the committed settings name no site kind of the description: give --site KIND")
		}
	}
	if p.SiteKind == "" {
		return p, nil, &parseErr{msg: "env create needs --site KIND (a site kind of the description) or --from-checkout"}
	}
	switch {
	case a.products != "":
		for _, w := range strings.Split(a.products, ",") {
			name, place, _ := strings.Cut(strings.TrimSpace(w), "=")
			if name != "" {
				p.Products = append(p.Products, vmodel.ProductPlan{Name: name, Place: place})
			}
		}
	case a.fromCheckout:
		for _, dp := range d.Products {
			if dp.PlaceVariable == "" {
				p.Products = append(p.Products, vmodel.ProductPlan{Name: dp.Name})
				continue
			}
			if w := get(dp.PlaceVariable); w != "" && w != "none" {
				p.Products = append(p.Products, vmodel.ProductPlan{Name: dp.Name, Place: committed[dp.PlaceVariable]})
			}
		}
	default:
		return p, nil, &parseErr{msg: "env create needs --products a,b[=PLACE] or --from-checkout"}
	}
	if len(p.Products) == 0 {
		return p, nil, fail("env create: no product runs in %s", a.env)
	}
	if errs := vmodel.PlanProblems(d, p); len(errs) > 0 {
		return p, nil, fail("%s", strings.Join(errs, "; "))
	}
	return p, committed, nil
}

// checkEnv refuses before the password what the arguments, the description and the info file can refuse.
func checkEnv(e *Env, args []string) (int, bool, error) {
	a, err := parseEnvArgs(e, args)
	if err != nil {
		return 2, true, err
	}
	if _, err := envContext(e, a.env); err != nil {
		return 1, true, err
	}
	d, err := e.description()
	if err != nil {
		return 1, true, err
	}
	if a.sub != envCreate {
		return 0, false, nil
	}
	if path, perr := vaultPath(e); perr == nil {
		if info := readInfo(path); info != nil {
			if sealed, _ := info["sealed"].(map[string]any); sealed[a.env] != nil {
				return 1, true, fail("the vault holds the environment %s already (its info file says so): icevault env fill-missing --env %s adds what it lacks", a.env, a.env)
			}
		}
	}
	if _, _, err := envPlan(d, a); err != nil {
		var pe *parseErr
		if asParse(err, &pe) {
			return 2, true, err
		}
		return 1, true, err
	}
	return 0, false, nil
}

func asParse(err error, pe **parseErr) bool {
	p, ok := err.(*parseErr)
	if ok {
		*pe = p
	}
	return ok
}

// runEnv is env create / env fill-missing on an unlocked vault of the vault model.
func runEnv(e *Env, args []string, out io.Writer, v *vault.Vault, plat *render.Project) (int, error) {
	a, err := parseEnvArgs(e, args)
	if err != nil {
		return 2, err
	}
	d := plat.D
	m, err := vmodel.Load(v)
	if err != nil {
		return 1, fail("%v", err)
	}
	if a.sub == envAdopt {
		return runAdopt(e, a, out, v, plat, m)
	}
	before, _ := sha256File(v.Path())
	var rep *vmodel.FillReport
	if a.sub == envCreate {
		p, committed, perr := envPlan(d, a)
		if perr != nil {
			return 1, perr
		}
		rep, err = vmodel.CreateEnv(m, d, a.env, p, committed)
	} else {
		committed, _ := render.ReadSettings(d.CommittedFile(a.env))
		rep, err = vmodel.FillMissing(m, d, a.env, committed)
	}
	if err != nil {
		return 1, fail("%v", err)
	}
	if errs := m.Check(); len(errs) > 0 {
		return 1, fail("the model would not be valid: %s", strings.Join(errs, "; "))
	}
	for _, c := range rep.Made {
		fmt.Fprintf(out, "  made connection    %s\n", c)
	}
	for _, c := range rep.Linked {
		fmt.Fprintf(out, "  linked connection  %s\n", c)
	}
	for _, x := range rep.Added {
		kind := "plain"
		if x.Secret {
			kind = "secret"
		}
		fmt.Fprintf(out, "  added  %-32s %-28s %s, %s\n", x.Where, x.Key, x.File, kind)
	}
	if len(rep.Added) == 0 && len(rep.Made) == 0 && len(rep.Linked) == 0 && a.sub == envFill {
		fmt.Fprintf(out, "env fill-missing: %s lacks nothing the project description asks of the owner\n", a.env)
		return 0, nil
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
	what := "filled"
	if a.sub == envCreate {
		what = "created"
	}
	fmt.Fprintf(out, "env %s: %s %s: %d empty entr%s to fill in, %d connection(s) made; no value was written (the window, or import, fills them in; what the system makes stays for the project's init)\n",
		a.sub, what, a.env, len(rep.Added), plural(len(rep.Added), "y", "ies"), len(rep.Made))
	afterChange(v.Path(), before, out)
	return 0, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
