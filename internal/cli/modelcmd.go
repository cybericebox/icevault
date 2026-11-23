package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// The commands that need the settings model, on top of internal/model, internal/render and internal/vmodel.

var envNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,19}$`)

// defaultModel is the runner every Env gets when none was set.
type defaultModel struct{}

func (defaultModel) NeedsUnlock(cmd string, args []string) bool {
	return cmd != cmdImport || !hasFlag(args, "dry-run")
}

type envCtx struct{ name, private string }

func envContext(e *Env, name string) (envCtx, error) {
	if !envNameRE.MatchString(name) {
		return envCtx{}, fail("%q is not an environment name (lower case letters, digits and dashes)", name)
	}
	if model.IsReserved(name) {
		return envCtx{}, fail("'%s' is a reserved name", name)
	}
	d, err := e.description()
	if err != nil {
		return envCtx{}, err
	}
	return envCtx{name, filepath.Join(plaintextRoot(d), name)}, nil
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

func (defaultModel) Run(e *Env, cmd string, args []string, v *vault.Vault, out io.Writer) (int, error) {
	if cmd == "import" && hasFlag(args, "dry-run") {
		return runImport(e, args, out)
	}
	plat, err := loadProject(e)
	if err != nil {
		return 1, err
	}
	if !vmodel.IsModel(v) {
		return 1, errOldLayout(v)
	}
	return runOnModel(e, cmd, args, v, out, plat)
}

// errOldLayout refuses a vault that is not in the vault model (the layout of IceVault before 0.3).
func errOldLayout(v *vault.Vault) error {
	return fail("%s holds no vault model: a vault of the layout before it (IceVault 0.2) is moved with IceVault 0.4 first (icevault migrate --apply, or the offer of its window); a new vault is made with icevault init-vault", v.Path())
}

func vaultPathOr(e *Env) string { p, _ := vaultPath(e); return p }

// writesVault: the commands of the model that open the vault for writing (import, recover, import-hcp, visibility --apply; session in seam.go).
func writesVault(cmd string, args []string) bool {
	switch cmd {
	case "import", cmdRecover, cmdImportHCP, cmdEnv:
		return true
	case cmdVisibility:
		return hasFlag(args, "apply")
	}
	return false
}

func notPortedCmd(e *Env, cmd, why string) (int, error) {
	fmt.Fprintf(e.Err, "icevault: %s is not available (it waits for %s)\n", cmd, why)
	return notPorted, nil
}

func envFlags(name string, args []string, e *Env, setup func(fs *flag.FlagSet)) (env, site string, err error) {
	_, err = parse(name, args, e, 0, func(fs *flag.FlagSet) {
		fs.StringVar(&env, "env", "", "environment")
		fs.StringVar(&site, "site", "", "site")
		if setup != nil {
			setup(fs)
		}
	})
	return
}

func runView(e *Env, args []string, out io.Writer, plat *render.Project, snap *model.Snapshot) error {
	var item string
	env, site, err := envFlags("view", args, e, func(fs *flag.FlagSet) { fs.StringVar(&item, "item", "", "SECTION/ITEM") })
	if err != nil {
		return err
	}
	if item != "" {
		ref, ok := model.SplitRef(item)
		if !ok {
			return fail("--item is SECTION/ITEM, for example providers/aws")
		}
		rows, err := plat.ViewRows(snap, "", &ref, "")
		if err != nil {
			return fail("%v", err)
		}
		printView(out, "item "+ref.String(), rows)
		return nil
	}
	ec, err := envContext(e, env)
	if err != nil {
		return err
	}
	s, err := render.PickSite(snap, ec.name, site)
	if err != nil {
		return fail("%v", err)
	}
	rows, err := plat.ViewRows(snap, ec.name, nil, s)
	if err != nil {
		return fail("%v", err)
	}
	title := fmt.Sprintf("environment '%s'", ec.name)
	if s != "" {
		title += fmt.Sprintf(" on site '%s'", s)
	}
	printView(out, title+" (linked items included)", rows)
	return nil
}

// writeInto makes path with the right mode from the first byte (a file next to it, then a rename); parent directories get 0700.
func writeInto(path string, mode os.FileMode, data []byte) error {
	d := filepath.Dir(path)
	var made []string
	for probe := d; probe != "" && probe != filepath.Dir(probe) && !isDir(probe); probe = filepath.Dir(probe) {
		made = append(made, probe)
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	for _, m := range made {
		_ = os.Chmod(m, 0o700)
	}
	tmp := filepath.Join(d, "."+filepath.Base(path)+".tmp-secrets")
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, mode)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

func runExport(e *Env, args []string, out io.Writer, plat *render.Project, snap *model.Snapshot) error {
	var to, file string
	env, site, err := envFlags("export", args, e, func(fs *flag.FlagSet) {
		fs.StringVar(&to, "to", "", "a new or empty directory: it will hold PLAINTEXT")
		fs.StringVar(&file, "file", "", "one extra file")
	})
	if err != nil {
		return err
	}
	if to == "" {
		return &parseErr{msg: "export needs --to DIR"}
	}
	if file != "" {
		rel := strings.TrimPrefix(filepath.ToSlash(file), filepath.ToSlash(filepath.Clean(plat.D.Checkout.Plaintext))+"/")
		fe, ok := snap.Extras[rel]
		if !ok {
			return fail("the vault holds no extra file '%s'", rel)
		}
		if err := os.MkdirAll(to, 0o700); err != nil {
			return err
		}
		dest := filepath.Join(to, filepath.FromSlash(rel))
		if err := writeInto(dest, 0o600, fe.Data); err != nil {
			return err
		}
		fmt.Fprintf(out, "WARNING: %s is PLAINTEXT. Delete it when you are done.\n", dest)
		return nil
	}
	ec, err := envContext(e, env)
	if err != nil {
		return err
	}
	s, err := render.PickSite(snap, ec.name, site)
	if err != nil {
		return fail("%v", err)
	}
	if ents, err := os.ReadDir(to); err == nil && len(ents) > 0 {
		return fail("%s is not empty", to)
	}
	if !render.Holds(snap, ec.name) {
		return fail("the vault holds nothing for '%s'", ec.name)
	}
	if err := render.CheckLinks(snap, ec.name); err != nil {
		return fail("%v", err)
	}
	files, err := plat.Render(snap, ec.name, s, true)
	if err != nil {
		return fail("%v", err)
	}
	if err := os.MkdirAll(to, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(to, 0o700)
	for _, f := range files {
		if err := writeInto(filepath.Join(to, filepath.FromSlash(f.Rel)), os.FileMode(f.Mode), f.Data); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "WARNING: %s now holds %d secret file(s) in PLAINTEXT. Delete it when you are done (rm -rf %s).\n", to, len(files), to)
	return nil
}

func runExportApp(e *Env, args []string, out io.Writer, plat *render.Project, snap *model.Snapshot) error {
	var app, to string
	var force, dry bool
	env, site, err := envFlags("export-app", args, e, func(fs *flag.FlagSet) {
		fs.StringVar(&app, "app", "", "the app")
		fs.StringVar(&to, "to", "", "the app's directory")
		fs.BoolVar(&force, "force", false, "replace an existing file")
		fs.BoolVar(&dry, "dry-run", false, "print the variable names and where they come from; write nothing")
	})
	if err != nil {
		return err
	}
	ec, err := envContext(e, env)
	if err != nil {
		return err
	}
	if app == "" {
		return &parseErr{msg: "export-app needs --app"}
	}
	d, err := e.description()
	if err != nil {
		return err
	}
	a := d.App(app)
	if a == nil {
		return &parseErr{msg: fmt.Sprintf("unknown app %q: one of %s", app, strings.Join(d.AppNames(), ", "))}
	}
	s, err := render.PickSite(snap, ec.name, site)
	if err != nil {
		return fail("%v", err)
	}
	if !render.Holds(snap, ec.name) {
		return fail("the vault holds nothing for '%s'", ec.name)
	}
	appDir := to
	if appDir == "" {
		appDir = appDirOf(d, a)
	}
	if !isDir(appDir) {
		return fail("%s is not a directory (the checkout of %s the project description names; --to DIR names another)", appDir, app)
	}
	example := ""
	if !a.All {
		ex := filepath.Join(appDir, appExampleOf(a))
		data, err := os.ReadFile(ex)
		if err != nil {
			return fail("%s does not exist: it names the variables the app needs", ex)
		}
		example = string(data)
	}
	text, report, err := plat.AppFileText(snap, ec.name, a, example, s)
	if err != nil {
		return fail("%v", err)
	}
	target := filepath.Join(appDir, ".env")
	for _, r := range report {
		fmt.Fprintf(out, "  %s  <- %s\n", r.Name, r.Source)
	}
	if dry {
		fmt.Fprintf(out, "would write %d variable(s) to %s (dry run: nothing written)\n", len(report), target)
		return nil
	}
	if _, code, err := e.Exec.Run("git", []string{"-C", appDir, "check-ignore", "-q", ".env"}, nil, 30*time.Second); err != nil || code != 0 {
		return fail("%s is not git-ignored: refusing to write secrets there (add .env to its .gitignore)", target)
	}
	if _, err := os.Lstat(target); err == nil && !force {
		return fail("%s exists: --force replaces it (it is not read)", target)
	}
	if err := writeInto(target, 0o600, []byte(text)); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %d variable(s) to %s (mode 0600, PLAINTEXT, git-ignored)\n", len(report), target)
	return nil
}

// privateRels lists the regular files below a private tree (symbolic links are not followed or listed), sorted.
func privateRels(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out
}

// appDirOf is the checkout of an app: its dir in the description (relative to the project checkout), else ../<name>.
func appDirOf(d *project.Description, a *project.App) string {
	rel := a.Dir
	if rel == "" {
		rel = "../" + a.Name
	}
	return filepath.Join(checkoutDir(d), filepath.FromSlash(rel))
}

// appExampleOf is the example file of an app.
func appExampleOf(a *project.App) string {
	if a.Example != "" {
		return a.Example
	}
	return render.AppExample
}

// confExtra is the committed general settings file of an environment, when the checkout has one.
func confExtra(e *Env, env string) map[string]string {
	d, err := e.description()
	if err != nil {
		return nil
	}
	if p := committedSettings(d, env); isFile(p) {
		return map[string]string{d.GeneralFile(): p}
	}
	return nil
}

func extraRels(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func runStatus(e *Env, args []string, out io.Writer, plat *render.Project, snap *model.Snapshot) error {
	env, site, err := envFlags("status", args, e, nil)
	if err != nil {
		return err
	}
	ec, err := envContext(e, env)
	if err != nil {
		return err
	}
	s, err := render.PickSite(snap, ec.name, site)
	if err != nil {
		return fail("%v", err)
	}
	st, err := plat.StatusOf(snap, ec.name, s)
	if err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(out, "vault: environment %s: %d settings file(s) with %d variable(s), %d other file(s), %d retired\n", ec.name, st.Settings, st.Variables, st.OtherFiles, st.Retired)
	if len(st.Uses) > 0 {
		fmt.Fprintf(out, "  uses: %s\n", strings.Join(st.Uses, ", "))
	}
	for _, b := range st.BrokenLinks {
		fmt.Fprintf(out, "  LINK PROBLEM: links %s, which does not exist\n", b)
	}
	for _, sh := range st.Shadowed {
		fmt.Fprintf(out, "  %s\n", sh)
	}
	for _, f := range st.Files {
		extra := ""
		if f.FromLinks > 0 {
			extra += fmt.Sprintf(", %d from linked items", f.FromLinks)
		}
		if len(f.Empty) > 0 {
			extra += fmt.Sprintf(", %d empty", len(f.Empty))
		}
		fmt.Fprintf(out, "  %s: %d variable(s)%s\n", f.Rel, f.Variables, extra)
		for _, v := range f.Vars {
			m := v.Managed
			if m == "" {
				m = "owner"
			}
			fmt.Fprintf(out, "      %-36s %-22s %s\n", v.Name, v.Source, m)
		}
	}
	if line := requiredValuesLine(e, ec, snap, plat, s); line != "" {
		fmt.Fprintln(out, line)
	}
	covered, _, _ := plat.TreeFiles(privateRels(ec.private), nil)
	if len(covered) > 0 {
		fmt.Fprintf(out, "plaintext copies still on disk in %s: %d file(s): the vault is used and these are ignored; `purge-plaintext --env %s` removes the ones the vault holds\n", ec.private, len(covered), ec.name)
	} else {
		fmt.Fprintf(out, "no plaintext secret files in %s\n", ec.private)
	}
	if path, err := vaultPath(e); err == nil {
		printCopies(path, out)
	}
	return nil
}

func printCopies(vaultFile string, out io.Writer) {
	if !isFile(vaultFile) {
		return
	}
	m := readInfo(vaultFile)
	if m == nil {
		m = freshInfo()
	}
	if len(m.destinations()) > 0 {
		listCopies(vaultFile, out)
		return
	}
	cur, _ := sha256File(vaultFile)
	seen := map[string]bool{}
	var current []string
	copies := m.copies()
	for _, c := range copies {
		if c["sha256"] == cur {
			to, _ := c["to"].(string)
			if !seen[to] {
				seen[to] = true
				current = append(current, to)
			}
		}
	}
	sort.Strings(current)
	switch {
	case len(copies) == 0:
		fmt.Fprintln(out, "vault copies: none recorded: `icevault copies add DIR` (standing one-way copies) or `copy --to DIR` (once); keep at least two, in other places")
	case len(current) > 0:
		tail := ""
		if len(current) < 2 {
			tail = "; keep at least two"
		}
		fmt.Fprintf(out, "vault copies up to date: %d (%s)%s\n", len(current), strings.Join(current, ", "), tail)
	default:
		last := copies[0]
		for _, c := range copies {
			if a, _ := c["at"].(string); a > fmt.Sprint(last["at"]) {
				last = c
			}
		}
		at, to := fmt.Sprint(last["at"]), fmt.Sprint(last["to"])
		if last["at"] == nil {
			at = "?"
		}
		if last["to"] == nil {
			to = "?"
		}
		fmt.Fprintf(out, "vault changed since the last copy (%s to %s): `icevault copy --to <dir>`\n", at, to)
	}
}

func runVisibility(e *Env, args []string, out io.Writer, plat *render.Project, snap *model.Snapshot, st vaultStore) error {
	var apply bool
	env, _, err := envFlags("visibility", args, e, func(fs *flag.FlagSet) {
		fs.BoolVar(&apply, "apply", false, "change the variables marked change")
	})
	if err != nil {
		return err
	}
	ec, err := envContext(e, env)
	if err != nil {
		return err
	}
	rows, err := plat.VisibilityRows(snap, ec.name)
	if err != nil {
		return fail("%v", err)
	}
	if len(rows) == 0 {
		fmt.Fprintln(out, "every owner variable already has the visibility the rule gives it")
		return nil
	}
	width := 0
	for _, r := range rows {
		width = max(width, len(r.Item+"/"+r.Group+"/"+r.Key))
	}
	fmt.Fprintf(out, "%-*s  current  proposed  verdict\n", width, "variable")
	done, todo := 0, 0
	for _, r := range rows {
		shown := r.Verdict
		if r.Verdict == "change" {
			todo++
			if apply {
				notes, err := model.EntryNotesSet(model.ManagedOwner, r.Proposed, r.Entry.Labels, r.Entry.Description, "", r.Entry.ManagedSet)
				if err == nil {
					err = st.SetNotes(r.Entry.Path, notes)
				}
				if err != nil {
					return fail("%v", err)
				}
				r.Entry.Vis, r.Entry.VisBy = r.Proposed, ""
				shown, done = "changed", done+1
			}
		}
		fmt.Fprintf(out, "%-*s  %-7s  %-8s  %s\n", width, r.Item+"/"+r.Group+"/"+r.Key, r.Current, r.Proposed, shown)
	}
	if apply {
		fmt.Fprintf(out, "%d changed, %d left as they are\n", done, len(rows)-done)
		return st.Commit()
	}
	fmt.Fprintf(out, "%d can be changed with --apply; %d stay as they are (chosen by the owner, sealed, or changed by hand)\n", todo, len(rows)-todo)
	return nil
}

func runImport(e *Env, args []string, out io.Writer) (int, error) {
	var dry bool
	var file string
	env, _, err := envFlags("import", args, e, func(fs *flag.FlagSet) {
		fs.BoolVar(&dry, "dry-run", false, "print what would change, write nothing")
		fs.StringVar(&file, "file", "", "one extra file of the plaintext folder")
	})
	if err != nil {
		return 2, err
	}
	if file != "" {
		rel := filepath.ToSlash(file)
		fmt.Fprintf(out, "  would look at %s\n", rel)
		return 0, nil
	}
	ec, err := envContext(e, env)
	if err != nil {
		return 1, err
	}
	plat, err := loadProject(e)
	if err != nil {
		return 1, err
	}
	extra := confExtra(e, ec.name)
	covered, skipped, unknown := plat.TreeFiles(privateRels(ec.private), extraRels(extra))
	var rels []string
	for r := range covered {
		rels = append(rels, r)
	}
	sort.Strings(rels)
	for _, r := range rels {
		fmt.Fprintf(out, "  would look at %s\n", r)
	}
	fmt.Fprintf(out, "would import: %d file(s) are covered, %d left out on purpose, %d not covered; which differ from the vault is known only after unlocking (status)\n", len(rels), len(skipped), len(unknown))
	return 0, nil
}

func runPurge(e *Env, args []string, out io.Writer, plat *render.Project, snap *model.Snapshot) error {
	var yes, force bool
	env, site, err := envFlags("purge-plaintext", args, e, func(fs *flag.FlagSet) {
		fs.BoolVar(&yes, "yes", false, "really delete")
		fs.BoolVar(&force, "force", false, "delete even without an up-to-date copy of the vault on another volume")
	})
	if err != nil {
		return err
	}
	ec, err := envContext(e, env)
	if err != nil {
		return err
	}
	s, err := render.PickSite(snap, ec.name, site)
	if err != nil {
		return fail("%v", err)
	}
	if yes {
		path, err := vaultPath(e)
		if err != nil {
			return err
		}
		if err := requireCopy(path, force, e); err != nil {
			return err
		}
	}
	view, err := plat.View(snap, ec.name, s)
	if err != nil {
		return fail("%v", err)
	}
	extra := confExtra(e, ec.name)
	covered, _, _ := plat.TreeFiles(privateRels(ec.private), extraRels(extra))
	var rels []string
	for r := range covered {
		rels = append(rels, r)
	}
	sort.Strings(rels)
	var same, differ, absent []string
	paths := map[string]string{}
	for _, rel := range rels {
		p := extra[rel]
		if p == "" {
			p = filepath.Join(ec.private, filepath.FromSlash(rel))
		}
		paths[rel] = p
		if covered[rel].Kind == "env" {
			ef := view.Env[rel]
			if ef == nil {
				absent = append(absent, rel)
				continue
			}
			text, err := os.ReadFile(p)
			if err != nil {
				return fail("%s cannot be read", p)
			}
			_, vars := render.ParseEnv(string(text))
			equal := len(vars) == ef.Variables.Len()
			for _, v := range vars {
				got, ok := ef.Variables.Get(v.Name)
				equal = equal && ok && got == render.StoredValue(v.Value, plat.VarManagedIn(rel, v.Name))
			}
			if equal {
				same = append(same, rel)
			} else {
				differ = append(differ, rel)
			}
			continue
		}
		fe := view.Files[rel]
		if fe == nil {
			absent = append(absent, rel)
			continue
		}
		if sum, _ := sha256File(p); sum == fe.Sha {
			same = append(same, rel)
		} else {
			differ = append(differ, rel)
		}
	}
	verb, past := "would delete", "would delete"
	if yes {
		verb, past = "delete", "deleted"
	}
	for _, r := range same {
		fmt.Fprintf(out, "  %-13s %s\n", verb, r)
	}
	for _, r := range differ {
		fmt.Fprintf(out, "  kept (differs from the vault) %s\n", r)
	}
	for _, r := range absent {
		fmt.Fprintf(out, "  kept (not in the vault)       %s\n", r)
	}
	if yes {
		for _, r := range same {
			_ = os.Remove(paths[r])
		}
	}
	tail := ""
	if !yes && len(same) > 0 {
		tail = " (repeat with --yes)"
	}
	fmt.Fprintf(out, "%s: %d; kept: %d%s\n", past, len(same), len(differ)+len(absent), tail)
	return nil
}

const noCopyReason = "purge-plaintext needs an up-to-date copy of the vault on ANOTHER volume (another disk, a USB stick, a synced folder on another disk): `icevault copies add DIR`, then run it again (`copies list` shows what is where; --force overrides with a typed confirmation)"

// copyElsewhere says whether a destination on another volume holds a copy that equals the vault now (the info file and the files decide, no password).
func copyElsewhere(vaultFile string) bool {
	for _, r := range copiesStatus(vaultFile) {
		if r.reachable && r.otherVolume && r.same {
			return true
		}
	}
	return false
}

// requireCopy: purge-plaintext may only delete the plaintext when the vault exists elsewhere: a destination on ANOTHER volume holds a copy that equals
// the vault now. --force with a typed confirmation overrides.
func requireCopy(vaultFile string, force bool, e *Env) error {
	if copyElsewhere(vaultFile) {
		return nil
	}
	why := noCopyReason
	if !force {
		return errors.New(why)
	}
	typed, err := e.Ask("Type 'delete without a copy' to delete the plaintext although no up-to-date copy of the vault is elsewhere: ")
	if err != nil || strings.TrimSpace(string(typed)) != "delete without a copy" {
		return errors.New(why)
	}
	return nil
}

func listCopies(vaultFile string, out io.Writer) {
	rows := copiesStatus(vaultFile)
	if len(rows) == 0 {
		fmt.Fprintln(out, "no destination: `icevault copies add DIR`")
		return
	}
	for _, r := range rows {
		fmt.Fprintln(out, copyRowLine(r))
	}
}

// The check of required values is the description's required-check: a script of the checkout, run with a fixed interpreter and no shell on a
// materialised tree, only while the user trusts the description (trust.go). Without one the line "required values" is not printed.

// hookArgs are the arguments of the check: each argument of the description with its placeholders replaced inside it, so a value never
// becomes more than one argument and no shell reads it.
func hookArgs(args []string, vals map[string]string) []string {
	pairs := make([]string, 0, 2*len(vals))
	for k, v := range vals {
		pairs = append(pairs, "{"+k+"}", v)
	}
	r := strings.NewReplacer(pairs...)
	argv := make([]string, 0, len(args))
	for _, a := range args {
		argv = append(argv, r.Replace(a))
	}
	return argv
}

// runHook runs the check (the interpreter, the private copy of the checked script and hookArgs; no shell) and returns its output (stdout and stderr together). Tests replace it.
var runHook = func(dir string, argv []string) ([]byte, int, error) {
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- an allowed interpreter and a script inside the checkout of a trusted description
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out, ee.ExitCode(), nil
	}
	return out, 0, err
}

// providerWordRE is what {provider} may be: one word that no option parser takes for an option.
var providerWordRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

var requiredRowRE = regexp.MustCompile(`^  (\S+)\s+([A-Za-z_][A-Za-z0-9_]*)$`)

// providerOf is the provider word of an environment: the derived variable from site.provider in the vault, else in its committed settings.
func providerOf(plat *render.Project, snap *model.Snapshot, env string) string {
	if p := plat.ProviderName(snap, env); p != "" {
		return p
	}
	name := ""
	for _, x := range plat.D.Derived {
		if x.From == "site.provider" {
			name = x.Name
		}
	}
	prov := ""
	if data, err := os.ReadFile(committedSettings(plat.D, env)); err == nil && name != "" {
		for _, ln := range strings.Split(string(data), "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(ln), "="); ok && k == name {
				prov = strings.TrimSpace(v)
			}
		}
	}
	return prov
}

// requiredValuesLine is the line of `status` about the required values that still hold a placeholder, or "" when there is no check configured, no cloud
// provider, or the check cannot run.
func requiredValuesLine(e *Env, ec envCtx, snap *model.Snapshot, plat *render.Project, site string) string {
	rc := plat.D.RequiredCheck
	if rc == nil {
		return ""
	}
	prov := providerOf(plat, snap, ec.name)
	settings, _ := plat.Settings(snap, ec.name, site)
	if cond, err := project.ParseWhen(rc.When); err != nil || !cond.Holds(plat.D.Getter(func(k string) string { return settings[k] })) {
		return ""
	}
	c, err := readChecked(plat.D)
	if err != nil {
		return "required values: not checked: " + err.Error()
	}
	if !trusted(e.Getenv, c) {
		return "required values: not checked: the project description or its script is not trusted on this machine (" + plat.D.Path + "; `icevault trust` after reading both)"
	}
	if !providerWordRE.MatchString(prov) {
		return fmt.Sprintf("required values: not checked: the provider word %q is not a word (lower case letters, digits, _ and -)", prov)
	}
	files, err := plat.Render(snap, ec.name, site, false)
	if err != nil || len(files) == 0 {
		return ""
	}
	// a fresh private folder of its own (0700): never the folder of a session, which may hold what a failed write-back left
	tmp, err := os.MkdirTemp("", plat.D.SessionPrefix()+"-status-")
	if err != nil {
		return ""
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	for _, f := range files {
		if writeInto(filepath.Join(tmp, filepath.FromSlash(f.Rel)), os.FileMode(f.Mode), f.Data) != nil {
			return ""
		}
	}
	out, _, err := runChecked(checkoutDir(plat.D), c, rc.Interpreter, hookArgs(rc.Args, map[string]string{"tree": tmp, "provider": prov, "env": ec.name}))
	if err != nil {
		return ""
	}
	var names []string
	inside := false
	for _, ln := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(ln, rc.Heading) {
			inside = true
			continue
		}
		if m := requiredRowRE.FindStringSubmatch(ln); inside && m != nil {
			names = append(names, m[1]+" "+m[2])
		} else if inside {
			inside = false
		}
	}
	if len(names) == 0 {
		return "required values: all set"
	}
	return "required values: still to fill in (file name): " + strings.Join(names, "; ")
}
