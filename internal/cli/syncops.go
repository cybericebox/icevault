package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cybericebox/icevault/internal/bridge"
	"github.com/cybericebox/icevault/internal/kinds"
	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
)

// The commands that write a plaintext tree into the vault: import, recover, import-hcp, and the write-back of a session. They run SyncTree and
// ImportTree (internal/render/sync.go) on the writer of the vault model (bridge.Writer).

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == "--"+name || a == "-"+name || strings.HasPrefix(a, "--"+name+"=") {
			return true
		}
	}
	return false
}

// recordEnv notes in the info file that the vault holds env (what it held when read plus what the tree added).
func recordEnv(vaultFile string, plat *render.Project, snap *model.Snapshot, env string, treeRels []string) {
	names := map[string]bool{}
	if v, err := plat.View(snap, env, ""); err == nil {
		for rel := range v.Env {
			names[rel] = true
		}
		for rel := range v.Files {
			names[rel] = true
		}
	}
	covered, _, _ := plat.TreeFiles(treeRels, nil)
	for rel := range covered {
		names[rel] = true
	}
	held := map[string]any{}
	for _, k := range plat.D.KeptFiles {
		if k.Guard != "" {
			held[k.Guard] = false
		}
	}
	for rel := range names {
		if k := plat.D.Kept(rel); k != nil && k.Guard != "" {
			held[k.Guard] = true
		}
	}
	info := readInfo(vaultFile)
	if info == nil {
		info = freshInfo()
	}
	sealed, _ := info["sealed"].(map[string]any)
	if sealed == nil {
		sealed = map[string]any{}
	}
	at := nowStamp()
	if o, ok := sealed[env].(map[string]any); ok {
		if s, ok := o["at"].(string); ok && s != "" {
			at = s
		}
	}
	sealed[env] = map[string]any{keyFiles: len(names), "guards": held, "at": at}
	info["sealed"] = sealed
	_ = writeInfo(vaultFile, info)
}

// afterChange copies the vault to the destinations when the file changed.
func afterChange(vaultFile, before string, out io.Writer) {
	if now, err := sha256File(vaultFile); err == nil && now != before {
		makeCopies(vaultFile, out)
	}
}

// runImportReal is `import` (not a dry run) on an unlocked vault.
func runImportReal(e *Env, args []string, out io.Writer, o *opened) (int, error) {
	var file string
	env, site, err := envFlags("import", args, e, func(fs *flag.FlagSet) {
		fs.Bool("dry-run", false, "")
		fs.StringVar(&file, "file", "", "one extra file of the plaintext folder")
	})
	if err != nil {
		return 2, err
	}
	before, _ := sha256File(o.path)
	if file != "" {
		return importFile(e, out, o, file)
	}
	ec, err := envContext(e, env)
	if err != nil {
		return 1, err
	}
	if site != "" && !model.NameRE.MatchString(site) {
		return 1, fail("'%s' is not a site name (lower case letters, digits, - and _)", site)
	}
	if !isDir(ec.private) {
		return 1, fail("%s holds no secret files to import", ec.private)
	}
	opt := render.Options{Env: ec.name, Tree: render.FSSource{FS: os.DirFS(ec.private)}, Site: site}
	if extra := confExtra(e, ec.name); extra != nil {
		conf := o.plat.Conf()
		data, err := os.ReadFile(extra[conf])
		if err != nil {
			return 1, fail("%s cannot be read", extra[conf])
		}
		opt.Extra = map[string][]byte{conf: data}
	}
	_, lines, err := o.plat.ImportTree(o.k, o.snap, opt, ec.private)
	if cerr := o.k.Commit(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return 1, fail("%v", err)
	}
	recordEnv(o.path, o.plat, o.snap, ec.name, privateRels(ec.private))
	for _, ln := range lines {
		fmt.Fprintln(out, ln)
	}
	afterChange(o.path, before, out)
	return 0, nil
}

// resolveImportFile checks the file of `import --file` without the vault: under the plaintext folder of the checkout, not the vault itself, a
// regular file. It returns the path, the path relative to that folder and the file info.
func resolveImportFile(e *Env, file string) (string, string, os.FileInfo, error) {
	d, err := e.description()
	if err != nil {
		return "", "", nil, err
	}
	priv := plaintextRoot(d)
	p := file
	if !filepath.IsAbs(p) {
		p = filepath.Join(priv, file)
	}
	p = filepath.Clean(p)
	rel, err := filepath.Rel(priv, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", "", nil, fail("%s is not under %s", file, priv)
	}
	rel = filepath.ToSlash(rel)
	if vp, verr := vaultPath(e); verr == nil && (filepath.Clean(vp) == p || isUnder(p, filepath.Dir(vp))) {
		return "", "", nil, fail("the vault does not go into itself")
	}
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return "", "", nil, fail("%s does not exist", p)
	}
	return p, rel, st, nil
}

func importFile(e *Env, out io.Writer, o *opened, file string) (int, error) {
	p, rel, st, err := resolveImportFile(e, file)
	if err != nil {
		return 1, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return 1, err
	}
	lines, _, err := render.ImportExtra(o.k, o.snap, rel, data, int(st.Mode().Perm()), false, nil)
	if cerr := o.k.Commit(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return 1, fail("%v", err)
	}
	for _, ln := range lines {
		fmt.Fprintln(out, ln)
	}
	return 0, nil
}

// runRecover writes the files of a left-over session directory into the vault and removes it.
func runRecover(e *Env, args []string, out io.Writer, o *opened) (int, error) {
	var base string
	env, site, err := envFlags("recover", args, e, func(fs *flag.FlagSet) {
		fs.StringVar(&base, "base", "", "the folder of the session directory (default: the temp directory)")
	})
	if err != nil {
		return 2, err
	}
	ec, err := envContext(e, env)
	if err != nil {
		return 1, err
	}
	s, err := render.PickSite(o.snap, ec.name, site)
	if err != nil {
		return 1, fail("%v", err)
	}
	before, _ := sha256File(o.path)
	path := sessionDir(e, base, ec.name, s)
	if _, err := os.Lstat(path); err != nil {
		return 1, fail("no left-over session directory at %s", path)
	}
	if info, st := readOwner(path); st == ownerLive {
		return 1, fail("a run of '%s' is in progress (PID %d): recover would pull the files from under it; wait for the run to end", ec.name, info.PID)
	}
	if err := ownSessionDir(path); err != nil {
		return 1, err
	}
	rep, err := o.plat.SyncTree(o.k, o.snap, render.Options{Env: ec.name, Tree: render.FSSource{FS: os.DirFS(path)}, Site: s})
	if cerr := o.k.Commit(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return 1, fail("%v", err)
	}
	for _, ln := range rep.Lines {
		fmt.Fprintln(out, ln)
	}
	fmt.Fprintf(out, "recovered into the vault: %d new, %d changed; %d unchanged. Removing %s\n", rep.Added, rep.Changed, rep.Unchanged, path)
	_ = os.RemoveAll(path)
	removeOwner(path)
	afterChange(o.path, before, out)
	return 0, nil
}

// runImportHCP takes the token `terraform login` wrote into the vault as HCP_TOKEN of the external system hcp. The token is never printed (its length only).
func runImportHCP(e *Env, args []string, out io.Writer, o *opened) (int, error) {
	if _, err := parse("import-hcp", args, e, 0, nil); err != nil {
		return 2, err
	}
	before, _ := sha256File(o.path)
	path, token, err := hcpCredentials(e)
	if err := hcpError(path, token, err); err != nil {
		return 1, err
	}
	w, ok := o.k.(*bridge.Writer)
	if !ok {
		return 1, fail("import-hcp needs a vault of the vault model")
	}
	c := hcpConnection(w, o.plat.D)
	if f := c.Field("token"); f != nil && f.Value != "" {
		same := "DIFFERS from the file: the vault wins, nothing changed"
		if f.Value == token {
			same = "the same as the file"
		}
		fmt.Fprintf(out, "vault: the token of the connection %s exists already (%s)\n", c.Name, same)
		return 0, nil
	}
	c.Set("token", token, true)
	w.Changed()
	if err := w.Commit(); err != nil {
		return 1, fail("%v", err)
	}
	fmt.Fprintf(out, "vault: token imported into the connection %s (%d characters); %s is left in place\n", c.Name, len(token), path)
	afterChange(o.path, before, out)
	return 0, nil
}

// hcpConnection is the connection of kind hcp the token goes to: the one of the vault, else a new one (named as the description's state
// connection names it), made the state connection of every site whose kind keeps its state in one and has none yet.
func hcpConnection(w *bridge.Writer, d *project.Description) *vmodel.Connection {
	m := w.Model()
	for _, c := range m.Connections {
		if c.Kind == kinds.HCP {
			return c
		}
	}
	name := ""
	d.Walk(func(h project.Home) {
		if name == "" && h.Conn != nil && h.Conn.Kind == kinds.HCP {
			name = h.Conn.Name
		}
	})
	if name == "" {
		k, _ := kinds.ConnectionKind(kinds.HCP)
		name = k.Title
	}
	c := &vmodel.Connection{Name: name, Kind: kinds.HCP}
	m.Connections = append(m.Connections, c)
	for _, e := range m.Envs {
		for _, s := range e.Sites {
			if sk, ok := d.SiteKinds[s.Kind]; ok && sk.State != nil && sk.State.Kind == kinds.HCP && s.State == nil {
				s.State = c
			}
		}
	}
	return c
}

// syncBack is the end of a session after the tree: write what the run made into the vault (system files that disappeared are retired too) and
// report. It returns the files the run made that are not on the list (not kept). A file of the vault that is not on the list (one the owner added in
// the window, e.g. notes/runbook.md) was rendered into the tree by the session itself: it is not "made in the session"; when the run changed it, the
// change is not written back (an owner file is changed in the app) and that is said instead.
func syncBack(e *Env, o *opened, s *session) ([]string, error) {
	fromVault := map[string]string{} // rel -> sha256 of what the session rendered from the vault (before the write-back changes the snapshot)
	if files, rerr := o.plat.Render(o.snap, s.Env, s.Site, false); rerr == nil {
		for _, f := range files {
			fromVault[f.Rel] = sha256Hex(f.Data)
			wipe(f.Data)
		}
	}
	rep, err := o.plat.SyncTree(o.k, o.snap, render.Options{Env: s.Env, Tree: render.FSSource{FS: os.DirFS(s.Path)}, Site: s.Site, RetireMissing: true})
	if cerr := o.k.Commit(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	_, _, listed := o.plat.TreeFiles(privateRels(s.Path), nil)
	var unknown, ownerChanged []string
	for _, rel := range listed {
		sum, ok := fromVault[rel]
		if !ok {
			unknown = append(unknown, rel)
			continue
		}
		if data, rerr := os.ReadFile(filepath.Join(s.Path, filepath.FromSlash(rel))); rerr == nil {
			if sha256Hex(data) != sum {
				ownerChanged = append(ownerChanged, rel)
			}
			wipe(data)
		}
	}
	if rep.Added+rep.Changed > 0 || len(rep.Retired) > 0 {
		recordEnv(o.path, o.plat, o.snap, s.Env, privateRels(s.Path))
		fmt.Fprintf(e.Out, "vault: written back after the run: %d new, %d changed\n", rep.Added, rep.Changed)
		makeCopies(o.path, e.Out)
		for _, ln := range rep.Lines {
			fmt.Fprintln(e.Out, ln)
		}
	}
	if len(rep.Retired) > 0 {
		fmt.Fprintf(e.Out, "vault: %d replaced or removed system value(s) kept as retired: %s\n", len(rep.Retired), strings.Join(headN(rep.Retired, 8), ", "))
	}
	if len(rep.Blocked) > 0 {
		fmt.Fprintf(e.Out, "vault: %d owner entry(ies) the run changed were NOT written back (change them in the app): %s\n", len(rep.Blocked), strings.Join(headN(rep.Blocked, 8), ", "))
	}
	if len(ownerChanged) > 0 {
		fmt.Fprintf(e.Out, "vault: %d file(s) of the vault the run changed were NOT written back (not on the list; change them in the app): %s\n", len(ownerChanged), strings.Join(headN(ownerChanged, 8), ", "))
	}
	sort.Strings(unknown)
	return unknown, nil
}

func headN(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

// hcpCredentials reads the token `terraform login` wrote; the caller wipes it.
func hcpCredentials(e *Env) (path, token string, err error) {
	home := e.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	path = filepath.Join(home, ".terraform.d", "credentials.tfrc.json")
	data, err := os.ReadFile(path)
	var doc struct {
		Credentials map[string]struct {
			Token any `json:"token"`
		} `json:"credentials"`
	}
	if err == nil {
		err = json.Unmarshal(data, &doc)
	}
	wipe(data)
	token, _ = doc.Credentials["app.terraform.io"].Token.(string)
	return path, token, err
}

func hcpError(path, token string, err error) error {
	if err != nil {
		return fail("%s has no token for app.terraform.io: run `mise exec -- terraform login` first", path)
	}
	if token == "" {
		return fail("%s has no token for app.terraform.io", path)
	}
	return nil
}
