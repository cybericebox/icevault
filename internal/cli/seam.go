package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/cybericebox/icevault/internal/bridge"
	"github.com/cybericebox/icevault/internal/kinds"
	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// The seam for the project's scripts: commands with machine-readable output (where, guard, settings, session). Nothing here prints a secret
// value: the output is paths, names, counts and settings; `settings` writes to a file the caller names (or to stdout only when the caller says
// "-").

const noVaultVar = "ICEVAULT_NO_VAULT"

// sessionVars are the names a session gives the scripts it runs (the description's session.variables, else these).
func sessionVars(e *Env) project.SessionVariables {
	if d, err := e.description(); err == nil {
		return d.SessionVars()
	}
	return project.SessionVariables{}.WithDefaults()
}

// tfDirPrefix is the start of the name of a session's own folder of the Terraform credentials and the settings: <prefix>-tf-.
func tfDirPrefix(e *Env) string {
	if d, err := e.description(); err == nil {
		return d.SessionPrefix() + "-tf-"
	}
	return "icevault-tf-"
}

// refreshInfo records which environments the vault holds in the info file, so the checks that run without the password know.
func refreshInfo(vaultFile string, plat *render.Project, snap *model.Snapshot) {
	words := map[string]bool{}
	for _, k := range plat.D.KeptFiles {
		if k.Guard != "" {
			words[k.Guard] = true
		}
	}
	info := readInfo(vaultFile)
	if info == nil {
		info = freshInfo()
	}
	old, _ := info["sealed"].(map[string]any)
	fresh := map[string]any{}
	for _, env := range render.EnvNames(snap) {
		v, err := plat.View(snap, env, "")
		if err != nil || (len(v.Env) == 0 && len(v.Files) == 0) {
			continue
		}
		held := map[string]any{}
		for w := range words {
			held[w] = false
		}
		for rel := range v.Files {
			if k := plat.D.Kept(rel); k != nil && k.Guard != "" {
				held[k.Guard] = true
			}
		}
		at := nowStamp()
		if o, ok := old[env].(map[string]any); ok {
			if s, ok := o["at"].(string); ok && s != "" {
				at = s
			}
		}
		fresh[env] = map[string]any{keyFiles: len(v.Env) + len(v.Files), "guards": held, "at": at}
	}
	a, _ := json.Marshal(old)
	b, _ := json.Marshal(fresh)
	if !bytes.Equal(a, b) || !isFile(infoPath(vaultFile)) {
		info["sealed"] = fresh
		_ = writeInfo(vaultFile, info)
	}
}

// opened is an unlocked vault with its snapshot, for the commands that work on one.
type opened struct {
	path string
	v    *vault.Vault
	k    vaultStore
	snap *model.Snapshot
	plat *render.Project
}

func (o *opened) close() { o.v.Close() }

// openModel opens the vault for a command of the seam. readOnly: a vault of the vault model is read through its projection (settings); the
// session, which writes back, refuses one.
func openModel(e *Env, _ bool) (*opened, error) {
	path, err := vaultPath(e)
	if err != nil {
		return nil, err
	}
	plat, err := loadProject(e)
	if err != nil {
		return nil, err
	}
	v, err := unlock(path, e)
	if err != nil {
		return nil, err
	}
	if !vmodel.IsModel(v) {
		v.Close()
		return nil, errOldLayout(v)
	}
	w, err := modelWriter(e, v, plat)
	if err != nil {
		v.Close()
		return nil, err
	}
	snap, _ := w.Snapshot()
	refreshInfo(path, plat, snap)
	return &opened{path, v, w, snap, plat}, nil
}

// model is the vault model the command changes (the writer's), nil when the store is another.
func (o *opened) model() *vmodel.Vault {
	if w, ok := o.k.(*bridge.Writer); ok {
		return w.Model()
	}
	return nil
}

// siteKind is the site kind of the one site of an environment ("" when it has none or several).
func (o *opened) siteKind(env string) string {
	m := o.model()
	if m == nil {
		return ""
	}
	if e := m.Env(env); e != nil && len(e.Sites) == 1 {
		return e.Sites[0].Kind
	}
	return ""
}

// stateToken is the token of the connection that keeps the Terraform state of the environment's site (a connection of kind hcp): the token
// field of the site's state connection, else of the one hcp connection of the vault. "" when none. Never printed.
func (o *opened) stateToken(env string) string {
	m := o.model()
	if m == nil {
		return ""
	}
	if e := m.Env(env); e != nil && len(e.Sites) == 1 && e.Sites[0].State != nil {
		if f := e.Sites[0].State.Field("token"); f != nil {
			return f.Value
		}
	}
	var only *vmodel.Connection
	for _, c := range m.Connections {
		if c.Kind == kinds.HCP {
			if only != nil {
				return ""
			}
			only = c
		}
	}
	if only != nil {
		if f := only.Field("token"); f != nil {
			return f.Value
		}
	}
	return ""
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ---------------------------------------------------------------- where

func cmdWhere(args []string, e *Env) error {
	var remember bool
	if _, err := parse("where", args, e, 0, func(fs *flag.FlagSet) {
		fs.BoolVar(&remember, "remember", false, "save the project checkout for programs with no shell environment (the window opened from Finder)")
	}); err != nil {
		return err
	}
	if remember {
		if e.Root == "" {
			return fail("the project checkout is not found: set ICEVAULT_ROOT, then run this again")
		}
		f, err := rememberRoot(e.Getenv, e.Root)
		if err != nil {
			return err
		}
		fmt.Fprintf(e.Err, "location saved in %s: %s\n", f, e.Root)
		return nil // nothing else: --remember reads no vault file and no info file
	}
	path, err := vaultPath(e)
	if err != nil {
		return err
	}
	exists := isFile(path)
	out := map[string]any{"vault": path, "exists": exists, "enabled": exists && e.Getenv(noVaultVar) == "", "info_file": infoPath(path), "info": nil,
		"session_var_set": e.Getenv(sessionVars(e).Marker) != ""}
	if info := readInfo(path); info != nil {
		out["info"] = info
	}
	return printJSON(e.Out, out)
}

// ---------------------------------------------------------------- guard

// realPath is p with its symbolic links resolved: the longest part of it that exists, resolved, with the rest (a folder a script is about to
// make) appended. Two spellings of one folder compare equal.
func realPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	cur, rest := abs, ""
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// envOfPrivate: the checkout and the environment of a plaintext tree <checkout>/<plaintext>/<env> of the project description, both paths compared
// with their links resolved. An error when the description cannot be read: the guards then refuse instead of letting a run through.
func envOfPrivate(e *Env, private string) (root, env string, ok bool, err error) {
	d, err := e.description()
	if err != nil {
		return "", "", false, err
	}
	p := realPath(private)
	if filepath.Dir(p) == realPath(plaintextRoot(d)) {
		return checkoutDir(d), filepath.Base(p), true, nil
	}
	return "", "", false, nil
}

// vaultMayHold answers from the info file without a password: "no", "yes" (the info file says so) or "unknown" (a vault exists and nothing says
// what is in it). guard "": any secret of the environment; else a file of the kept-files rule with that guard word.
func vaultMayHold(e *Env, private, guard string) (vaultFile, env, state string, err error) {
	if e.Getenv(noVaultVar) != "" {
		return "", "", "no", nil
	}
	var ok bool
	_, env, ok, err = envOfPrivate(e, private)
	if err != nil {
		return "", "", "", err
	}
	if !ok || e.Getenv(sessionVars(e).Marker) != "" {
		return "", "", "no", nil
	}
	vaultFile, perr := vaultPath(e)
	if perr != nil || !isFile(vaultFile) {
		return vaultFile, env, "no", nil
	}
	info := readInfo(vaultFile)
	if info == nil {
		return vaultFile, env, "unknown", nil
	}
	sealed, _ := info["sealed"].(map[string]any)
	d, ok := sealed[env].(map[string]any)
	if !ok {
		return vaultFile, env, "no", nil
	}
	if guard == "" {
		return vaultFile, env, "yes", nil
	}
	held, ok := d["guards"].(map[string]any)
	if !ok {
		return vaultFile, env, "unknown", nil // an info file written before the guards were recorded: the next unlock tells
	}
	if h, _ := held[guard].(bool); h {
		return vaultFile, env, "yes", nil
	}
	if _, known := held[guard]; !known {
		return vaultFile, env, "unknown", nil
	}
	return vaultFile, env, "no", nil
}

func refusal(vaultFile, env, state, private, what string) error {
	holds := "may hold"
	if state == "yes" {
		holds = "holds"
	}
	return fail("the vault %s %s the secrets of '%s', and this run reads plaintext from %s: to %s here would make secrets that clash with the vault's. "+
		"Run the command in a session of the vault (it unlocks the vault and uses its secrets), or see `icevault status --env %s`",
		vaultFile, holds, env, private, what, env)
}

// guardDirRE is the folder pattern of a guarded rule: the rule's pattern without its "/.+", below a plaintext tree.
func guardDirRE(k *project.KeptFile) *regexp.Regexp {
	re, err := regexp.Compile("^(.*)/(?:" + strings.TrimSuffix(k.Pattern, "/.+") + ")/?$")
	if err != nil {
		return nil
	}
	return re
}

// cmdGuard: sealed --private DIR [--what TEXT] | <guard word> --dir DIR | token-file PATH | plaintext --private DIR [--env E].
// Exit 0: allowed (or the answer is on stdout as JSON); exit 1: refused, one line on stderr.
func cmdGuard(args []string, e *Env) error {
	if len(args) == 0 {
		return &parseErr{msg: "guard needs sealed, a guard word of the project description, token-file or plaintext"}
	}
	sub, rest := args[0], args[1:]
	var private, dir, what, env string
	pos, err := parse("guard "+sub, rest, e, 1, func(fs *flag.FlagSet) {
		fs.StringVar(&private, "private", "", "the plaintext tree")
		fs.StringVar(&dir, "dir", "", "the directory")
		fs.StringVar(&what, "what", "make new secrets", "what the run wanted to do")
		fs.StringVar(&env, "env", "", "environment")
	})
	if err != nil {
		return err
	}
	switch sub {
	case "sealed":
		if private == "" {
			return &parseErr{msg: "guard sealed needs --private DIR"}
		}
		v, en, state, err := vaultMayHold(e, private, "")
		if err != nil {
			return fail("cannot tell whether the vault holds the secrets of %s, so this run is refused: %v", private, err)
		}
		if state != "no" {
			return refusal(v, en, state, private, what)
		}
		return nil
	case "token-file":
		if len(pos) != 1 {
			return &parseErr{msg: "guard token-file needs PATH"}
		}
		return safeTokenFile(pos[0])
	case "plaintext":
		if private == "" {
			return &parseErr{msg: "guard plaintext needs --private DIR"}
		}
		plat, err := loadProject(e)
		if err != nil {
			return err
		}
		covered, _, _ := plat.TreeFiles(privateRels(private), nil)
		names := make([]string, 0, len(covered))
		for r := range covered {
			names = append(names, r)
		}
		sort.Strings(names)
		return printJSON(e.Out, map[string]any{"private": private, keyFiles: names})
	}
	d, derr := e.description()
	if derr != nil {
		return fail("cannot check the guard %s, so this run is refused: %v", sub, derr)
	}
	k := d.Guarded(sub)
	if k == nil {
		return &parseErr{msg: "guard: unknown " + sub}
	}
	if dir == "" {
		return &parseErr{msg: "guard " + sub + " needs --dir DIR"}
	}
	if e.Getenv(noVaultVar) != "" || e.Getenv(sessionVars(e).Marker) != "" {
		return nil
	}
	re := guardDirRE(k)
	if re == nil {
		return fail("the pattern of %s (%s) does not name a folder, so the guard %s cannot check %s", k.Name, k.Pattern, sub, dir)
	}
	m := re.FindStringSubmatch(filepath.ToSlash(realPath(dir)))
	if m == nil {
		return fail("%s is not a folder of %s (%s below a plaintext tree): the guard %s refuses what it cannot check", dir, k.Name, k.Pattern, sub)
	}
	v, en, state, err := vaultMayHold(e, m[1], sub)
	if err != nil {
		return fail("cannot tell whether the vault holds %s, so this run is refused: %v", k.Name, err)
	}
	if state != "no" {
		return refusal(v, en, state, dir, "make "+k.Name)
	}
	return nil
}

// ---------------------------------------------------------------- settings

// cmdSettings: settings --out FILE|- (--all | --env E [--site S]). The settings of environments (the keys of the general file) are not secrets, but they are
// written to the file the caller names; "-" is the explicit way to stdout.
func cmdSettings(args []string, e *Env) error {
	var all bool
	var out string
	env, site, err := envFlags("settings", args, e, func(fs *flag.FlagSet) {
		fs.BoolVar(&all, "all", false, "every environment")
		fs.StringVar(&out, "out", "", "the file to write; - is stdout")
	})
	if err != nil {
		return err
	}
	if out == "" || (!all && env == "") {
		return &parseErr{msg: "settings needs --out FILE (or -) and --all or --env E"}
	}
	o, err := openModel(e, true)
	if err != nil {
		return err
	}
	defer o.close()
	var payload any
	if all {
		m, err := o.plat.AllSettings(o.snap)
		if err != nil {
			return fail("%v", err)
		}
		payload = m
	} else {
		ec, err := envContext(e, env)
		if err != nil {
			return err
		}
		s, err := render.PickSite(o.snap, ec.name, site)
		if err != nil {
			return fail("%v", err)
		}
		m, err := o.plat.Settings(o.snap, ec.name, s)
		if err != nil {
			return fail("%v", err)
		}
		payload = m
	}
	if out == "-" {
		return printJSON(e.Out, payload)
	}
	var buf bytes.Buffer
	if err := printJSON(&buf, payload); err != nil {
		return err
	}
	return writeInto(out, 0o600, buf.Bytes())
}

// ---------------------------------------------------------------- the run-time session

func sessionDir(e *Env, base, env, site string) string {
	if base == "" {
		base = os.TempDir()
	}
	prefix := "icevault"
	if d, err := e.description(); err == nil {
		prefix = d.SessionPrefix()
	}
	name := fmt.Sprintf("%s-%d-%s", prefix, os.Getuid(), env)
	if site != "" {
		name += "-" + site
	}
	return filepath.Join(base, name)
}

// session is one open run-time tree of a pair (environment, site).
type session struct {
	Path     string            `json:"path"`
	Env      string            `json:"env"`
	Site     string            `json:"site"`
	Real     string            `json:"real_private"`
	TFDir    string            `json:"tf_dir"`
	TFConfig string            `json:"tf_config"`
	Manifest map[string]string `json:"manifest"`
	ExtraEnv map[string]string `json:"vars"`
	base     string
	readOnly bool // a read-only session: its own directory, never written back
}

func (s *session) siteArg() string {
	if s.Site != "" {
		return " --site " + s.Site
	}
	return ""
}

func sha256Hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func cleanStaleTF(e *Env, base string) {
	if base == "" {
		base = os.TempDir()
	}
	prefix := fmt.Sprintf("%s%d-", tfDirPrefix(e), os.Getuid())
	ents, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, en := range ents {
		if !strings.HasPrefix(en.Name(), prefix) {
			continue
		}
		p := filepath.Join(base, en.Name())
		if st, err := os.Lstat(p); err == nil && st.IsDir() && ownedByMe(st) {
			_ = os.RemoveAll(p)
		}
	}
}

func baseOrTemp(base string) string {
	if base == "" {
		return os.TempDir()
	}
	return base
}

// writeCredentials writes credentials.tfrc.json (made with O_EXCL, mode 0600, only the credentials block for app.terraform.io) into dir.
func writeCredentials(dir, token string) (string, error) {
	path := filepath.Join(dir, "credentials.tfrc.json")
	body, _ := json.Marshal(map[string]any{"credentials": map[string]any{"app.terraform.io": map[string]any{"token": token}}})
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		_ = f.Chmod(0o600)
		_, err = f.Write(body)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	wipe(body)
	if err != nil {
		return "", err
	}
	return path, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// openSession starts a session on an unlocked vault.
func openSession(e *Env, o *opened, env, site, base string) (*session, error) {
	s := &session{Env: env, Site: site, Path: sessionDir(e, base, env, site), Manifest: map[string]string{}, ExtraEnv: map[string]string{}, base: base}
	ec, err := envContext(e, env)
	if err != nil {
		return nil, err
	}
	s.Real = ec.private
	if err := os.Mkdir(s.Path, 0o700); err != nil { // atomic: of two runs only one makes the directory
		if errors.Is(err, fs.ErrExist) {
			return nil, s.existsError()
		}
		return nil, err
	}
	_ = os.Chmod(s.Path, 0o700)
	if err := writeOwner(s.Path); err != nil {
		_ = os.RemoveAll(s.Path)
		return nil, err
	}
	return s.fill(e, o)
}

// openReadOnlySession renders the files of an environment into a directory of its own (unique name, mode 0700), so it never meets a running session or
// another read-only one. It is never written back.
func openReadOnlySession(e *Env, o *opened, env, site, base string) (*session, error) {
	s := &session{Env: env, Site: site, Manifest: map[string]string{}, ExtraEnv: map[string]string{}, base: base, readOnly: true}
	ec, err := envContext(e, env)
	if err != nil {
		return nil, err
	}
	s.Real = ec.private
	prefix := "icevault"
	if d, err := e.description(); err == nil {
		prefix = d.SessionPrefix()
	}
	name := fmt.Sprintf("%s-ro-%d-%s-", prefix, os.Getuid(), env)
	if site != "" {
		name += site + "-"
	}
	dir, err := os.MkdirTemp(baseOrTemp(base), name)
	if err != nil {
		return nil, err
	}
	s.Path = dir
	_ = os.Chmod(s.Path, 0o700)
	return s.fill(e, o)
}

// fill renders the session's files into its directory and prepares the variables. On a failure it removes everything it made.
func (s *session) fill(e *Env, o *opened) (*session, error) {
	env, site, base := s.Env, s.Site, s.base
	fail1 := func(err error) (*session, error) {
		_ = os.RemoveAll(s.Path)
		removeOwner(s.Path)
		s.dropTF()
		return nil, err
	}
	if err := render.CheckLinks(o.snap, env); err != nil {
		return fail1(fail("%v", err))
	}
	files, err := o.plat.Render(o.snap, env, site, false)
	if err != nil {
		return fail1(fail("%v", err))
	}
	for _, f := range files {
		if err := writeInto(filepath.Join(s.Path, filepath.FromSlash(f.Rel)), os.FileMode(f.Mode), f.Data); err != nil {
			return fail1(err)
		}
		s.Manifest[f.Rel] = sha256Hex(f.Data)
	}
	// a directory of its own outside the tree (mode 0700, an unpredictable name, removed with the session) holds the token file for terraform and the
	// settings of the environments, so the program that runs under the session needs no second unlock to read them
	cleanStaleTF(e, base)
	dir, err := os.MkdirTemp(baseOrTemp(base), fmt.Sprintf("%s%d-", tfDirPrefix(e), os.Getuid()))
	if err != nil {
		return fail1(err)
	}
	s.TFDir = dir
	all, err := o.plat.AllSettings(o.snap)
	if err != nil {
		return fail1(fail("%v", err))
	}
	pair := map[string]string{}
	if site != "" {
		if pair, err = o.plat.Settings(o.snap, env, site); err != nil {
			return fail1(fail("%v", err))
		}
	}
	siteType := ""
	if site != "" {
		siteType = o.siteKind(env)
	}
	doc, _ := json.Marshal(map[string]any{"all": all, "pair": pair, "site": site, "site_type": siteType})
	settingsFile := filepath.Join(dir, "settings.json")
	if err := writeInto(settingsFile, 0o600, doc); err != nil {
		return fail1(err)
	}
	if token := o.stateToken(env); token != "" {
		path, err := writeCredentials(dir, token)
		if err != nil {
			return fail1(err)
		}
		if err := safeTokenFile(path); err != nil {
			return fail1(err)
		}
		s.TFConfig = path
	}
	for _, rel := range o.plat.D.Session.Persist {
		real := filepath.Join(s.Real, filepath.FromSlash(rel))
		if err := os.MkdirAll(real, 0o700); err != nil {
			return fail1(err)
		}
		link := filepath.Join(s.Path, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
			return fail1(err)
		}
		if err := os.Symlink(real, link); err != nil {
			return fail1(err)
		}
	}
	sv := o.plat.D.SessionVars()
	s.ExtraEnv = map[string]string{sv.Marker: "1", sv.Environment: env, sv.Tree: s.Path, sv.SettingsFile: settingsFile}
	if s.readOnly {
		s.ExtraEnv[sv.ReadOnly] = "1"
	}
	if site != "" {
		s.ExtraEnv[sv.Site] = site
	}
	if s.TFConfig != "" {
		s.ExtraEnv["TF_CLI_CONFIG_FILE"] = s.TFConfig
		s.ExtraEnv[sv.TokenFile] = s.TFConfig
	}
	return s, nil
}

func (s *session) dropTF() {
	if s.TFDir != "" {
		_ = os.RemoveAll(s.TFDir)
	}
	s.TFDir, s.TFConfig = "", ""
}

// closeSession ends a session: drop the token file, write what the run made back into the vault, remove the tree. On a failed write-back
// the tree is kept: it may hold the only copy of what the run made.
func closeSession(e *Env, o *opened, s *session) error {
	if s.readOnly {
		return closeReadOnly(e, s)
	}
	s.dropTF()
	defer removeOwner(s.Path) // the run is over: the kept tree of a failed write-back is a leftover for recover
	cleanStaleTF(e, s.base)   // the open of another process left its token directory: only real directories of this user are removed
	unknown, err := syncBack(e, o, s)
	if err != nil {
		fmt.Fprintf(e.Err, "icevault: the run's files could NOT be written to the vault (%v); they are kept in %s; `icevault recover --env %s%s` repeats the write\n", err, s.Path, s.Env, s.siteArg())
		return errExit{"the session tree is kept: " + s.Path}
	}
	if len(unknown) > 0 {
		shown := unknown
		more := ""
		if len(shown) > 8 {
			shown, more = shown[:8], " ..."
		}
		fmt.Fprintf(e.Out, "vault: %d file(s) made in the session are not kept (no rule of the project description keeps them): %s%s\n", len(unknown), strings.Join(shown, ", "), more)
	}
	return os.RemoveAll(s.Path)
}

// closeReadOnly ends a read-only session: what the command changed in the tree is dropped with it (said once, as a count), the tree is removed.
func closeReadOnly(e *Env, s *session) error {
	s.dropTF()
	cleanStaleTF(e, s.base)
	changed := 0
	seen := map[string]bool{}
	_ = filepath.WalkDir(s.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == s.Path || !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(s.Path, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		seen[rel] = true
		if data, rerr := os.ReadFile(p); rerr != nil {
			changed++
		} else {
			if sum, ok := s.Manifest[rel]; !ok || sum != sha256Hex(data) {
				changed++
			}
			wipe(data)
		}
		return nil
	})
	for rel := range s.Manifest {
		if !seen[rel] {
			changed++
		}
	}
	if changed > 0 {
		fmt.Fprintf(e.Out, "vault: read-only session: %d file(s) changed in the session are not kept (a read-only session writes nothing back)\n", changed)
	}
	return os.RemoveAll(s.Path)
}

// cmdSession: run --env E [--site S] -- COMMAND ARGS...
func cmdSession(args []string, e *Env) error {
	if len(args) == 0 {
		return &parseErr{msg: "session needs run"}
	}
	sub, rest := args[0], args[1:]
	if sub != "run" {
		return &parseErr{msg: "session: unknown " + sub}
	}
	var child []string
	for i, a := range rest {
		if a == "--" {
			rest, child = rest[:i], rest[i+1:]
			break
		}
	}
	var base string
	var readOnly bool
	env, site, err := envFlags("session "+sub, rest, e, func(fs *flag.FlagSet) {
		fs.StringVar(&base, "base", "", "the folder of the session directory (default: the temp directory)")
		fs.BoolVar(&readOnly, "read-only", false, "a session of its own that is never written back (for commands that only look)")
	})
	if err != nil {
		return err
	}
	if sub == "run" && len(child) == 0 { // refused before the vault is asked for
		return &parseErr{msg: "session run needs -- COMMAND"}
	}
	ec, err := envContext(e, env)
	if err != nil {
		return err
	}
	o, err := openModel(e, false)
	if err != nil {
		return err
	}
	defer o.close()
	if !render.Holds(o.snap, ec.name) {
		return fail("the vault holds nothing for '%s'", ec.name)
	}
	warnExpiredVault(e, o.v, ec.name)
	s0, err := render.PickSite(o.snap, ec.name, site)
	if err != nil {
		return fail("%v", err)
	}
	switch sub {
	case "run":
		if len(child) == 0 {
			return &parseErr{msg: "session run needs -- COMMAND"}
		}
		open := openSession
		if readOnly {
			open = openReadOnlySession
		}
		s, err := open(e, o, ec.name, s0, base)
		if err != nil {
			return err
		}
		rc := runChild(e, s, child)
		cerr := closeSession(e, o, s)
		if rc != 0 {
			return exitCode(rc)
		}
		if cerr != nil {
			return cerr
		}
		return nil
	}
	return &parseErr{msg: "session: unknown " + sub}
}

// exitCode is the exit status of a child that ran under `session run`: returned as is, nothing printed.
type exitCode int

func (c exitCode) Error() string { return fmt.Sprintf("exit %d", int(c)) }

// runChild runs the command with the session's variables; SIGTERM and Ctrl+C go to the child, then the session is closed as usual.
func runChild(e *Env, s *session, argv []string) int {
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- the caller names the command
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, e.Out, e.Err
	env := os.Environ()
	for k, v := range s.ExtraEnv {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(e.Err, "icevault: %s cannot be started: %v\n", argv[0], err)
		return 127
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case sg := <-sig:
			_ = cmd.Process.Signal(sg)
		case err := <-done:
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			if err != nil {
				return 1
			}
			return 0
		}
	}
}
