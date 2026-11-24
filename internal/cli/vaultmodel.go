package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cybericebox/icevault/internal/bridge"
	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// The commands on a vault of the vault model (internal/vmodel). The read commands (export, export-app, view, status, purge-plaintext,
// settings) read the projection of the model (vmodel.CompatWith), which lays the project's files out; the commands that write (import,
// recover, import-hcp, visibility --apply, the session, external serve) write through bridge.Writer, which puts each write into the model and
// saves it with vmodel.Sync; export --batches writes the batches of a run.

// descriptionOf is the project description of this process.
func descriptionOf(e *Env) (*project.Description, error) { return e.description() }

// manifestOrder ranks a key by its first place in the files of the manifest.
func manifestOrder(plat *render.Project) vmodel.Order {
	rank := map[string]int{}
	n := 0
	for _, rel := range plat.ManifestFiles() {
		for _, r := range plat.Manifest(rel) {
			if _, ok := rank[r.Key]; !ok {
				rank[r.Key] = n
			}
			n++
		}
	}
	return func(key string) (int, bool) { r, ok := rank[key]; return r, ok }
}

// vaultStore is what the commands write through (bridge.Writer).
type vaultStore interface {
	model.Writer
	Commit() error
}

// modelWriter is the writer of the commands on the vault model.
func modelWriter(e *Env, v *vault.Vault, plat *render.Project) (*bridge.Writer, error) {
	d, err := descriptionOf(e)
	if err != nil {
		return nil, err
	}
	w, err := bridge.NewWriter(v, d, plat)
	if err != nil {
		return nil, fail("%v", err)
	}
	return w, nil
}

// modelView is a vault of the vault model as the read commands see it.
type modelView struct {
	m      *vmodel.Vault
	d      *project.Description
	compat *vmodel.CompatSnapshot
}

func openModelView(e *Env, v *vault.Vault, plat *render.Project) (*modelView, error) {
	d, err := descriptionOf(e)
	if err != nil {
		return nil, err
	}
	m, err := vmodel.Load(v)
	if err != nil {
		return nil, fail("%v", err)
	}
	if len(m.Problems) > 0 {
		fmt.Fprintf(e.Err, "vault: %d problem(s) in the model: %s\n", len(m.Problems), strings.Join(m.Problems, "; "))
	}
	return &modelView{m: m, d: d, compat: vmodel.CompatWith(m, d, vmodel.CompatOptions{Order: manifestOrder(plat)})}, nil
}

// skipped refuses an environment the projection could not lay out.
func (mv *modelView) skipped(env string) error {
	if why := mv.compat.Skipped[env]; why != "" {
		return fail("%s", why)
	}
	return nil
}

// runOnModel runs a command of the settings model on a vault of the vault model.
func runOnModel(e *Env, cmd string, args []string, v *vault.Vault, out io.Writer, plat *render.Project) (int, error) {
	if f := vmodel.FormatOf(v); f != vmodel.Format && writesVault(cmd, args) {
		return 1, fail("%v", vmodel.ErrNewerFormat)
	}
	switch cmd {
	case cmdEnv:
		return runEnv(e, args, out, v, plat)
	case cmdImport, cmdRecover, cmdImportHCP:
		w, err := modelWriter(e, v, plat)
		if err != nil {
			return 1, err
		}
		snap, _ := w.Snapshot()
		if path, perr := vaultPath(e); perr == nil {
			refreshInfo(path, plat, snap)
		}
		op := &opened{path: vaultPathOr(e), v: v, k: w, snap: snap, plat: plat}
		switch cmd {
		case cmdImport:
			return runImportReal(e, args, out, op)
		case cmdRecover:
			return runRecover(e, args, out, op)
		}
		return runImportHCP(e, args, out, op)
	}
	if cmd == cmdVisibility && hasFlag(args, "apply") {
		w, err := modelWriter(e, v, plat)
		if err != nil {
			return 1, err
		}
		snap, _ := w.Snapshot()
		return 0, runVisibility(e, args, out, plat, snap, w)
	}
	if cmd == cmdExpiring {
		return 0, runExpiring(e, args, out, v)
	}
	mv, err := openModelView(e, v, plat)
	if err != nil {
		return 1, err
	}
	snap := mv.compat.Snap
	if path, perr := vaultPath(e); perr == nil {
		refreshInfo(path, plat, snap)
	}
	if env := flagVals(cmd, args)["env"]; env != "" {
		if err := mv.skipped(env); err != nil && (cmd != cmdExport || !hasFlag(args, "batches")) {
			return 1, err
		}
	}
	if env := flagVals(cmd, args)["env"]; env != "" && (cmd == cmdExport || cmd == cmdExportApp) {
		warnExpired(e, mv.m, env)
	}
	switch cmd {
	case cmdView:
		return 0, runView(e, args, out, plat, snap)
	case cmdExport:
		if hasFlag(args, "batches") {
			return 0, runBatches(e, args, out, mv)
		}
		return 0, runExport(e, args, out, plat, snap)
	case cmdExportApp:
		return 0, runExportApp(e, args, out, plat, snap)
	case cmdStatus:
		if err := runStatus(e, args, out, plat, snap); err != nil {
			return 0, err
		}
		if env := flagVals(cmd, args)["env"]; env != "" {
			if x := mv.m.Env(env); x != nil {
				printExpiring(out, mv.m.ExpiringIn(x, e.Now(), vmodel.SoonDays), "  ")
			}
		}
		return 0, nil
	case cmdVisibility:
		return 0, runVisibility(e, args, out, plat, snap, nil)
	case cmdPurge:
		return 0, runPurge(e, args, out, plat, snap)
	}
	return notPortedCmd(e, cmd, "the vault model")
}

// batchSelection reads the selection of export --batches.
func batchSelection(v map[string]string) (vmodel.Selection, error) {
	sel := vmodel.Selection{Site: v["site"], Product: v["product"], All: v["all"] == flagOn}
	n := 0
	for _, x := range []bool{sel.Site != "", sel.Product != "", sel.All} {
		if x {
			n++
		}
	}
	if n != 1 {
		return sel, &parseErr{msg: "export --batches names one of --site S, --product P, --all"}
	}
	return sel, nil
}

// runBatches writes the batches of a run: DIR/<batch>.env (mode 0600, the quoting of the settings files) and DIR/batches.json (no value).
func runBatches(e *Env, args []string, out io.Writer, mv *modelView) error {
	vals := flagVals(cmdExport, args)
	sel, err := batchSelection(vals)
	if err != nil {
		return err
	}
	to := vals["to"]
	ec, err := envContext(e, vals["env"])
	if err != nil {
		return err
	}
	if ents, err := os.ReadDir(to); err == nil && len(ents) > 0 {
		return fail("%s is not empty", to)
	}
	bs, err := vmodel.Batches(mv.m, mv.d, ec.name, sel)
	if err != nil {
		return fail("%v", err)
	}
	var misfits []string
	for _, b := range bs {
		for _, x := range b.Vars {
			if rule := mv.d.ValueProblem(x.Key, x.Value); rule != "" {
				misfits = append(misfits, render.TypeProblem{File: b.Name, Name: x.Key, Rule: rule}.String())
			}
		}
	}
	if len(misfits) > 0 {
		return fail("a value does not fit its type, nothing is written: %s", strings.Join(misfits, "; "))
	}
	if err := os.MkdirAll(to, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(to, 0o700)
	type index struct {
		Format      int               `json:"format"`
		Environment string            `json:"environment"`
		Batches     []*vmodel.Batch   `json:"batches"`
		Files       map[string]string `json:"files"`
	}
	idx := index{Format: vmodel.Format, Environment: ec.name, Batches: bs, Files: map[string]string{}}
	for _, b := range bs {
		var sb strings.Builder
		for _, x := range b.Vars {
			sb.WriteString(x.Key + "=" + render.QuoteEnv(x.Value) + "\n")
		}
		name := b.Name + ".env"
		if err := writeInto(filepath.Join(to, name), 0o600, []byte(sb.String())); err != nil {
			return err
		}
		idx.Files[b.Name] = name
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	if err := writeInto(filepath.Join(to, "batches.json"), 0o600, append(data, '\n')); err != nil {
		return err
	}
	fmt.Fprintf(out, "WARNING: %s now holds %d batch file(s) in PLAINTEXT (batches.json names them). Delete it when you are done (rm -rf %s).\n", to, len(bs), to)
	return nil
}

// checkBatches refuses a wrong export --batches before the password.
func checkBatches(e *Env, v map[string]string) (int, bool, error) {
	if v["batches"] != flagOn {
		if v["product"] != "" || v["all"] == flagOn {
			return 2, true, &parseErr{msg: "--product and --all name batches: add --batches"}
		}
		return 0, false, nil
	}
	if v["file"] != "" {
		return 2, true, &parseErr{msg: "--file is a file of the export of the project's files, not of --batches"}
	}
	if _, err := batchSelection(v); err != nil {
		return 2, true, err
	}
	if _, err := envContext(e, v["env"]); err != nil {
		return 1, true, err
	}
	if ents, err := os.ReadDir(v["to"]); err == nil && len(ents) > 0 {
		return 1, true, fail("%s is not empty", v["to"])
	}
	return 0, false, nil
}
