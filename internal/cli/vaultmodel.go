package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/cybericebox/icevault/internal/bridge"
	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// The commands on a vault of the vault model (internal/vmodel). The read commands (export, view, status, purge-plaintext,
// settings) read the projection of the model (vmodel.CompatWith), which lays the project's files out; the commands that write (import,
// recover, import-hcp, visibility --apply, the session, external serve) write through bridge.Writer, which puts each write into the model and
// saves it with vmodel.Sync.

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
	case cmdSet:
		return runSet(e, args, out, v, plat)
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
		if err := mv.skipped(env); err != nil {
			return 1, err
		}
	}
	if env := flagVals(cmd, args)["env"]; env != "" && cmd == cmdExport {
		warnExpired(e, mv.m, env)
	}
	switch cmd {
	case cmdView:
		return 0, runView(e, args, out, plat, snap)
	case cmdExport:
		return 0, runExport(e, args, out, plat, snap)
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
