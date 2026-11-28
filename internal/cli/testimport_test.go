package cli

import (
	"fmt"
	"os"

	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/pkg/vault"
)

// importEnv fills the vault of the harness with the plaintext tree of an environment of the example project. The command that did it (import) is gone from
// the command line; the tests still need a vault that holds the example's files, so they take the same path through the library: ImportTree on the
// writer of the vault model. The lines it prints are written to h.out.
func (h *harness) importEnv(env string) int {
	h.t.Helper()
	h.out.Reset()
	h.errb.Reset()
	e := h.newEnv()
	path, err := vaultPath(e)
	if err != nil {
		h.t.Fatal(err)
	}
	v, err := vault.Open(path, vault.Credentials{Password: []byte(pw), KeyFile: h.env["ICEVAULT_KEYFILE"]})
	if err != nil {
		h.t.Fatal(err)
	}
	defer v.Close()
	plat, err := loadProject(e)
	if err != nil {
		h.t.Fatal(err)
	}
	w, err := modelWriter(e, v, plat)
	if err != nil {
		h.t.Fatal(err)
	}
	snap, _ := w.Snapshot()
	refreshInfo(path, plat, snap)
	ec, err := envContext(e, env)
	if err != nil {
		fmt.Fprintln(&h.errb, err)
		return 1
	}
	opt := render.Options{Env: ec.name, Tree: render.FSSource{FS: os.DirFS(ec.private)}}
	if extra := confExtra(e, ec.name); extra != nil {
		conf := plat.Conf()
		data, err := os.ReadFile(extra[conf])
		if err != nil {
			h.t.Fatal(err)
		}
		opt.Extra = map[string][]byte{conf: data}
	}
	_, lines, err := plat.ImportTree(w, snap, opt, ec.private)
	if cerr := w.Commit(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		fmt.Fprintln(&h.errb, err)
		return 1
	}
	recordEnv(path, plat, snap, ec.name, privateRels(ec.private))
	for _, ln := range lines {
		fmt.Fprintln(&h.out, ln)
	}
	return 0
}
