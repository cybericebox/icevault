package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// env adopt-connections: values an environment holds as its own that the project description now takes from a connection move into the
// connection (vmodel.AdoptConnections). Names only are printed, never a value; --dry-run changes nothing.
func runAdopt(e *Env, a envArgs, out io.Writer, v *vault.Vault, plat *render.Project, m *vmodel.Vault) (int, error) {
	if m.ReadOnly {
		return 1, fail("the vault is of a newer format than this tool writes")
	}
	before, _ := sha256File(v.Path())
	plan, err := vmodel.AdoptConnections(m, plat.D, a.env)
	if err != nil {
		return 1, fail("%v", err)
	}
	moved := 0
	for _, x := range plan {
		moved += x.Count()
		made := " (" + map[string]string{"new": "new connection", "product": "the product's connection", "environment": "a connection this environment uses", "named": "the connection the description names"}[x.Chosen] + ")"
		if x.Count() > 0 {
			fmt.Fprintf(out, "  %s: %s -> connection %s [%s]%s\n", x.Product, strings.Join(x.Variables, ", "), x.Connection, x.Kind, made)
		}
		if len(x.Differing) > 0 {
			fmt.Fprintf(out, "  %s: kept as they are, held in several places with different values: %s\n", x.Product, strings.Join(x.Differing, ", "))
		}
		if rest := without(without(x.Conflicts, x.Sealed), x.Differing); len(rest) > 0 {
			fmt.Fprintf(out, "  %s: kept as they are, the connection %s holds another value: %s\n", x.Product, x.Connection, strings.Join(rest, ", "))
		}
		if len(x.Sealed) > 0 {
			fmt.Fprintf(out, "  %s: kept as they are, sealed (a sealed value never moves): %s\n", x.Product, strings.Join(x.Sealed, ", "))
		}
	}
	if moved == 0 {
		fmt.Fprintf(out, "env adopt-connections: %s holds no value that a connection of the project description takes over\n", a.env)
		return 0, nil
	}
	if a.dryRun {
		fmt.Fprintf(out, "env adopt-connections: %d value(s) of %s would move (dry run: nothing changed)\n", moved, a.env)
		return 0, nil
	}
	if errs := m.Check(); len(errs) > 0 {
		return 1, fail("the model would not be valid: %s", strings.Join(errs, "; "))
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
	fmt.Fprintf(out, "env adopt-connections: %d value(s) of %s moved into connections; no value was printed\n", moved, a.env)
	afterChange(v.Path(), before, out)
	return 0, nil
}

// without lists the names of a that are not in b.
func without(a, b []string) []string {
	var out []string
	for _, x := range a {
		keep := true
		for _, y := range b {
			keep = keep && x != y
		}
		if keep {
			out = append(out, x)
		}
	}
	return out
}
