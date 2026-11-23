package cli

import (
	"fmt"
	"io"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/render"
)

// printView prints a table of names only, never a value: file, variable, source, managed-by, set or empty, last change; then what is missing.
// The rows come from the settings model (render.ViewRows); this is only the layout.
func printView(out io.Writer, title string, rows []render.ViewRow) {
	empty := 0
	fw, nw := 4, 8
	for _, r := range rows {
		if r.State == "empty" {
			empty++
		}
		fw, nw = max(fw, len(r.File)), max(nw, len(r.Name))
	}
	fmt.Fprintf(out, "%s: %d variable(s), %d empty\n", title, len(rows), empty)
	fmt.Fprintf(out, "  %-*s  %-*s  %-22s  %-7s  %-5s  CHANGED\n", fw, "FILE", nw, "VARIABLE", "SOURCE", "MANAGED", "STATE")
	for _, r := range rows {
		fmt.Fprintf(out, "  %-*s  %-*s  %-22s  %-7s  %-5s  %s\n", fw, r.File, nw, r.Name, r.Source, r.Managed, r.State, r.Changed)
	}
	var miss []render.ViewRow
	for _, r := range rows {
		if r.Missing() {
			miss = append(miss, r)
		}
	}
	if len(miss) == 0 {
		fmt.Fprintln(out, "\nmissing: nothing")
		return
	}
	fmt.Fprintf(out, "\nmissing: %d entry(ies) the environment needs and that are empty (fill them in the KeePassXC app):\n", len(miss))
	for _, r := range miss {
		fmt.Fprintf(out, "  %s/%s  [%s]\n", render.StemOf(r.File), r.Name, r.Managed)
		for _, ln := range splitLines(model.HintOf(r.Notes)) {
			fmt.Fprintf(out, "      %s\n", ln)
		}
	}
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
