package render

import (
	"fmt"
	"strings"

	"github.com/cybericebox/icevault/internal/model"
)

// ljust pads s with spaces to n characters (Python str.ljust).
func ljust(s string, n int) string {
	if k := len([]rune(s)); k < n {
		return s + strings.Repeat(" ", n-k)
	}
	return s
}

// AuditVisibility is `icevault visibility`: the lines of the table (key,
// current, proposed, verdict; never a value) for every owner variable the rule
// would treat differently; with apply it moves the "change" ones (never unseals,
// never touches a choice of the owner) through w. Returns the lines and how many
// were changed.
func (p *Project) AuditVisibility(w model.Writer, snap *model.Snapshot, env string, apply bool) ([]string, int, error) {
	rows, err := p.VisibilityRows(snap, env)
	if err != nil {
		return nil, 0, err
	}
	if len(rows) == 0 {
		return []string{"every owner variable already has the visibility the rule gives it"}, 0, nil
	}
	width := 0
	for _, r := range rows {
		if n := len([]rune(r.Item + "/" + r.Group + "/" + r.Key)); n > width {
			width = n
		}
	}
	lines := []string{ljust("variable", width) + "  current  proposed  verdict"}
	done, todo := 0, 0
	for _, r := range rows {
		shown := r.Verdict
		if r.Verdict == "change" {
			todo++
			if apply {
				e := r.Entry
				if err := func() error {
					nts, err := model.EntryNotesSet(model.ManagedOwner, r.Proposed, e.Labels, e.Description, "", e.ManagedSet)
					if err != nil {
						return err
					}
					return w.SetNotes(e.Path, nts)
				}(); err != nil {
					return lines, done, err
				}
				e.Vis, e.VisBy = r.Proposed, ""
				shown = "changed"
				done++
			}
		}
		lines = append(lines, ljust(r.Item+"/"+r.Group+"/"+r.Key, width)+"  "+ljust(r.Current, 7)+"  "+ljust(r.Proposed, 8)+"  "+shown)
	}
	if apply {
		lines = append(lines, fmt.Sprintf("%d changed, %d left as they are", done, len(rows)-done))
	} else {
		lines = append(lines, fmt.Sprintf("%d can be changed with --apply; %d stay as they are (chosen by the owner, sealed, or changed by hand)", todo, len(rows)-todo))
	}
	return lines, done, nil
}

// ViewText is `icevault view`: a table of names only, never a value (file,
// variable, source, managed-by, set or empty, last change), then what is
// missing with its hint. item non-nil: the table of one item.
func ViewText(env string, item *model.ItemKey, site string, rows []ViewRow) []string {
	title := ""
	if item != nil {
		title = "item " + item.String()
	} else {
		title = "environment '" + env + "'"
		if site != "" {
			title += " on site '" + site + "'"
		}
		title += " (linked items included)"
	}
	empty := 0
	fw, nw := 4, 8
	for _, r := range rows {
		if r.State == "empty" {
			empty++
		}
		if n := len([]rune(r.File)); n > fw {
			fw = n
		}
		if n := len([]rune(r.Name)); n > nw {
			nw = n
		}
	}
	lines := []string{fmt.Sprintf("%s: %d variable(s), %d empty", title, len(rows), empty),
		"  " + ljust("FILE", fw) + "  " + ljust("VARIABLE", nw) + "  " + ljust("SOURCE", 22) + "  " + ljust("MANAGED", 7) + "  " + ljust("STATE", 5) + "  CHANGED"}
	for _, r := range rows {
		lines = append(lines, "  "+ljust(r.File, fw)+"  "+ljust(r.Name, nw)+"  "+ljust(r.Source, 22)+"  "+ljust(r.Managed, 7)+"  "+ljust(r.State, 5)+"  "+r.Changed)
	}
	var miss []ViewRow
	for _, r := range rows {
		if r.Missing() {
			miss = append(miss, r)
		}
	}
	if len(miss) == 0 {
		return append(lines, "", "missing: nothing")
	}
	lines = append(lines, "", fmt.Sprintf("missing: %d entry(ies) the environment needs and that are empty (fill them in the KeePassXC app):", len(miss)))
	for _, r := range miss {
		lines = append(lines, "  "+StemOf(r.File)+"/"+r.Name+"  ["+r.Managed+"]")
		for _, ln := range strings.Split(model.HintOf(r.Notes), "\n") {
			if ln != "" {
				lines = append(lines, "      "+ln)
			}
		}
	}
	return lines
}

// StatusLines is the vault part of `status --env E` (names and counts only).
func StatusLines(st *Status, env string) []string {
	lines := []string{fmt.Sprintf("vault: environment %s: %d settings file(s) with %d variable(s), %d other file(s), %d retired",
		env, st.Settings, st.Variables, st.OtherFiles, st.Retired)}
	if len(st.Uses) > 0 {
		lines = append(lines, "  uses: "+strings.Join(st.Uses, ", "))
	}
	for _, b := range st.BrokenLinks {
		lines = append(lines, "  LINK PROBLEM: links "+b+", which does not exist")
	}
	for _, s := range st.Shadowed {
		lines = append(lines, "  shadowed: "+s)
	}
	for _, t := range st.TypeProblems {
		lines = append(lines, "  TYPE PROBLEM: "+t.String())
	}
	for _, f := range st.Files {
		l := fmt.Sprintf("  %s: %d variable(s)", f.Rel, f.Variables)
		if f.FromLinks > 0 {
			l += fmt.Sprintf(", %d from linked items", f.FromLinks)
		}
		if len(f.Empty) > 0 {
			l += fmt.Sprintf(", %d empty (%s)", len(f.Empty), strings.Join(f.Empty, ", "))
		}
		lines = append(lines, l)
		for _, v := range f.Vars {
			lines = append(lines, "      "+ljust(v.Name, 36)+" "+ljust(v.Source, 22)+" "+v.Managed)
		}
	}
	return lines
}
