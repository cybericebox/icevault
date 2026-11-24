package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/vmodel"
)

func exportedText(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if data, rerr := os.ReadFile(p); rerr == nil {
				b.Write(data)
			}
		}
		return nil
	})
	return b.String()
}

// A value that refers to a variable of its own environment (${{ self.KEY }}) comes out resolved in the export; a reference that does not resolve
// stops the export and names the variable, and status lists it.
func TestExportResolvesSelfReferences(t *testing.T) {
	h := goldenHarness(t)
	var host string
	h.editModel(func(m *vmodel.Vault) {
		e := m.Env("prod")
		for _, x := range e.General {
			if x.Key == "PUBLIC_HOST" {
				host = x.Value
			}
		}
		setGeneral(e, "NOTES_LABEL", "${{ self.PUBLIC_HOST }}-notes")
	})
	to := filepath.Join(h.dir, "out-self")
	if rc := h.run("export", "--env", "prod", "--to", to); rc != 0 {
		t.Fatalf("export: rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	text := exportedText(t, to)
	if !strings.Contains(text, host+"-notes") || strings.Contains(text, "self.PUBLIC_HOST") {
		t.Fatalf("not resolved (host %q) len=%d files=%v", host, len(text), listFiles(to))
	}
	h.editModel(func(m *vmodel.Vault) {
		e := m.Env("prod")
		setGeneral(e, "NOTES_LABEL", "${{ self.NOT_THERE }}")
	})
	h.out.Reset()
	h.errb.Reset()
	to2 := filepath.Join(h.dir, "out-self-2")
	if rc := h.run("export", "--env", "prod", "--to", to2); rc == 0 || !strings.Contains(h.errb.String(), "NOTES_LABEL") || !strings.Contains(h.errb.String(), "self.NOT_THERE") {
		t.Fatalf("export with a broken reference: rc=%d %s", rc, h.errb.String())
	}
	if _, err := os.Stat(to2); err == nil {
		if ents, _ := os.ReadDir(to2); len(ents) > 0 {
			t.Fatal("something was written with a broken reference")
		}
	}
	h.out.Reset()
	h.errb.Reset()
	h.run("status", "--env", "prod")
	if all := h.out.String() + h.errb.String(); !strings.Contains(all, "NOTES_LABEL") {
		t.Fatalf("status does not list the broken reference:\n%s", all)
	}
}

func listFiles(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p[len(dir):])
		}
		return nil
	})
	return out
}

func setGeneral(e *vmodel.Environment, key, value string) {
	for _, x := range e.General {
		if x.Key == key {
			x.Value = value
			return
		}
	}
	e.General = append(e.General, &vmodel.Var{Key: key, Value: value, Vis: vmodel.VisPlain})
}

// The shared variables are a global item of the projection now: view, visibility and status of an environment read the same as without one.
func TestSharedItemDoesNotChangeTheCommands(t *testing.T) {
	h := goldenHarness(t)
	read := func() string {
		var all strings.Builder
		for _, args := range [][]string{{"view", "--env", "prod"}, {"visibility", "--env", "prod"}, {"status", "--env", "prod"}} {
			h.out.Reset()
			h.errb.Reset()
			h.run(args...)
			all.WriteString(stamps(h.out.String()) + h.errb.String())
		}
		return all.String()
	}
	before := read()
	h.editModel(func(m *vmodel.Vault) {
		m.Shared = append(m.Shared, &vmodel.Var{Key: "UNUSED_SHARED", Value: "x", Vis: vmodel.VisPlain})
	})
	if after := read(); after != before {
		t.Fatalf("a shared variable nobody imports changed the commands:\n--- before\n%s--- after\n%s", before, after)
	}
}
