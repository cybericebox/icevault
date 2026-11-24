package render

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/project"
)

func TestRequireTypedNamesTheVariableNeverTheValue(t *testing.T) {
	if RequireTyped(nil) != nil {
		t.Fatal("nothing wrong")
	}
	err := RequireTyped([]TypeProblem{{"apps/web.env", "API_REPLICAS", project.RuleInt}, {"base.env", "MODE", project.RuleEnum}})
	if err == nil || !strings.Contains(err.Error(), "apps/web.env/API_REPLICAS must be a whole number") || !strings.Contains(err.Error(), "base.env/MODE must be one of its choices") {
		t.Fatalf("%v", err)
	}
	if got := (TypeProblem{"f", "N", project.RulePattern}).Words(); got != "does not match its pattern" {
		t.Fatal(got)
	}
}

func typedProject(t *testing.T, fourth string) *Project {
	t.Helper()
	d, err := project.Parse([]byte(strings.Replace(testDescription, "{name: FOURTH}", fourth, 1)))
	if err != nil {
		t.Fatal(err)
	}
	return NewProject(d, testTemplates)
}

// export-app stops on a value that does not fit, as render does, and names the variable, never the value.
func TestAppFileStopsOnATypedValue(t *testing.T) {
	const bad = "four-secret-looking"
	snap := snapOf(t, row{"environments/e/web", "BASE_HOST", "example.org", own}, row{"environments/e/web", "FOURTH", bad, own})
	app := &project.App{Name: "jobs", From: webRel, All: true}
	p := typedProject(t, "{name: FOURTH, type: int}")
	_, _, err := p.AppFileText(snap, "e", app, "", "")
	if err == nil || !strings.Contains(err.Error(), "apps/web.env/FOURTH must be a whole number") || strings.Contains(err.Error(), bad) {
		t.Fatalf("%v", err)
	}
	if _, err := p.Render(snap, "e", "", true); err == nil || strings.Contains(err.Error(), bad) {
		t.Fatalf("render: %v", err)
	}
	// a variable whose when condition is false is not used: nothing is checked
	p = typedProject(t, "{name: FOURTH, type: int, when: 'WORKER=cluster'}")
	if _, _, err := p.AppFileText(snap, "e", app, "", ""); err != nil {
		t.Fatalf("inactive: %v", err)
	}
	if v, _ := p.View(snap, "e", ""); len(p.TypeProblems(v)) != 0 {
		t.Fatal("an inactive variable is reported")
	}
	// a range
	p = typedProject(t, "{name: FOURTH, type: int, min: 1, max: 3}")
	snap = snapOf(t, row{"environments/e/web", "BASE_HOST", "example.org", own}, row{"environments/e/web", "FOURTH", "4", own})
	if v, _ := p.View(snap, "e", ""); len(p.TypeProblems(v)) != 1 || p.TypeProblems(v)[0].Rule != project.RuleRange {
		t.Fatal("range")
	}
}
