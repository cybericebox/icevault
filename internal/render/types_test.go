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
