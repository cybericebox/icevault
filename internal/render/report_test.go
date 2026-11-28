package render

import (
	"regexp"
	"strings"
	"testing"
)

func TestViewTextListsNamesOnlyAndWhatIsMissingWithItsHint(t *testing.T) {
	notes := "managed-by=owner\nvisibility=plain\nlabels=file:apps/web.env\nNEEDED FOR: off-site backups. Get it: the storage provider, API tokens."
	snap := snapOf(t,
		row{"environments/staging/backup", "BACKUP_ACCESS_KEY", "", notes},
		row{"environments/staging/backup", "BACKUP_SECRET_KEY", "secret-key-value", "managed-by=owner\nvisibility=secret\nlabels=file:apps/web.env"}, // the feature is in use
		row{"environments/staging/web", "BASE_HOST", "example.org", "managed-by=owner\nvisibility=plain\nthe domain"},
		row{"environments/staging/web", "COOKIE_SECRET", "secret-jwt-value", "managed-by=system\nvisibility=plain"})
	rows, err := proj().ViewRows(snap, "staging", nil, "")
	eq(t, err, nil, "rows")
	text := strings.Join(ViewText("staging", nil, "", rows), "\n")
	if strings.Contains(text, "secret-jwt-value") || strings.Contains(text, "secret-key-value") || strings.Contains(text, "example.org") {
		t.Error("a value is shown")
	}
	for _, re := range []string{`apps/web\.env\s+BACKUP_ACCESS_KEY\s+environment\s+owner\s+empty`, `COOKIE_SECRET\s+environment\s+system\s+set`} {
		if !regexp.MustCompile(re).MatchString(text) {
			t.Errorf("no match for %s in:\n%s", re, text)
		}
	}
	contains2(t, text, "missing: 1 entry(ies)")
	contains2(t, text, "apps-web/BACKUP_ACCESS_KEY  [owner]")
	contains2(t, text, "Get it: the storage provider, API tokens.")
	if strings.Contains(text, "managed-by=") {
		t.Error("machine lines are not shown")
	}
	contains2(t, text, "environment 'staging' (linked items included): 4 variable(s), 1 empty")
	ok := snapOf(t, row{"environments/e/web", "BASE_HOST", "x", own})
	rows2, _ := proj().ViewRows(ok, "e", nil, "")
	contains2(t, strings.Join(ViewText("e", nil, "aws-main", rows2), "\n"), "environment 'e' on site 'aws-main' (linked items included)")
	contains2(t, strings.Join(ViewText("e", nil, "", rows2), "\n"), "missing: nothing")
}

func TestStatusLines(t *testing.T) {
	snap := snapOf(t,
		row{"environments/e", ".item", "", "uses=mine/a,mine/gone\nstate=active"},
		row{"environments/e/web", "BASE_HOST", "own", own}, row{"environments/e/web", "FOURTH", "", own},
		row{"mine/a", ".item", "", "state=active"}, row{"mine/a/web", "BASE_HOST", "other", own}, row{"mine/a/web", "API_NAME", "x", "managed-by=owner\nlabels=file:apps/web.env"})
	st, _ := proj().StatusOf(snap, "e", "")
	text := strings.Join(StatusLines(st, "e"), "\n")
	contains2(t, text, "vault: environment e: 1 settings file(s) with 3 variable(s), 0 other file(s), 0 retired")
	contains2(t, text, "  uses: mine/a")
	contains2(t, text, "LINK PROBLEM: links mine/gone, which does not exist")
	contains2(t, text, "shadowed: mine/a/web/BASE_HOST (the value of environments/e is used)")
	contains2(t, text, "apps/web.env: 3 variable(s), 1 from linked items, 1 empty")
	if !regexp.MustCompile(`API_NAME\s+mine/a\s+owner`).MatchString(text) {
		t.Error("the source of a linked variable is shown")
	}
}
