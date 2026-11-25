//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/vmodel"
)

const sentinel = "SENTINEL-never-printed-9" // the value of the other and shared secrets, which no type checks

func day(offset int) string { return time.Now().UTC().AddDate(0, 0, offset).Format(vmodel.DayFormat) }

// expiryHarness has a variable of prod that expired yesterday, one that expires in 3 days, a shared one that expired a week ago and an other secret
// that expires in a year; every value is the sentinel.
func expiryHarness(t *testing.T) (*harness, string, string) {
	h := goldenHarness(t)
	var gone, soon string
	h.editModel(func(m *vmodel.Vault) {
		prod := m.Env("prod")
		gone, soon = prod.General[0].Key, prod.General[1].Key
		prod.General[0].Expires, prod.General[1].Expires = day(-1), day(3)
		m.Other = append(m.Other, &vmodel.Other{Title: "later", Value: sentinel, Expires: day(365)})
		m.Shared = append(m.Shared, &vmodel.Var{Key: "OLD_SHARED", Value: sentinel, Vis: vmodel.VisSecret, Expires: day(-7)})
	})
	return h, gone, soon
}

func TestExpiringListsNamesAndDatesNeverValues(t *testing.T) {
	h, gone, soon := expiryHarness(t)
	if rc := h.run("expiring"); rc != 0 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	out := h.out.String()
	for _, want := range []string{"EXPIRED " + day(-7) + "  shared: OLD_SHARED", "EXPIRED " + day(-1) + "  environment prod: " + gone, "expires " + day(3) + "  environment prod: " + soon} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "later") || strings.Contains(out, sentinel) {
		t.Fatalf("a year ahead is not listed, and no value is printed:\n%s", out)
	}
	if rc := h.run("expiring", "--days", "400"); rc != 0 || !strings.Contains(h.out.String(), "other: later") {
		t.Fatalf("--days 400: %s", h.out.String())
	}
	if rc := h.run("expiring", "--days", "x"); rc != 2 {
		t.Fatalf("a bad --days: rc=%d", rc)
	}
}

func TestStatusExportAndSessionWarnAboutExpiredOnes(t *testing.T) {
	h, gone, soon := expiryHarness(t)
	if rc := h.run("status", "--env", "prod"); rc != 0 {
		t.Fatalf("status: %s", h.errb.String())
	}
	if out := h.out.String(); !strings.Contains(out, "EXPIRED "+day(-1)+"  environment prod: "+gone) || !strings.Contains(out, soon) || strings.Contains(out, sentinel) {
		t.Fatalf("status:\n%s", out)
	}
	to := filepath.Join(h.dir, "out")
	if rc := h.run("export", "--env", "prod", "--to", to); rc != 0 {
		t.Fatalf("export is not blocked by an expired value: rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
	if e := h.errb.String(); !strings.Contains(e, "WARNING: environment prod: "+gone+" has expired ("+day(-1)+")") || strings.Contains(e, soon) || strings.Contains(e, sentinel) {
		t.Fatalf("export stderr:\n%s", e)
	}
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	if rc := h.run("session", "run", "--env", "prod", "--base", base, "--", "true"); rc != 0 {
		t.Fatalf("session: %s", h.errb.String())
	}
	if e := h.errb.String(); !strings.Contains(e, gone+" has expired") || strings.Contains(e, sentinel) {
		t.Fatalf("session stderr:\n%s", e)
	}
}
