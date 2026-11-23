package desktop

import (
	"errors"
	"testing"

	"github.com/cybericebox/icevault/internal/cliinstall"
)

type fakeCLI struct {
	st       cliinstall.Status
	err      error
	installs []bool
}

func (f *fakeCLI) Status() cliinstall.Status { return f.st }
func (f *fakeCLI) Install(replace bool) (cliinstall.Status, error) {
	f.installs = append(f.installs, replace)
	if f.err != nil {
		return cliinstall.Status{}, f.err
	}
	f.st = cliinstall.Status{State: cliinstall.Installed, Dir: "/d", Link: "/d/icevault"}
	return f.st, nil
}

func unlockedWith(t *testing.T, cli CLIInstaller, confirm func(string) bool) *App {
	t.Helper()
	a := New(Options{Unlocker: &MemoryUnlocker{Password: "pw"}, CLI: cli, Confirm: confirm})
	if r := a.Unlock("password", "pw"); r.Status != 200 {
		t.Fatal(r)
	}
	return a
}

func TestCLIStatusAndInstall(t *testing.T) {
	f := &fakeCLI{st: cliinstall.Status{State: cliinstall.NotInstalled, Dir: "/d"}}
	a := unlockedWith(t, f, nil)
	if r := a.CLIStatus(); r.Status != 200 || r.Data.(cliinstall.Status).State != cliinstall.NotInstalled {
		t.Fatalf("status: %+v", r)
	}
	r := a.CLIInstall(false)
	if r.Status != 200 || r.Data.(cliinstall.Status).State != cliinstall.Installed || len(f.installs) != 1 || f.installs[0] {
		t.Fatalf("install: %+v %v", r, f.installs)
	}
}

func TestCLIInstallNeedsAnUnlockedWindowAndTheExtraCheck(t *testing.T) {
	f := &fakeCLI{}
	locked := New(Options{CLI: f})
	if r := locked.CLIInstall(false); r.Status != 423 || len(f.installs) != 0 {
		t.Fatalf("locked: %+v", r)
	}
	var reasons []string
	a := unlockedWith(t, f, func(reason string) bool { reasons = append(reasons, reason); return false })
	r := a.CLIInstall(true)
	if r.Status != 403 || len(f.installs) != 0 || len(reasons) != 1 || reasons[0] != "cli" {
		t.Fatalf("refused check: %+v %v %v", r, reasons, f.installs)
	}
	assertCoded(t, "refused", r)
}

func TestCLIInstallRefusalsKeepTheirCodeAndParameters(t *testing.T) {
	f := &fakeCLI{err: &cliinstall.Error{Code: "cli_elsewhere", Params: map[string]any{"link": "/d/icevault", "target": "/dev/icevault"}}}
	a := unlockedWith(t, f, nil)
	r := a.CLIInstall(false)
	data := r.Data.(map[string]any)
	params, _ := data["params"].(map[string]any)
	if r.Status != 409 || data["code"] != "cli_elsewhere" || params["target"] != "/dev/icevault" {
		t.Fatalf("%+v", r)
	}
	// a replace request is passed on, and a plain error is only "internal"
	f.err = errors.New(leak)
	f.installs = nil
	r = a.CLIInstall(true)
	assertCoded(t, "plain error", r)
	if len(f.installs) != 1 || !f.installs[0] {
		t.Fatalf("the replace flag was lost: %v", f.installs)
	}
}

func TestCLIStatusWithoutAnInstaller(t *testing.T) {
	a := New(Options{})
	r := a.CLIStatus()
	if st := r.Data.(cliinstall.Status); st.State != cliinstall.Unavailable || st.Code != "cli_unavailable" {
		t.Fatalf("%+v", r)
	}
}
