package desktop

import (
	"context"
	"testing"

	"github.com/cybericebox/icevault/internal/update"
)

type fakeUpdater struct {
	st      update.Status
	err     error
	applied bool
	checks  int
	due     bool
}

func (f *fakeUpdater) Status() update.Status { return f.st }
func (f *fakeUpdater) Check(context.Context) update.Status {
	f.checks++
	return f.st
}
func (f *fakeUpdater) Fetch(context.Context) (update.Status, error) { return f.st, f.err }
func (f *fakeUpdater) Apply() error {
	if f.err != nil {
		return f.err
	}
	f.applied = true
	return nil
}
func (f *fakeUpdater) SetAuto(on bool) update.Status { f.st.Auto = on; return f.st }
func (f *fakeUpdater) Due() bool                     { return f.due }

func TestUpdateApplyLocksAndQuits(t *testing.T) {
	fu := &fakeUpdater{st: update.Status{State: update.Ready, Latest: "v0.4.0", URL: "https://github.com/cybericebox/icevault/releases/tag/v0.4.0"}}
	quit := false
	var opened string
	a := New(Options{Update: fu, Quit: func() { quit = true }, OpenURL: func(u string) { opened = u }})
	a.attach(failCore{})
	if r := a.UpdateRelease(); r.Status != 200 || opened != fu.st.URL {
		t.Fatalf("release page: %+v %q", r, opened)
	}
	if r := a.UpdateApply(); r.Status != 200 || !fu.applied || !quit {
		t.Fatalf("apply: %+v applied=%v quit=%v", r, fu.applied, quit)
	}
	if _, e := a.store(); e == nil {
		t.Fatal("the vault stays unlocked after the update")
	}
}

func TestUpdateApplyAsksTouchID(t *testing.T) {
	fu := &fakeUpdater{st: update.Status{State: update.Ready}}
	asked := ""
	a := New(Options{Update: fu, Confirm: func(reason string) bool { asked = reason; return false }, Quit: func() {}})
	if r := a.UpdateApply(); r.Status != 403 || fu.applied || asked != "update" {
		t.Fatalf("%+v applied=%v asked=%q", r, fu.applied, asked)
	}
}

func TestCheckForUpdateOnlyWhenDue(t *testing.T) {
	fu := &fakeUpdater{}
	a := New(Options{Update: fu})
	CheckForUpdate(a)
	fu.due = true
	CheckForUpdate(a)
	CheckForUpdate(New(Options{}))
	if fu.checks != 1 {
		t.Fatalf("checks: %d", fu.checks)
	}
}
