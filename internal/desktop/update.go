package desktop

import (
	"context"
	"errors"

	"github.com/cybericebox/icevault/internal/update"
)

// Updater is internal/update as the window needs it.
type Updater interface {
	Status() update.Status
	Check(ctx context.Context) update.Status
	Fetch(ctx context.Context) (update.Status, error)
	Apply() error
	SetAuto(on bool) update.Status
	Due() bool
}

// UpdateStatus is the state of the update of the application. It needs no unlock: it says nothing about the vault.
func (a *App) UpdateStatus() Response {
	if a.o.Update == nil {
		return ok(update.Status{State: update.Unavailable, Code: "update_no_bundle"})
	}
	return ok(a.o.Update.Status())
}

// UpdateCheck asks GitHub for the latest release now (the page's "Check now").
func (a *App) UpdateCheck() Response {
	if a.o.Update == nil {
		return fail(409, "update_no_bundle")
	}
	return ok(a.o.Update.Check(context.Background()))
}

// UpdateFetch downloads and checks the new copy in the background; the page asks UpdateStatus for the progress.
func (a *App) UpdateFetch() Response {
	if a.o.Update == nil {
		return fail(409, "update_no_bundle")
	}
	st, err := a.o.Update.Fetch(context.Background())
	if err != nil {
		return updateAnswer(err)
	}
	a.say("downloading the update " + st.Latest)
	return ok(st)
}

// UpdateApply puts the checked copy in place of this application, locks the vault and ends the program; the new copy starts when it has ended.
// Where Touch ID is on, it asks first: the program that will hold the vault changes.
func (a *App) UpdateApply() Response {
	if a.o.Update == nil {
		return fail(409, "update_no_bundle")
	}
	if okc, why := a.confirm("update"); !okc {
		return refused(why)
	}
	if err := a.o.Update.Apply(); err != nil {
		return updateAnswer(err)
	}
	a.say("the application was updated; starting the new copy")
	a.lock()
	a.quit()
	return ok(map[string]any{"ok": true})
}

// UpdateAuto turns the check at the start on or off.
func (a *App) UpdateAuto(on bool) Response {
	if a.o.Update == nil {
		return fail(409, "update_no_bundle")
	}
	return ok(a.o.Update.SetAuto(on))
}

// UpdateRelease opens the release page of the latest release in the browser (the only address this method opens).
func (a *App) UpdateRelease() Response {
	if a.o.Update == nil || a.o.OpenURL == nil {
		return fail(409, "update_no_bundle")
	}
	st := a.o.Update.Status()
	if st.URL == "" {
		return fail(409, "update_none")
	}
	a.o.OpenURL(st.URL)
	return ok(map[string]any{"ok": true})
}

// CheckForUpdate is the check at the start: once a day at most, when it is on; the page learns the answer from UpdateStatus.
func CheckForUpdate(a *App) {
	if a.o.Update != nil && a.o.Update.Due() {
		a.o.Update.Check(context.Background())
	}
}

func updateAnswer(err error) Response {
	var e *update.Error
	if errors.As(err, &e) {
		return fail(409, e.Code)
	}
	return fail(500, "update_failed")
}
