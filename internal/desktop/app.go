package desktop

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/cybericebox/icevault/internal/cliinstall"
)

// Limits and delays of the browser screen, kept as they are.
const (
	IdleDefault    = 10 * time.Minute // without the person doing anything: lock
	ExitDefault    = 30 * time.Minute // without the person doing anything: end the program
	MaxWrong       = 5                // wrong passwords in a row: the fifth ends the program
	WrongDelay     = 800 * time.Millisecond
	MaxPassword    = 1024
	MaxTouchFails  = 3 // failed, cancelled or timed-out Touch ID requests in one run; then only the password field
	ClipboardClear = 45 * time.Second
	SyncDefault    = 2 * time.Second // how often an unlocked window looks whether another writer changed the vault file
	maxFileBytes   = 20_000_000
)

// EventVaultChanged is the event the page gets when the vault was read again after another writer saved it; its data is {"rev": n}.
const EventVaultChanged = "vault-changed"

// EventVaultLocked is the event the page gets when the program locked the vault (idle time, a vault chosen from outside): the page shows the lock
// screen at once instead of at its next heartbeat, so nothing decrypted stays on the screen after the lock. Its data is {}.
const EventVaultLocked = "vault-locked"

// Response is what every bound method answers; the page adapter turns it into the {status, data} the page logic already knows.
type Response struct {
	Status int `json:"status"`
	Data   any `json:"data"`
}

// Options are the parts the App is built from. Zero values give the defaults of the browser screen.
type Options struct {
	Unlocker   Unlocker
	Focus      string                   // an environment to open first ("" for none)
	Binding    bool                     // a Touch ID binding exists for this vault: the page offers "Unlock with Touch ID"
	Confirm    func(reason string) bool // the extra Touch ID check of risky actions; nil = Touch ID is not enabled and nothing is asked
	Clipboard  Clipboard
	Quit       func() // ends the program
	Idle       time.Duration
	ExitAfter  time.Duration
	ClearAfter time.Duration
	Clock      func() time.Time
	Sleep      func(time.Duration)
	AfterFunc  func(d time.Duration, f func()) (stop func())
	Say        func(text string) // state lines for the terminal; never a value
	// SyncEvery is how often the unlocked vault file is checked for changes by another writer (0: SyncDefault, below 0: never by itself).
	SyncEvery time.Duration
	// Notify sends an event to the page (the Wails runtime in the window); nil: the page sees the change in the rev of its next ping.
	Notify func(event string, data any)
	// CLI links the icevault command of the application bundle into a PATH directory; nil when the window runs without one (the demo).
	CLI CLIInstaller
	// Vaults is the list of vaults the lock screen offers (vaults.go); nil: only the vault of Unlocker, Binding and Confirm.
	Vaults Vaults
	// Vault is the vault chosen at the start (ICEVAULT_VAULT, a file handed over by macOS, else the newest of the list); "" for none.
	Vault string
	// Pick shows the system file and folder dialogs; nil where there are none (tests).
	Pick Picker
	// PickDescription shows the system file dialog for the project description (.yaml, .yml); nil: the page cannot choose one.
	PickDescription func(title string) (string, error)
	// Update keeps the application up to date (internal/update); nil when the window runs without a bundle (the demo, tests).
	Update Updater
	// OpenURL opens an address in the browser; nil where there is none.
	OpenURL func(url string)
	// Maker and PickSave make "New vault" possible (newvault.go): both are needed, and the list of Vaults; nil: the page offers no new vault.
	Maker    VaultMaker
	PickSave SavePicker
	// AgentDir is the folder of the agent socket and journal (agentapi.Dir); "" switches the agent API off. The socket exists only while the vault is unlocked.
	AgentDir string
	// AgentTTL is how long a request waits for the person's answer (0: AgentTTLDefault).
	AgentTTL time.Duration
}

// CLIInstaller is internal/cliinstall as the window needs it.
type CLIInstaller interface {
	Status() cliinstall.Status
	Install(replace bool) (cliinstall.Status, error)
}

// App is the object the window binds. Only its exported methods are visible to the page.
type App struct {
	o Options

	mu          sync.Mutex // guards the fields below
	core        Core
	mode        string
	active      time.Time
	wrong       int
	touchFails  int
	unlockState string
	clipHash    [32]byte
	clipStop    func()
	rev         int        // how many times the vault was read again after another writer saved it (the page compares it)
	cur         Target     // how the chosen vault is unlocked
	vault       string     // the chosen vault file ("" without a list of vaults or before one is chosen)
	problem     error      // why the chosen vault cannot be unlocked (a coded *Error), nil when it can
	lastSync    time.Time  // the last background check of the vault file
	strength    sync.Mutex // one password estimate at a time (newvault.go)
	newRoot     string     // the project folder chosen for a new vault, and the file its description names
	newDefault  string
	newNoProj   bool         // a vault without a project was chosen for the new vault
	newPath     string       // the place the person chose for a new vault (newvault.go)
	kit         *recoveryKit // the password of the vault just made, until its recovery kit is saved or dropped
	changeWrong int          // wrong current passwords in a row in the change-password dialog (changepw.go)
	changing    sync.Mutex   // one password change at a time
	agent       *agentHub    // the agent API (agent.go); nil when it is off
	ops         sync.Mutex   // one operation on the core at a time: the window's own and the agents'

	unlocking  sync.Mutex // one unlock at a time
	confirming sync.Mutex // never two Touch ID dialogs at once
	syncing    sync.Mutex // one reload of the vault file at a time
}

// New builds an App. It starts locked.
// JSON keys and unlock methods the answers repeat.
const (
	keyTouchID  = "touchid"
	keyCode     = "code"
	keyPassword = "password"
	keyParams   = "params"
)

func New(o Options) *App {
	if o.Idle <= 0 {
		o.Idle = IdleDefault
	}
	if o.ExitAfter <= 0 {
		o.ExitAfter = ExitDefault
	}
	if o.ClearAfter <= 0 {
		o.ClearAfter = ClipboardClear
	}
	if o.SyncEvery == 0 {
		o.SyncEvery = SyncDefault
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	if o.AfterFunc == nil {
		o.AfterFunc = func(d time.Duration, f func()) func() {
			t := time.AfterFunc(d, f)
			return func() { t.Stop() }
		}
	}
	a := &App{o: o, mode: "view", active: o.Clock(), unlockState: "idle", cur: Target{Unlocker: o.Unlocker, Binding: o.Binding, Confirm: o.Confirm}}
	if o.AgentDir != "" {
		a.agent = newAgentHub(a, o.AgentDir, o.AgentTTL)
	}
	if o.Vaults != nil && o.Vault != "" {
		a.selectVault(o.Vault)
	}
	return a
}

func (a *App) say(text string) {
	if a.o.Say != nil {
		a.o.Say(text)
	}
}

func ok(data any) Response { return Response{200, data} }

// fail is an answer that carries only a code: the page translates it (srv.<code> in messages.json). No message text ever goes to the page.
func fail(status int, code string) Response {
	return Response{status, map[string]any{keyCode: code}}
}

// answer turns an error of the core into the answer for the page: a stable code and its parameters, never the text of the error (it may name
// a path or come from a library; the page has the words). An error without a code is classified by Classify.
func answer(err error) Response {
	var e *Error
	if errors.As(err, &e) && e.Code != "" {
		return Response{e.Status, map[string]any{"reload": e.Reload, "confirm": e.Confirm, keyCode: e.Code, keyParams: e.Params}}
	}
	var ce *cliinstall.Error
	if errors.As(err, &ce) {
		return Response{409, map[string]any{keyCode: ce.Code, keyParams: ce.Params}}
	}
	status, code, params := Classify(err)
	return Response{status, map[string]any{keyCode: code, keyParams: params}}
}

func (a *App) store() (Core, *Error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.core == nil {
		return nil, &Error{Status: 423, Code: "locked"}
	}
	return a.core, nil
}

func (a *App) editing() (Core, *Response) {
	c, e := a.store()
	if e != nil {
		r := answer(e)
		return nil, &r
	}
	a.mu.Lock()
	m := a.mode
	a.mu.Unlock()
	if m != "edit" {
		r := fail(403, "view_mode")
		return nil, &r
	}
	return c, nil
}

// ---- clock

func (a *App) touch(active bool) {
	if active {
		a.mu.Lock()
		a.active = a.o.Clock()
		a.mu.Unlock()
	}
}

func (a *App) shouldLock() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.core != nil && a.o.Clock().Sub(a.active) > a.o.Idle
}

func (a *App) expired() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.o.Clock().Sub(a.active) > a.o.ExitAfter
}

// tick applies the idle rules once: lock after the idle time, end the program after the exit time.
func (a *App) tick() {
	if a.shouldLock() {
		a.lock()
	}
	if a.expired() {
		a.say("exited (idle)")
		a.quit()
	}
	if a.syncDue() {
		go func() { _, _ = a.syncDisk(false, false) }() // the key derivation of a changed file takes a while: the idle clock does not wait for it
	}
}

// syncDue says whether the background check of the vault file is due (and starts its period).
func (a *App) syncDue() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.core == nil || a.o.SyncEvery < 0 {
		return false
	}
	if _, can := a.core.(Syncer); !can {
		return false
	}
	now := a.o.Clock()
	if now.Sub(a.lastSync) < a.o.SyncEvery {
		return false
	}
	a.lastSync = now
	return true
}

// syncDisk reads the vault file again when another writer saved it. wait: wait for a reload already running (a refresh, a write) instead of skipping.
// A change raises the rev and tells the page; the page redraws (or, with an edit open, offers a reload).
func (a *App) syncDisk(full, wait bool) (bool, error) {
	c, e := a.store()
	if e != nil {
		return false, e
	}
	s, can := c.(Syncer)
	if !can {
		return false, nil
	}
	if wait {
		a.syncing.Lock()
	} else if !a.syncing.TryLock() {
		return false, nil
	}
	changed, err := s.Sync(full)
	a.syncing.Unlock()
	if err != nil || !changed {
		return false, err
	}
	a.mu.Lock()
	a.rev++
	rev := a.rev
	a.mu.Unlock()
	a.say("the vault was read again: another writer saved it")
	if a.o.Notify != nil {
		a.o.Notify(EventVaultChanged, map[string]any{"rev": rev})
	}
	return true, nil
}

// Refresh reads the vault file again when it changed on disk (the page's Refresh button) and answers {changed, rev}; the page redraws either way.
func (a *App) Refresh() Response {
	if _, e := a.store(); e != nil {
		return answer(e)
	}
	changed, err := a.syncDisk(true, true)
	if err != nil {
		return answer(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return ok(map[string]any{"changed": changed, "rev": a.rev})
}

func (a *App) quit() {
	a.agentStop()
	if a.o.Quit != nil {
		a.o.Quit()
	}
}

// Watch runs the idle rules (lock, end) until ctx ends; interval 0 means half a second.
func Watch(ctx context.Context, a *App, interval time.Duration) {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.tick()
			}
		}
	}()
}

// ---- lock, status

func (a *App) lock() {
	a.dropKit()
	a.mu.Lock()
	c := a.core
	a.core, a.mode = nil, "view"
	a.mu.Unlock()
	a.agentStop()
	a.clearClipboardIfOurs()
	if c != nil {
		c.Lock()
		a.say("locked")
		if a.o.Notify != nil {
			a.o.Notify(EventVaultLocked, map[string]any{})
		}
	}
}

// Lock drops everything decrypted.
func (a *App) Lock() Response {
	a.lock()
	return ok(map[string]any{"ok": true})
}

// Close ends the program (the page's Close button).
func (a *App) Close() Response {
	a.lock()
	a.quit()
	return ok(map[string]any{"ok": true})
}

func (a *App) status() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	var focus any
	if a.o.Focus != "" {
		focus = a.o.Focus
	}
	left := MaxTouchFails - a.touchFails
	if left < 0 {
		left = 0
	}
	return map[string]any{"locked": a.core == nil, "mode": a.mode, keyTouchID: a.cur.Confirm != nil, "binding": a.cur.Binding, "unlock_state": a.unlockState,
		"focus": focus, "keyfile": a.cur.Unlocker != nil && a.cur.Unlocker.HasKeyFile(), "touch_left": left, "vaults": a.o.Vaults != nil, "vault": a.vault, "can_change_password": a.canChangePassword(), "agent": a.agent != nil}
}

// Status is the lock state and the mode.
func (a *App) Status() Response { return ok(a.status()) }

// Ping is the page's heartbeat; active says the person did something since the last one (it resets the idle clock).
func (a *App) Ping(active bool) Response {
	a.touch(active)
	a.mu.Lock()
	defer a.mu.Unlock()
	agent := 0
	if a.agent != nil {
		agent = a.agent.pendingCount()
	}
	return ok(map[string]any{"ok": true, "locked": a.core == nil, "mode": a.mode, "rev": a.rev, "agent": agent})
}

// ---- unlock: the only place a password is read

// attach makes c the unlocked core; it answers what the unlock reports besides ok: the count of entries whose managed-by the rule corrected.
func (a *App) attach(c Core) map[string]any {
	out := map[string]any{"ok": true}
	if cc, isC := c.(Corrector); isC {
		if n := cc.Corrected(); n > 0 {
			out["corrected"] = n
		}
	}
	a.mu.Lock()
	a.core, a.mode, a.unlockState, a.wrong = c, "view", "idle", 0
	a.active = a.o.Clock()
	a.mu.Unlock()
	a.say("unlocked")
	a.agentStart()
	a.opened()
	return out
}

// Unlock: method "touch" raises the Touch ID dialog from this process; method "password" opens the vault with that password.
func (a *App) Unlock(method, password string) Response {
	pw := []byte(password)
	defer wipe(pw)
	if _, e := a.store(); e == nil {
		return ok(map[string]any{"ok": true})
	}
	if method != "touch" && method != keyPassword {
		return fail(400, "bad_request")
	}
	if r, none := a.noTarget(); none {
		return r
	}
	if !a.unlocking.TryLock() {
		return fail(409, "unlock_running")
	}
	defer a.unlocking.Unlock()
	if method == "touch" {
		return a.unlockTouch()
	}
	return a.unlockPassword(pw)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (a *App) unlockTouch() Response {
	tg := a.target()
	if !tg.Binding {
		return fail(400, "no_binding")
	}
	a.mu.Lock()
	fails := a.touchFails
	a.mu.Unlock()
	if fails >= MaxTouchFails {
		return Response{403, map[string]any{keyPassword: true, keyCode: "touch_off"}}
	}
	if !a.confirming.TryLock() {
		return Response{409, map[string]any{keyPassword: true, keyCode: "touch_busy"}}
	}
	a.mu.Lock()
	a.unlockState = "waiting_touch"
	a.mu.Unlock()
	a.say("Touch ID requested by the page")
	pw, err := tg.Unlocker.Touch()
	a.mu.Lock()
	a.unlockState = "idle"
	if err != nil || pw == nil {
		a.touchFails++
	}
	a.mu.Unlock()
	a.confirming.Unlock()
	if err != nil {
		var e *Error // a coded refusal of the unlocker (the Touch ID tools are missing) keeps its code and parameters
		if errors.As(err, &e) && e.Code != "" {
			return Response{e.Status, map[string]any{keyPassword: true, keyCode: e.Code, keyParams: e.Params}}
		}
		return Response{409, map[string]any{keyPassword: true, keyCode: "touch_failed"}}
	}
	if pw == nil {
		return Response{401, map[string]any{keyPassword: true, keyCode: "touch_refused"}}
	}
	defer wipe(pw)
	c, err := tg.Unlocker.Open(pw)
	if err != nil {
		if errors.Is(err, ErrWrongPassword) {
			return Response{401, map[string]any{keyPassword: true, keyCode: "touch_stale"}}
		}
		status, code, params := Classify(err)
		return Response{status, map[string]any{keyPassword: true, keyCode: code, keyParams: params}}
	}
	return ok(a.attach(c))
}

func (a *App) unlockPassword(pw []byte) Response {
	if len(pw) == 0 || len(pw) > MaxPassword {
		return fail(400, "type_password")
	}
	c, err := a.target().Unlocker.Open(pw)
	if err != nil {
		if !errors.Is(err, ErrWrongPassword) {
			return answer(err)
		}
		a.mu.Lock()
		a.wrong++
		wrong := a.wrong
		a.mu.Unlock()
		a.o.Sleep(WrongDelay)
		if wrong >= MaxWrong {
			a.say("exited (5 wrong passwords in a row)")
			a.quit()
			return Response{401, map[string]any{"exit": true, keyCode: "wrong_password_exit"}}
		}
		left := MaxWrong - wrong
		return Response{401, map[string]any{"left": left, keyCode: "wrong_password", keyParams: map[string]any{"left": left}}}
	}
	return ok(a.attach(c))
}

// ---- Touch ID again

// confirm is the extra check of the risky actions: (true, "") or (false, code). One at a time; nothing is asked when Touch ID is not enabled.
func (a *App) confirm(reason string) (bool, string) {
	check := a.target().Confirm
	if check == nil {
		return true, ""
	}
	if !a.confirming.TryLock() {
		return false, "touch_busy"
	}
	defer a.confirming.Unlock()
	a.say("Touch ID requested by the page (" + reason + ")")
	if check(reason) {
		return true, ""
	}
	return false, "touch_refused"
}

func refused(code string) Response { return fail(403, code) }

// ---- mode, reads, reveal

// SetMode switches between "view" and "edit"; edit asks for the extra check.
func (a *App) SetMode(want string) Response {
	if _, e := a.store(); e != nil {
		return answer(e)
	}
	if want != "view" && want != "edit" {
		return fail(400, "bad_request")
	}
	a.mu.Lock()
	cur := a.mode
	a.mu.Unlock()
	if want == "edit" && cur != "edit" {
		if okc, why := a.confirm("edit"); !okc {
			return refused(why)
		}
	}
	a.mu.Lock()
	a.mode = want
	a.mu.Unlock()
	return ok(map[string]any{"mode": want})
}

// Read runs a read op (see Core). Allowed in view mode.
func (a *App) Read(op string, args map[string]any) Response {
	c, e := a.store()
	if e != nil {
		return answer(e)
	}
	if args == nil {
		args = map[string]any{}
	}
	switch op {
	case "nav", "item", "compare", "references", "pull-candidates", "shared", "visibility", "preview-value", "migrate-plan":
	default:
		return fail(404, "not_found")
	}
	a.ops.Lock()
	data, err := c.Read(op, args)
	a.ops.Unlock()
	if err != nil {
		return answer(err)
	}
	if op == "nav" {
		if m, isMap := data.(map[string]any); isMap {
			out := make(map[string]any, len(m)+1)
			for k, v := range m {
				out[k] = v
			}
			if a.o.Focus != "" {
				out["focus"] = a.o.Focus
			} else {
				out["focus"] = nil
			}
			data = out
		}
	}
	return ok(data)
}

func str(args map[string]any, k string) string {
	s, _ := args[k].(string)
	return s
}

func (a *App) reveal(c Core, args map[string]any) (string, *Response) {
	a.ops.Lock()
	value, err := c.Reveal(str(args, "section"), str(args, "name"), str(args, "group"), str(args, "key"))
	a.ops.Unlock()
	if err != nil {
		r := answer(err)
		return "", &r
	}
	if okc, why := a.confirm("reveal"); !okc {
		r := refused(why)
		return "", &r
	}
	return value, nil
}

// Reveal answers {value}: one value, after the extra check. The page shows it for 20 seconds and drops it.
func (a *App) Reveal(args map[string]any) Response {
	c, e := a.store()
	if e != nil {
		return answer(e)
	}
	value, r := a.reveal(c, args)
	if r != nil {
		return *r
	}
	return ok(map[string]any{"value": value})
}

// ---- writes

// Write runs a write op (see Core). All of them are refused in view mode. Where the browser screen asked for a check, so does this.
func (a *App) Write(op string, args map[string]any) Response {
	if !writeOps[op] {
		return fail(404, "not_found")
	}
	c, r := a.editing()
	if r != nil {
		return *r
	}
	if args == nil {
		args = map[string]any{}
	}
	switch op {
	case "apply-shared", "duplicates-apply":
		if !stringList(args["keys"]) {
			return fail(400, "bad_request")
		}
	case "create-file", "replace-file":
		raw, isStr := args["data"].(string)
		if !isStr {
			raw = ""
		}
		if len(raw) > maxFileBytes*2 {
			return fail(400, "bad_request")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(raw)
		if err != nil {
			return fail(400, "bad_request")
		}
		cp := make(map[string]any, len(args))
		for k, v := range args {
			cp[k] = v
		}
		cp["data"] = data
		args = cp
		if op == "replace-file" {
			if okc, why := a.confirm("replace"); !okc {
				return refused(why)
			}
		}
	}
	// what another writer saved since the last check is read first, so this write lands on it instead of failing with "changed on disk"
	a.ops.Lock()
	_, _ = a.syncDisk(false, true)
	data, err := c.Write(op, args)
	a.ops.Unlock()
	if err != nil {
		return answer(err)
	}
	if data == nil {
		data = map[string]any{"ok": true}
	}
	return ok(data)
}

func stringList(v any) bool {
	l, isList := v.([]any)
	if !isList {
		if _, isStrs := v.([]string); isStrs {
			return true
		}
		return false
	}
	for _, x := range l {
		if _, isStr := x.(string); !isStr {
			return false
		}
	}
	return true
}

var writeOps = func() map[string]bool {
	m := map[string]bool{}
	for _, op := range []string{"set", "meta", "seal", "create-section", "update-section", "retire-section", "create-item", "update-item", "uses",
		"create-group", "rename-group", "generate", "generate-seal", "scope", "make-global", "move-entry", "create-site", "add-site", "pull-globals",
		"apply-shared", "group-sites", "item-sites", "site-type", "duplicates", "duplicates-apply", "create-entry", "retire-entry", "restore-entry",
		"retire-group", "create-missing", "retire-item", "retire-file", "create-file", "replace-file", "managed",
		"m-var", "m-import", "m-connection", "m-field", "m-site", "m-product", "m-env", "m-env-fill", "m-env-adopt", "m-other", "migrate-apply"} {
		m[op] = true
	}
	return m
}()

// ---- clipboard

func hash(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func (a *App) putClipboard(text string) error {
	if a.o.Clipboard == nil {
		return errors.New("no clipboard")
	}
	if err := a.o.Clipboard.Set(text); err != nil {
		return err
	}
	h := hash(text)
	a.mu.Lock()
	if a.clipStop != nil {
		a.clipStop()
	}
	a.clipHash = h
	a.clipStop = a.o.AfterFunc(a.o.ClearAfter, a.clearClipboardIfOurs)
	a.mu.Unlock()
	return nil
}

// clearClipboardIfOurs empties the clipboard only when it still holds what this program put there (the person may have copied something else since).
func (a *App) clearClipboardIfOurs() {
	a.mu.Lock()
	h, stop := a.clipHash, a.clipStop
	a.clipStop, a.clipHash = nil, [32]byte{}
	a.mu.Unlock()
	if stop == nil || a.o.Clipboard == nil {
		return
	}
	stop()
	cur, err := a.o.Clipboard.Get()
	if err != nil {
		return
	}
	hc := hash(cur)
	if subtle.ConstantTimeCompare(hc[:], h[:]) == 1 {
		_ = a.o.Clipboard.Set("")
	}
}

// CopyText puts text the page already shows (a revealed value) on the clipboard; it is cleared after ClipboardClear unless something else was copied.
func (a *App) CopyText(text string) Response {
	if _, e := a.store(); e != nil {
		return answer(e)
	}
	if err := a.putClipboard(text); err != nil {
		return fail(500, "copy_failed")
	}
	return ok(map[string]any{"ok": true})
}

// CopySecret reveals the value in Go (after the extra check) and puts it on the clipboard: the page never receives it.
func (a *App) CopySecret(args map[string]any) Response {
	c, e := a.store()
	if e != nil {
		return answer(e)
	}
	value, r := a.reveal(c, args)
	if r != nil {
		return *r
	}
	if err := a.putClipboard(value); err != nil {
		return fail(500, "copy_failed")
	}
	return ok(map[string]any{"ok": true})
}

// ---- the icevault command

// CLIStatus says whether the icevault command of this application is linked into a PATH directory. It reads the file system only and needs no unlock.
func (a *App) CLIStatus() Response {
	if a.o.CLI == nil {
		return ok(cliinstall.Status{State: cliinstall.Unavailable, Code: "cli_unavailable"})
	}
	return ok(a.o.CLI.Status())
}

// CLIInstall links the command (an unlocked window, and the extra check where Touch ID is on). A link that points elsewhere is replaced only with replace
// set, which the page sends after its own confirmation.
func (a *App) CLIInstall(replace bool) Response {
	if _, e := a.store(); e != nil {
		return answer(e)
	}
	if a.o.CLI == nil {
		return fail(409, "cli_unavailable")
	}
	if okc, why := a.confirm("cli"); !okc {
		return refused(why)
	}
	st, err := a.o.CLI.Install(replace)
	if err != nil {
		return answer(err)
	}
	a.say("the icevault command was linked")
	return ok(st)
}
