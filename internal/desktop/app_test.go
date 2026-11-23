package desktop

import (
	"encoding/base64"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type fakeClip struct {
	text string
	sets int
}

func (c *fakeClip) Set(s string) error   { c.text = s; c.sets++; return nil }
func (c *fakeClip) Get() (string, error) { return c.text, nil }

type harness struct {
	app      *App
	un       *MemoryUnlocker
	clip     *fakeClip
	now      time.Time
	quit     int
	slept    []time.Duration
	fire     func()
	confirms []string
	allow    bool
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{un: &MemoryUnlocker{Password: "throwaway-pw"}, clip: &fakeClip{}, now: time.Unix(1000, 0), allow: true}
	h.app = New(Options{
		Unlocker: h.un, Clipboard: h.clip, Quit: func() { h.quit++ },
		Clock: func() time.Time { return h.now }, Sleep: func(d time.Duration) { h.slept = append(h.slept, d) },
		AfterFunc: func(d time.Duration, f func()) func() { h.fire = f; return func() {} },
		Confirm:   func(reason string) bool { h.confirms = append(h.confirms, reason); return h.allow },
		Binding:   true,
	})
	return h
}

func (h *harness) unlock(t *testing.T) {
	t.Helper()
	if r := h.app.Unlock("password", "throwaway-pw"); r.Status != 200 {
		t.Fatalf("unlock: %d", r.Status)
	}
}

func data(r Response) map[string]any { m, _ := r.Data.(map[string]any); return m }

func TestLockedAnswers423(t *testing.T) {
	h := newHarness(t)
	for _, r := range []Response{h.app.Read("nav", nil), h.app.Write("set", nil), h.app.Reveal(nil), h.app.SetMode("edit"), h.app.CopyText("x")} {
		if r.Status != 423 || data(r)["code"] != "locked" {
			t.Fatalf("want 423 locked, got %d %v", r.Status, r.Data)
		}
	}
	if st := data(h.app.Status()); st["locked"] != true || st["mode"] != "view" {
		t.Fatalf("status %v", st)
	}
}

func TestUnlockWrongThenRight(t *testing.T) {
	h := newHarness(t)
	r := h.app.Unlock("password", "nope")
	if r.Status != 401 || data(r)["code"] != "wrong_password" || data(r)["left"] != 4 {
		t.Fatalf("%d %v", r.Status, r.Data)
	}
	if len(h.slept) != 1 || h.slept[0] != WrongDelay {
		t.Fatalf("delay %v", h.slept)
	}
	if r := h.app.Unlock("password", ""); r.Status != 400 || data(r)["code"] != "type_password" {
		t.Fatalf("%d", r.Status)
	}
	h.unlock(t)
	if st := data(h.app.Status()); st["locked"] != false {
		t.Fatal("not unlocked")
	}
	if r := h.app.Unlock("password", "ignored"); r.Status != 200 { // already unlocked
		t.Fatal("second unlock")
	}
	if h.un.Opens != 1 {
		t.Fatalf("opens %d", h.un.Opens)
	}
}

func TestFifthWrongPasswordEndsProgram(t *testing.T) {
	h := newHarness(t)
	var last Response
	for i := 0; i < MaxWrong; i++ {
		last = h.app.Unlock("password", "bad")
	}
	if last.Status != 401 || data(last)["exit"] != true || h.quit != 1 {
		t.Fatalf("%v quit=%d", last.Data, h.quit)
	}
}

func TestBadUnlockRequests(t *testing.T) {
	h := newHarness(t)
	if r := h.app.Unlock("other", "x"); r.Status != 400 {
		t.Fatal(r.Status)
	}
	if r := h.app.Unlock("password", strings.Repeat("a", MaxPassword+1)); r.Status != 400 {
		t.Fatal(r.Status)
	}
}

func TestTouchRefusedThreeTimesThenOff(t *testing.T) {
	h := newHarness(t) // MemoryUnlocker.Touch always answers "refused"
	for i := 0; i < MaxTouchFails; i++ {
		if r := h.app.Unlock("touch", ""); r.Status != 401 || data(r)["code"] != "touch_refused" {
			t.Fatalf("%d %v", r.Status, r.Data)
		}
	}
	if r := h.app.Unlock("touch", ""); r.Status != 403 || data(r)["code"] != "touch_off" {
		t.Fatalf("%d %v", r.Status, r.Data)
	}
	if st := data(h.app.Status()); st["touch_left"] != 0 {
		t.Fatal(st)
	}
}

func TestViewModeRefusesWrites(t *testing.T) {
	h := newHarness(t)
	h.unlock(t)
	r := h.app.Write("set", map[string]any{"value": "v"})
	if r.Status != 403 || data(r)["code"] != "view_mode" {
		t.Fatalf("%d %v", r.Status, r.Data)
	}
	if h.app.Write("no-such-op", nil).Status != 404 || h.app.Read("set", nil).Status != 404 {
		t.Fatal("unknown ops must be 404")
	}
	// reads and preview are allowed in view mode
	if h.app.Read("preview-value", map[string]any{"value": "x"}).Status != 200 {
		t.Fatal("preview")
	}
}

func TestEditModeAndConfirm(t *testing.T) {
	h := newHarness(t)
	h.unlock(t)
	h.allow = false
	if r := h.app.SetMode("edit"); r.Status != 403 || data(r)["code"] != "touch_refused" {
		t.Fatalf("%d %v", r.Status, r.Data)
	}
	h.allow = true
	if r := h.app.SetMode("edit"); r.Status != 200 || data(r)["mode"] != "edit" {
		t.Fatalf("%d", r.Status)
	}
	if r := h.app.SetMode("edit"); r.Status != 200 || len(h.confirms) != 2 { // no second check when already editing
		t.Fatalf("confirms %v", h.confirms)
	}
	if h.app.SetMode("bogus").Status != 400 {
		t.Fatal("bad mode")
	}
	if r := h.app.Write("set", map[string]any{"value": "v"}); r.Status != 200 || data(r)["ok"] != true {
		t.Fatalf("%d %v", r.Status, r.Data)
	}
	r := h.app.Write("retire-section", nil)
	if r.Status != 409 || data(r)["code"] != "section_has_items" {
		t.Fatalf("%d %v", r.Status, r.Data)
	}
	if h.app.Lock().Status != 200 || data(h.app.Status())["mode"] != "view" {
		t.Fatal("lock must reset the mode")
	}
}

func TestWriteValidation(t *testing.T) {
	h := newHarness(t)
	h.unlock(t)
	h.app.SetMode("edit")
	if h.app.Write("apply-shared", map[string]any{"keys": []any{"a", 1.0}}).Status != 400 || h.app.Write("apply-shared", nil).Status != 400 {
		t.Fatal("keys must be strings")
	}
	if h.app.Write("apply-shared", map[string]any{"keys": []any{"a"}}).Status != 200 {
		t.Fatal("good keys")
	}
	if h.app.Write("create-file", map[string]any{"data": "!!not base64!!"}).Status != 400 {
		t.Fatal("bad base64")
	}
	h.confirms = nil
	enc := base64.StdEncoding.EncodeToString([]byte("file body"))
	if r := h.app.Write("replace-file", map[string]any{"rel": "a", "data": enc}); r.Status != 200 {
		t.Fatalf("%d %v", r.Status, r.Data)
	}
	if len(h.confirms) != 1 || h.confirms[0] != "replace" {
		t.Fatalf("confirms %v", h.confirms)
	}
	h.allow = false
	if r := h.app.Write("replace-file", map[string]any{"rel": "a", "data": enc}); r.Status != 403 {
		t.Fatalf("%d", r.Status)
	}
}

func TestRevealNeedsConfirmAndCopyNeverReturnsValue(t *testing.T) {
	h := newHarness(t)
	h.unlock(t)
	ref := map[string]any{"section": "demo", "name": "item", "group": "general", "key": "API_KEY"}
	if r := h.app.Reveal(ref); r.Status != 200 || data(r)["value"] != "demo-token-value" {
		t.Fatalf("%d", r.Status)
	}
	h.allow = false
	if r := h.app.Reveal(ref); r.Status != 403 {
		t.Fatalf("%d", r.Status)
	}
	if r := h.app.CopySecret(ref); r.Status != 403 || h.clip.sets != 0 {
		t.Fatal("refused copy must not touch the clipboard")
	}
	h.allow = true
	r := h.app.CopySecret(ref)
	if r.Status != 200 || data(r)["value"] != nil || h.clip.text != "demo-token-value" {
		t.Fatalf("%d %v", r.Status, r.Data)
	}
	if h.app.Reveal(map[string]any{"section": "x"}).Status != 404 {
		t.Fatal("unknown value")
	}
}

func TestClipboardClearsOnlyOurValue(t *testing.T) {
	h := newHarness(t)
	h.unlock(t)
	h.app.CopyText("first")
	h.fire() // the timer fires: still ours, cleared
	if h.clip.text != "" {
		t.Fatal("not cleared")
	}
	h.app.CopyText("second")
	h.clip.text = "something else the person copied"
	h.fire()
	if h.clip.text != "something else the person copied" {
		t.Fatal("cleared a value that is not ours")
	}
	h.app.CopyText("third")
	h.app.Lock() // locking clears our value at once
	if h.clip.text != "" {
		t.Fatal("lock must clear the clipboard")
	}
}

func TestIdleLockAndExit(t *testing.T) {
	h := newHarness(t)
	h.unlock(t)
	h.now = h.now.Add(IdleDefault - time.Second)
	h.app.Ping(true) // activity resets the clock
	h.now = h.now.Add(IdleDefault - time.Second)
	h.app.tick()
	if data(h.app.Status())["locked"] != false {
		t.Fatal("locked too early")
	}
	h.now = h.now.Add(2 * time.Second)
	h.app.tick()
	if data(h.app.Status())["locked"] != true {
		t.Fatal("must lock after idle")
	}
	if h.quit != 0 {
		t.Fatal("quit too early")
	}
	h.now = h.now.Add(ExitDefault)
	h.app.tick()
	if h.quit != 1 {
		t.Fatal("must end after the exit time")
	}
}

// The idle lock tells the page at once (the vault-locked event), so nothing decrypted waits on the screen for the next heartbeat; locking a locked
// window tells nothing.
func TestIdleLockTellsThePage(t *testing.T) {
	h := newHarness(t)
	var events []string
	h.app.o.Notify = func(name string, _ any) { events = append(events, name) }
	h.unlock(t)
	h.now = h.now.Add(IdleDefault + time.Second)
	h.app.tick()
	h.app.tick()
	h.app.Lock()
	if len(events) != 1 || events[0] != EventVaultLocked {
		t.Fatalf("events %v", events)
	}
}

func TestPingWithoutActivityDoesNotResetIdle(t *testing.T) {
	h := newHarness(t)
	h.unlock(t)
	h.now = h.now.Add(IdleDefault + time.Second)
	h.app.Ping(false)
	h.app.tick()
	if data(h.app.Status())["locked"] != true {
		t.Fatal("a passive heartbeat must not keep it open")
	}
}

func TestNavCarriesFocus(t *testing.T) {
	h := newHarness(t)
	h.app.o.Focus = "prod"
	h.unlock(t)
	if d := data(h.app.Read("nav", nil)); d["focus"] != "prod" {
		t.Fatal(d)
	}
}

func TestPageAndCSP(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":    {Data: []byte("<style nonce=\"__NONCE__\">/*__FONTS__*/ /*__CREST__*/ /*__APPICON__*/</style><script nonce=\"__NONCE__\">const MSG = /*__MESSAGES__*/{};</script>")},
		"fonts.css":     {Data: []byte("F")},
		"crest.css":     {Data: []byte("C")},
		"appicon.css":   {Data: []byte("I")},
		"messages.json": {Data: []byte(`{"en":{"a":"</script>"}}`)},
	}
	b, err := BuildPage(fsys, "N0NCE")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "__") || strings.Count(s, "N0NCE") != 2 || strings.Contains(s, "</script>\"") {
		t.Fatalf("page: %s", s)
	}
	if !strings.Contains(s, "C I") {
		t.Fatalf("the lock mark and the application icon are not in the page: %s", s)
	}
	for _, part := range []string{"appicon.css", "crest.css"} {
		kept := fsys[part]
		delete(fsys, part)
		if _, err := BuildPage(fsys, "n"); err == nil {
			t.Fatal("a missing part must fail: " + part)
		}
		fsys[part] = kept
	}
	csp := CSP("N")
	for _, must := range []string{"default-src 'none'", "connect-src 'self'", "img-src data:", "frame-ancestors 'none'", "'nonce-N'"} {
		if !strings.Contains(csp, must) {
			t.Fatalf("csp lacks %s", must)
		}
	}
	if strings.Contains(csp, "unsafe") || strings.Contains(csp, "http") || strings.Contains(csp, "*") {
		t.Fatal("csp too loose: " + csp)
	}
}
