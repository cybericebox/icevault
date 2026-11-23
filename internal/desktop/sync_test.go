package desktop

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// syncCore is a MemoryCore that can be told the vault file changed on disk.
type syncCore struct {
	MemoryCore
	mu      sync.Mutex
	pending bool // another writer saved: the next Sync reads it
	fail    error
	syncs   []bool
}

func (c *syncCore) Sync(full bool) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.syncs = append(c.syncs, full)
	if c.fail != nil {
		return false, c.fail
	}
	ch := c.pending
	c.pending = false
	return ch, nil
}

func (c *syncCore) changeOnDisk() { c.mu.Lock(); c.pending = true; c.mu.Unlock() }

type syncUnlocker struct{ core *syncCore }

func (u syncUnlocker) Open(pw []byte) (Core, error) {
	if string(pw) != "throwaway-pw" {
		return nil, ErrWrongPassword
	}
	return u.core, nil
}
func (syncUnlocker) Touch() ([]byte, error) { return nil, nil }
func (syncUnlocker) HasKeyFile() bool       { return false }

type syncHarness struct {
	app    *App
	core   *syncCore
	now    time.Time
	events chan map[string]any
}

func newSyncHarness(t *testing.T) *syncHarness {
	t.Helper()
	h := &syncHarness{core: &syncCore{}, now: time.Unix(1000, 0), events: make(chan map[string]any, 8)}
	h.app = New(Options{Unlocker: syncUnlocker{h.core}, Clock: func() time.Time { return h.now }, Sleep: func(time.Duration) {},
		Notify: func(ev string, d any) {
			if ev == EventVaultChanged {
				h.events <- d.(map[string]any)
			}
		}})
	if r := h.app.Unlock("password", "throwaway-pw"); r.Status != 200 {
		t.Fatalf("unlock: %d", r.Status)
	}
	return h
}

func (h *syncHarness) event(t *testing.T) map[string]any {
	t.Helper()
	select {
	case e := <-h.events:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no vault-changed event")
		return nil
	}
}

func (h *syncHarness) noEvent(t *testing.T) {
	t.Helper()
	select {
	case e := <-h.events:
		t.Fatalf("an unexpected vault-changed event: %v", e)
	case <-time.After(50 * time.Millisecond):
	}
}

// The idle tick looks at the vault file every SyncEvery: a change by another writer raises the rev and tells the page once; an unchanged file says nothing.
func TestTickNoticesAChangeOnDisk(t *testing.T) {
	h := newSyncHarness(t)
	h.now = h.now.Add(SyncDefault)
	h.app.tick()
	h.noEvent(t)
	h.core.changeOnDisk()
	h.app.tick() // the same moment: not due yet
	h.noEvent(t)
	h.now = h.now.Add(SyncDefault)
	h.app.tick()
	if e := h.event(t); e["rev"] != 1 {
		t.Fatalf("event %v", e)
	}
	if p := data(h.app.Ping(false)); p["rev"] != 1 {
		t.Fatalf("ping %v", p)
	}
	h.now = h.now.Add(SyncDefault)
	h.app.tick()
	h.noEvent(t) // read once: no reload loop
}

// Refresh compares the bytes (full) and answers the rev; the page's own writes read a pending change first and do not count as one themselves.
func TestRefreshAndWritesSync(t *testing.T) {
	h := newSyncHarness(t)
	r := h.app.Refresh()
	if r.Status != 200 || data(r)["changed"] != false || data(r)["rev"] != 0 {
		t.Fatalf("refresh %d %v", r.Status, r.Data)
	}
	if got := h.core.syncs; len(got) != 1 || !got[0] {
		t.Fatalf("refresh must compare the bytes: %v", got)
	}
	h.core.changeOnDisk()
	if r := h.app.Refresh(); data(r)["changed"] != true || data(r)["rev"] != 1 {
		t.Fatalf("refresh after a change %v", r.Data)
	}
	h.event(t)

	if r := h.app.SetMode("edit"); r.Status != 200 {
		t.Fatal(r.Status)
	}
	h.core.changeOnDisk()
	if r := h.app.Write("set", map[string]any{}); r.Status != 200 {
		t.Fatalf("write %d", r.Status)
	}
	if e := h.event(t); e["rev"] != 2 {
		t.Fatalf("the change before the write: %v", e)
	}
	if r := h.app.Write("set", map[string]any{}); r.Status != 200 {
		t.Fatalf("write %d", r.Status)
	}
	h.noEvent(t)

	h.core.mu.Lock()
	h.core.fail = errors.New("unreadable")
	h.core.mu.Unlock()
	if r := h.app.Refresh(); r.Status == 200 {
		t.Fatal("a failed reload must be an error for the Refresh button")
	}
	h.app.Lock()
	if r := h.app.Refresh(); r.Status != 423 {
		t.Fatalf("locked refresh %d", r.Status)
	}
}

// A core that cannot reload (the demo) is never asked; Refresh still answers.
func TestRefreshWithoutSyncer(t *testing.T) {
	h := newHarness(t)
	h.unlock(t)
	if r := h.app.Refresh(); r.Status != 200 || data(r)["changed"] != false {
		t.Fatalf("%d %v", r.Status, r.Data)
	}
	h.now = h.now.Add(time.Minute)
	if h.app.syncDue() {
		t.Fatal("a core without Sync is due")
	}
}
