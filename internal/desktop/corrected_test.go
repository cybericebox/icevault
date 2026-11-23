package desktop

import "testing"

// correctingCore is a core that corrected who manages some entries when it was opened.
type correctingCore struct {
	MemoryCore
	n, calls int
}

func (c *correctingCore) Corrected() int { c.calls++; n := c.n; c.n = 0; return n }

type correctingUnlocker struct {
	MemoryUnlocker
	core *correctingCore
}

func (u *correctingUnlocker) Open(pw []byte) (Core, error) {
	if _, err := u.MemoryUnlocker.Open(pw); err != nil {
		return nil, err
	}
	return u.core, nil
}

func TestUnlockSaysHowManyEntriesTheRuleCorrected(t *testing.T) {
	h := newHarness(t)
	cu := &correctingUnlocker{MemoryUnlocker: MemoryUnlocker{Password: "throwaway-pw"}, core: &correctingCore{n: 3}}
	h.app.cur.Unlocker = cu
	r := h.app.Unlock("password", "throwaway-pw")
	if r.Status != 200 || data(r)["corrected"] != 3 || data(r)["ok"] != true {
		t.Fatalf("unlock: %d %v", r.Status, r.Data)
	}
	h.app.Lock()
	cu.core.n = 0
	r = h.app.Unlock("password", "throwaway-pw")
	if _, said := data(r)["corrected"]; r.Status != 200 || said {
		t.Fatalf("nothing corrected: no count (%v)", r.Data)
	}
	// a core without the interface answers as before
	h2 := newHarness(t)
	if r := h2.app.Unlock("password", "throwaway-pw"); r.Status != 200 || len(data(r)) != 1 {
		t.Fatalf("plain core: %v", r.Data)
	}
}

func TestManagedIsAWriteOp(t *testing.T) {
	h := newHarness(t)
	h.unlock(t)
	if r := h.app.Write("managed", map[string]any{"section": "environments", "name": "e", "group": "g", "key": "K", "managed": "owner"}); r.Status != 403 {
		t.Fatalf("view mode refuses it: %d", r.Status)
	}
}
