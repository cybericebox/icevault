package desktop

import (
	"crypto/subtle"
	"sync"
)

// MemoryUnlocker is an in-memory vault with throwaway data: the fake of the tests and the content of the --demo run of the window. It is not a vault.
type MemoryUnlocker struct {
	Password string
	Opens    int // successful opens
	mu       sync.Mutex
}

func (u *MemoryUnlocker) Open(password []byte) (Core, error) {
	if subtle.ConstantTimeCompare(password, []byte(u.Password)) != 1 {
		return nil, ErrWrongPassword
	}
	u.mu.Lock()
	u.Opens++
	u.mu.Unlock()
	return &MemoryCore{values: map[string]string{"demo/item/general/API_KEY": "demo-token-value"}}, nil
}

func (u *MemoryUnlocker) Touch() ([]byte, error) { return nil, nil }
func (u *MemoryUnlocker) HasKeyFile() bool       { return false }

// MemoryCore records the calls it gets so that tests can check what reached the core.
type MemoryCore struct {
	mu     sync.Mutex
	values map[string]string
	Calls  []string // "op" of every Write
	Args   []map[string]any
	Locked bool
}

func (c *MemoryCore) Read(op string, args map[string]any) (any, error) {
	if op == "nav" {
		return map[string]any{"sections": []any{}, "consumer": false, "manifest_i18n": map[string]any{}}, nil
	}
	return map[string]any{"op": op}, nil
}

func (c *MemoryCore) Write(op string, args map[string]any) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Calls = append(c.Calls, op)
	c.Args = append(c.Args, args)
	if op == "retire-section" {
		return nil, &Error{Status: 409, Code: "section_has_items"}
	}
	return nil, nil
}

func (c *MemoryCore) Reveal(section, name, group, key string) (string, error) {
	v, found := c.values[section+"/"+name+"/"+group+"/"+key]
	if !found {
		return "", &Error{Status: 404, Code: CodeNotFound}
	}
	return v, nil
}

func (c *MemoryCore) Lock() { c.mu.Lock(); c.Locked = true; c.mu.Unlock() }
