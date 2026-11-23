//go:build harness && !desktop

package main

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/desktop"
)

func raw(s ...string) []json.RawMessage {
	out := make([]json.RawMessage, len(s))
	for i, x := range s {
		out[i] = json.RawMessage(x)
	}
	return out
}

// The harness runs the bound methods of the real App by name, as the Wails bridge does: exported methods with the right arguments only.
func TestHarnessCallsTheApp(t *testing.T) {
	a := desktop.New(desktop.Options{Unlocker: &desktop.MemoryUnlocker{Password: "throwaway"}})
	if r, st := call(a, "Status", nil); st != 200 || r.Data.(map[string]any)["locked"] != true {
		t.Fatalf("status: %d %v", st, r.Data)
	}
	if r, st := call(a, "Unlock", raw(`"password"`, `"throwaway"`)); st != 200 || r.Status != 200 {
		t.Fatalf("unlock: %d %+v", st, r)
	}
	if r, _ := call(a, "Read", raw(`"nav"`, `{}`)); r.Status != 200 {
		t.Fatalf("read: %+v", r)
	}
	for _, bad := range []struct {
		method string
		args   []json.RawMessage
		want   int
	}{{"lock", nil, 404}, {"Nope", nil, 404}, {"", nil, 404}, {"Unlock", raw(`"password"`), 400}, {"Unlock", raw(`1`, `2`), 400}} {
		if _, st := call(a, bad.method, bad.args); st != bad.want {
			t.Errorf("%s: %d, want %d", bad.method, st, bad.want)
		}
	}
}

// The page is the window's own, with the stand-in of the bridge loaded before adapter.js; the window's frontend itself has no harness script.
func TestHarnessPageLoadsTheShim(t *testing.T) {
	front, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		t.Fatal(err)
	}
	p, err := pageFS(front)
	if err != nil {
		t.Fatal(err)
	}
	body, err := desktop.BuildPage(p, "n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `<script src="/harness.js"></script><script src="/adapter.js"></script>`) {
		t.Fatal("the shim is not loaded before the adapter")
	}
	if _, err := fs.Stat(front, "harness.js"); err == nil {
		t.Fatal("the window's frontend must not carry the harness script")
	}
}
