package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// runExternal runs `external serve` with the given input lines, as the calling program would, and returns the replies.
func runExternal(h *harness, lines ...string) (int, []map[string]any) {
	h.out.Reset()
	h.errb.Reset()
	asks := append([]string(nil), h.pw...)
	e := &Env{Getenv: func(k string) string { return h.env[k] }, Out: &h.out, Err: &h.errb, Now: time.Now, Root: h.root, Exec: h.exec, In: strings.NewReader(strings.Join(lines, "\n") + "\n"),
		StdioIsTerminal: func() bool { return false },
		Ask: func(string) ([]byte, error) {
			if len(asks) == 0 {
				return nil, errExit{NeedsOwner}
			}
			p := asks[0]
			asks = asks[1:]
			return []byte(p), nil
		}}
	rc := Run([]string{"external", "serve"}, e)
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(h.out.String()), "\n") {
		if ln == "" {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			panic(err)
		}
		out = append(out, m)
	}
	return rc, out
}

const extOpen = `{"op":"open","name":"monitor","title":"Monitor","keys":{"MONITOR_ACCOUNT":"plain","MONITOR_KEY":"secret"},"help":{"MONITOR_KEY":"the key of the monitor"}}`

func TestExternalGetPutClose(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	rc, out := runExternal(h, extOpen,
		`{"op":"get","group":"monitoring","key":"MONITOR_KEY"}`,
		`{"op":"put","group":"monitoring","key":"MONITOR_KEY","value":"tok-throwaway-1"}`,
		`{"op":"put","group":"monitoring","key":"MONITOR_ACCOUNT","value":"someone"}`,
		`{"op":"get","group":"monitoring","key":"MONITOR_KEY"}`,
		`{"op":"put","group":"monitoring","key":"MONITOR_KEY","value":"tok-throwaway-2"}`,
		`{"op":"put","group":"monitoring","key":"NOT_A_KEY","value":"x"}`,
		`{"op":"nope"}`,
		`{"op":"get","group":"../x","key":"MONITOR_KEY"}`,
		`{"op":"close"}`)
	if rc != 0 || len(out) != 10 {
		t.Fatalf("rc=%d out=%v err=%s", rc, out, h.errb.String())
	}
	if out[0]["ok"] != true || out[1]["ok"] != true || out[1]["value"] != nil {
		t.Fatalf("open/get of a missing entry: %v", out[:2])
	}
	if out[4]["value"] != "tok-throwaway-1" {
		t.Fatalf("get after put: %v", out[4])
	}
	if out[6]["ok"] == true || !strings.Contains(out[6]["error"].(string), "is not a key of monitor") || out[7]["ok"] == true || out[9]["ok"] != true || out[8]["ok"] == true {
		t.Fatalf("refusals: %v", out[6:])
	}
	if strings.Contains(h.errb.String(), "tok-throwaway") {
		t.Fatal("a value on stderr")
	}
	// the vault has the connection the description serves as monitor (kind other), with the fields of its variables
	v, err := vault.Open(h.env["ICEVAULT_VAULT"], vault.Credentials{Password: []byte(pw)})
	if err != nil {
		t.Fatal(err)
	}
	m, err := vmodel.Load(v)
	v.Close()
	if err != nil {
		t.Fatal(err)
	}
	var c *vmodel.Connection
	for _, x := range m.Connections {
		if x.Kind == "other" {
			c = x
		}
	}
	if c == nil || c.Field("api_key") == nil || c.Field("api_key").Value != "tok-throwaway-2" || !c.Field("api_key").Secret || c.Field("account").Value != "someone" {
		t.Fatalf("connection: %+v", c)
	}
	// a new session sees them
	rc, out = runExternal(h, extOpen, `{"op":"get","group":"monitoring","key":"MONITOR_ACCOUNT"}`, `{"op":"get","group":"monitoring","key":"MONITOR_KEY"}`)
	if rc != 0 || out[2]["value"] != "tok-throwaway-2" || out[1]["value"] != "someone" {
		t.Fatalf("%v", out)
	}
}

func TestExternalRefusals(t *testing.T) {
	h := newHarness(t)
	// not a terminal
	e := &Env{Getenv: func(string) string { return "" }, Out: &h.out, Err: &h.errb, StdioIsTerminal: func() bool { return true }, In: strings.NewReader("")}
	if rc := Run([]string{"external", "serve"}, e); rc != 1 || !strings.Contains(h.errb.String(), "not for a terminal") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	// no vault
	if rc, _ := runExternal(h, extOpen); rc != 1 || !strings.Contains(h.errb.String(), "there is no vault at") {
		t.Fatalf("%s", h.errb.String())
	}
	h.initVault()
	// a bad first message, a wrong password, no password source
	if rc, _ := runExternal(h, `{"op":"get"}`); rc != 1 {
		t.Fatal("first message")
	}
	if rc, _ := runExternal(h, `{"op":"open","name":"Bad Name","title":"t","keys":{"K":"secret"}}`); rc != 1 {
		t.Fatal("name")
	}
	if rc, _ := runExternal(h, `{"op":"open","name":"x","title":"t","keys":{"K":"loud"}}`); rc != 1 {
		t.Fatal("visibility")
	}
	h.pw = []string{"wrong"}
	if rc, out := runExternal(h, extOpen); rc != 1 || len(out) != 0 || !strings.Contains(h.errb.String(), "wrong password") {
		t.Fatalf("%s", h.errb.String())
	}
	h.pw = nil
	if rc, _ := runExternal(h, extOpen); rc != 1 || !strings.Contains(h.errb.String(), NeedsOwner) {
		t.Fatalf("%s", h.errb.String())
	}
	_ = filepath.Join
	_ = os.Stat
	_ = bytes.NewReader
}

func TestExternalMakesCopiesAfterAChange(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	dest := filepath.Join(h.dir, "usb")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if rc := h.run("copies", "add", dest); rc != 0 {
		t.Fatal(h.errb.String())
	}
	rc, out := runExternal(h, extOpen, `{"op":"put","group":"monitoring","key":"MONITOR_KEY","value":"v1"}`, `{"op":"close"}`)
	if rc != 0 || len(out) != 3 {
		t.Fatalf("%d %v", rc, out)
	}
	a, _ := sha256File(h.env["ICEVAULT_VAULT"])
	b, _ := sha256File(filepath.Join(dest, "v.kdbx"))
	if a != b || !strings.Contains(h.errb.String(), "vault copy written to") {
		t.Fatalf("the copy is not current: %s", h.errb.String())
	}
	if strings.Contains(h.out.String(), "vault copy") {
		t.Fatal("copy lines must not go to the protocol channel")
	}
}
