package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cybericebox/icevault/internal/agentapi"
)

// agentEnv is an Env whose configuration folder is a short temporary one (a unix socket path is limited to about a hundred bytes).
func agentEnv(t *testing.T, in string) (*Env, *bytes.Buffer, *bytes.Buffer, string) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "ivcl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	var out, errb bytes.Buffer
	e := &Env{Getenv: func(k string) string {
		if k == agentapi.ConfigDirVar {
			return base
		}
		return ""
	}, Out: &out, Err: &errb, In: strings.NewReader(in)}
	return e, &out, &errb, agentapi.Dir(e.Getenv)
}

// fakeWindow answers like the window: pending for set-value, then allowed on the second status; it records the requests.
func fakeWindow(t *testing.T, dir string, state string) (*[]agentapi.Request, func()) {
	t.Helper()
	if err := agentapi.MakeDir(dir); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", agentapi.SocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(agentapi.SocketPath(dir), 0o600)
	var mu sync.Mutex
	var got []agentapi.Request
	polls := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadBytes('\n')
			var req agentapi.Request
			_ = json.Unmarshal(line, &req)
			mu.Lock()
			got = append(got, req)
			resp := agentapi.Response{OK: true, Data: map[string]any{"ok": true}}
			switch req.Op {
			case "batch-submit":
				resp = agentapi.Response{OK: true, State: agentapi.StatePending, ID: "abc"}
			case "batch-status":
				polls++
				resp = agentapi.Response{OK: true, State: agentapi.StatePending, ID: "abc"}
				if polls >= 2 {
					resp.State = state
				}
			case "nope":
				resp = agentapi.Response{Code: "unknown_op"}
			}
			mu.Unlock()
			b, _ := json.Marshal(resp)
			_, _ = c.Write(append(b, '\n'))
			_ = c.Close()
		}
	}()
	return &got, func() { _ = ln.Close() }
}

func TestAgentCommandWithNoWindow(t *testing.T) {
	e, out, _, _ := agentEnv(t, "")
	if rc := Run([]string{"agent", "structure"}, e); rc != 1 || strings.TrimSpace(out.String()) != `{"ok":false,"code":"no_window"}` {
		t.Fatalf("rc=%d %q", rc, out.String())
	}
}

func TestAgentCommandNeverTakesAValueOnTheCommandLine(t *testing.T) {
	e, out, errb, dir := agentEnv(t, "")
	got, stop := fakeWindow(t, dir, agentapi.StateAllowed)
	defer stop()
	if rc := Run([]string{"agent", "batch-submit", `{"scope":"shared","key":"K","value":"typed-secret-1"}`}, e); rc != 2 {
		t.Fatalf("rc=%d", rc)
	}
	if strings.Contains(out.String()+errb.String(), "typed-secret-1") || len(*got) != 0 {
		t.Fatal("the typed value was echoed or sent")
	}
}

func TestAgentCommandReadsTheValueFromAFileAndWaits(t *testing.T) {
	e, out, _, dir := agentEnv(t, "")
	got, stop := fakeWindow(t, dir, agentapi.StateAllowed)
	defer stop()
	f := filepath.Join(t.TempDir(), "v")
	if err := os.WriteFile(f, []byte("file-secret-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	arg, _ := json.Marshal(map[string]any{"scope": "shared", "key": "K", "value_file": f})
	if rc := Run([]string{"agent", "batch-submit", string(arg), "--as", "my agent"}, e); rc != 0 {
		t.Fatalf("rc=%d %s", rc, out.String())
	}
	if !strings.Contains(out.String(), `"state":"allowed"`) || strings.Contains(out.String(), "file-secret-1") {
		t.Fatalf("answer %q", out.String())
	}
	first := (*got)[0]
	if first.Args["value"] != "file-secret-1" || first.Args["value_file"] != nil || first.Client != "my agent" || first.PID == 0 {
		t.Fatalf("request %+v", first)
	}
}

func TestAgentCommandValueFromStdinAndDenied(t *testing.T) {
	e, out, _, dir := agentEnv(t, "stdin-secret-1\n")
	got, stop := fakeWindow(t, dir, agentapi.StateDenied)
	defer stop()
	if rc := Run([]string{"agent", "batch-submit", `{"other":"wifi","value_stdin":true}`}, e); rc != 3 {
		t.Fatalf("rc=%d %s", rc, out.String())
	}
	if (*got)[0].Args["value"] != "stdin-secret-1" || !strings.Contains(out.String(), "denied") {
		t.Fatalf("%+v %q", (*got)[0], out.String())
	}
}

func TestAgentCommandNoWaitAndRefusals(t *testing.T) {
	e, out, _, dir := agentEnv(t, "")
	_, stop := fakeWindow(t, dir, agentapi.StateAllowed)
	defer stop()
	f := filepath.Join(t.TempDir(), "v")
	_ = os.WriteFile(f, []byte("x"), 0o600)
	arg, _ := json.Marshal(map[string]any{"other": "wifi", "value_file": f})
	if rc := Run([]string{"agent", "batch-submit", string(arg), "--no-wait"}, e); rc != 0 || !strings.Contains(out.String(), `"state":"pending"`) {
		t.Fatalf("rc=%d %q", rc, out.String())
	}
	out.Reset()
	if rc := Run([]string{"agent", "nope"}, e); rc != 1 || !strings.Contains(out.String(), "unknown_op") {
		t.Fatalf("rc=%d %q", rc, out.String())
	}
	if rc := Run([]string{"agent"}, e); rc != 2 {
		t.Fatalf("rc=%d", rc)
	}
}

func TestAgentHelpIsTheOpOfTheWindow(t *testing.T) {
	e, out, _, dir := agentEnv(t, "")
	got, stop := fakeWindow(t, dir, agentapi.StateAllowed)
	defer stop()
	for _, args := range [][]string{{"agent", "help"}, {"agent", "help", "{}"}} {
		out.Reset()
		if rc := Run(args, e); rc != 0 || !strings.Contains(out.String(), `"ok":true`) {
			t.Fatalf("%v: rc=%d %q", args, rc, out.String())
		}
	}
	if len(*got) != 2 || (*got)[0].Op != "help" || (*got)[1].Op != "help" {
		t.Fatalf("the op was not sent: %+v", *got)
	}
	out.Reset()
	if rc := Run([]string{"help", "agent"}, e); rc != 0 || !strings.Contains(out.String(), "agent") || strings.Contains(out.String(), `"ok"`) {
		t.Fatalf("the usage of the command: rc=%d %q", rc, out.String())
	}
}

func TestAgentCommandRefusesAnOpenFolder(t *testing.T) {
	e, out, errb, dir := agentEnv(t, "")
	_, stop := fakeWindow(t, dir, agentapi.StateAllowed)
	defer stop()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if rc := Run([]string{"agent", "structure"}, e); rc == 0 || strings.Contains(out.String(), `"ok":true`) {
		t.Fatalf("rc=%d %q %q", rc, out.String(), errb.String())
	}
}
