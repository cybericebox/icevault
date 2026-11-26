package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cybericebox/icevault/internal/agentapi"
)

// "icevault agent OP [JSON]" is the client of the agent API of the window (internal/desktop/agent.go). It talks to the socket of the unlocked window and
// prints the answer as JSON. It never asks for a password, never opens a vault and never unlocks anything: with the window locked or closed there is no
// socket and the answer is {"ok":false,"code":"no_window"}.
//
// A batch of changes is made with batch-begin, write ops that take "batch":ID, and batch-submit, which waits for the window. A value is never an argument of the command: "value_file" (a path) or "value_stdin" (true) in the JSON says where the value is read from, and it goes
// to the window in the request only. No answer carries a secret value.

const (
	agentWaitDefault = 600 // seconds; the window drops a batch that waits longer than its own limit (ten minutes)
	agentPoll        = 600 * time.Millisecond
	agentCall        = 15 * time.Second
	agentValueMax    = 64 << 10
	agentNameVar     = "ICEVAULT_AGENT_NAME"
)

// Exit codes of "agent": 0 done (or allowed), 1 refused or no window, 2 wrong command line, 3 the person denied, the request expired or failed, or the wait ran out.
const exitAgentNotDone = 3

func cmdAgent(args []string, e *Env) error {
	var noWait bool
	var wait int
	var as string
	pos, err := parse("agent", args, e, 2, func(fs *flag.FlagSet) {
		fs.BoolVar(&noWait, "no-wait", false, "answer pending at once")
		fs.IntVar(&wait, "timeout", agentWaitDefault, "seconds to wait for the person")
		fs.StringVar(&as, "as", "", "the name shown at the confirmation")
	})
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return &parseErr{msg: "agent needs an op"}
	}
	call := map[string]any{}
	stdinJSON := len(pos) == 2 && pos[1] == "-"
	if len(pos) == 2 {
		raw := []byte(pos[1])
		if pos[1] == "-" {
			if raw, err = readLimited(e.In, agentapi.MaxRequest); err != nil {
				return fail("the arguments could not be read from the standard input")
			}
		}
		if err := json.Unmarshal(raw, &call); err != nil {
			return &parseErr{msg: "the arguments are not a JSON object"}
		}
	}
	if err := agentValue(call, stdinJSON, e); err != nil {
		return err
	}
	if as == "" {
		as = e.Getenv(agentNameVar)
	}
	if as == "" {
		as = "icevault agent"
	}
	dir := agentapi.Dir(e.Getenv)
	if dir == "" {
		return fail("the configuration folder of this user is unknown")
	}
	resp, err := agentapi.Call(dir, agentapi.Request{Op: pos[0], Args: call, Client: as, PID: os.Getppid()}, agentCall)
	if err != nil {
		if errors.Is(err, agentapi.ErrNoWindow) {
			printAgentJSON(e.Out, agentapi.Response{Code: "no_window"})
			return exitCode(1)
		}
		return fail("%v", err)
	}
	if resp.OK && resp.State == agentapi.StatePending && !noWait {
		tok, _ := call["token"].(string)
		resp = agentWait(dir, resp.ID, tok, as, time.Duration(wait)*time.Second)
	}
	printAgentJSON(e.Out, resp)
	switch {
	case !resp.OK:
		return exitCode(1)
	case resp.State == agentapi.StateDenied || resp.State == agentapi.StateRejected || resp.State == agentapi.StateExpired || resp.State == agentapi.StateFailed:
		return exitCode(exitAgentNotDone)
	case resp.State == agentapi.StatePending && !noWait:
		return exitCode(exitAgentNotDone)
	}
	return nil
}

// agentWait asks for the state of a pending request until the person has answered or the time is over.
func agentWait(dir, id, token, as string, limit time.Duration) agentapi.Response {
	end := time.Now().Add(limit)
	resp := agentapi.Response{OK: true, State: agentapi.StatePending, ID: id}
	for time.Now().Before(end) {
		time.Sleep(agentPoll)
		r, err := agentapi.Call(dir, agentapi.Request{Op: "batch-status", Args: map[string]any{"id": id, "token": token}, Client: as}, agentCall)
		if err != nil { // the window was locked or closed meanwhile: nothing can be allowed any more
			return agentapi.Response{OK: true, State: agentapi.StateDenied, ID: id, Code: "no_window"}
		}
		if !r.OK || r.State != agentapi.StatePending {
			return r
		}
		resp = r
	}
	return resp
}

// agentValue turns "value_file" and "value_stdin" into the "value" of the request. A "value" typed in the arguments is refused: it would be in the process list.
func agentValue(call map[string]any, stdinTaken bool, e *Env) error {
	if _, has := call["value"]; has {
		return &parseErr{msg: "a value is never given on the command line: use value_file (a path) or value_stdin (true)"}
	}
	file, _ := call["value_file"].(string)
	stdin, _ := call["value_stdin"].(bool)
	delete(call, "value_file")
	delete(call, "value_stdin")
	switch {
	case file != "" && stdin:
		return &parseErr{msg: "give value_file or value_stdin, not both"}
	case stdin && stdinTaken:
		return &parseErr{msg: "the standard input holds the arguments: it cannot hold the value too"}
	case file == "" && !stdin:
		return nil
	}
	r := e.In
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return fail("the value file cannot be opened")
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	data, err := readLimited(r, agentValueMax)
	if err != nil {
		return fail("the value could not be read (it is longer than %d bytes, or unreadable)", agentValueMax)
	}
	call["value"] = strings.TrimRight(string(data), "\r\n")
	return nil
}

func readLimited(r io.Reader, max int) ([]byte, error) {
	if r == nil {
		return nil, errors.New("no input")
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil || len(data) > max {
		return nil, errors.New("too long")
	}
	return data, nil
}

func printAgentJSON(w io.Writer, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintln(w, string(b))
}
