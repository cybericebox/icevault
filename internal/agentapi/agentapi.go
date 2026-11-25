// Package agentapi is the wire of the agent API: the local socket the unlocked window serves, and the client the command line uses. It knows nothing of the
// vault: a request is an op name with JSON arguments, an answer is JSON. The window (internal/desktop) holds the vault and decides; this package only moves
// the lines and checks that the socket folder is the user's own.
//
// A secret value travels in a request (the "value" argument of an op the window confirms), never in an answer, and is never logged here.
package agentapi

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Names of the files in the folder of the application in the user's configuration folder.
const (
	// AppDirName is the folder of the application in the configuration base: the bundle identifier of IceVault.app.
	AppDirName = "com.cybericebox.icevault"
	// ConfigDirVar replaces the user's configuration base folder (tests), as in the rest of the program.
	ConfigDirVar = "ICEVAULT_CONFIG_DIR"
	// SocketName is the unix socket the unlocked window listens on.
	SocketName = "agent.sock"
	// JournalName is the log of the actions of agents (names and results only, never a value).
	JournalName = "agent-journal.log"
	// MaxRequest is the largest request line the window reads.
	MaxRequest = 1 << 20
)

// States of a request that waits for the person at the window.
const (
	StatePending = "pending"
	StateAllowed = "allowed"
	StateDenied  = "denied"
	StateExpired = "expired"
	StateFailed  = "failed"
)

// Request is one line the client sends.
type Request struct {
	Op   string         `json:"op"`
	Args map[string]any `json:"args,omitempty"`
	// Client names the program that asks, as it says itself (shown to the person at the confirmation; not verified).
	Client string `json:"client,omitempty"`
	PID    int    `json:"pid,omitempty"`
}

// Response is the one line the window answers. OK false carries a Code (and Params) of a refusal; a request that waits for the person answers State
// "pending" with an ID, and the op "status" {id} says how it ended.
type Response struct {
	OK     bool           `json:"ok"`
	State  string         `json:"state,omitempty"`
	ID     string         `json:"id,omitempty"`
	Code   string         `json:"code,omitempty"`
	Params map[string]any `json:"params,omitempty"`
	Data   any            `json:"data,omitempty"`
}

// Dir is the folder of the socket and the journal: the configuration base (ICEVAULT_CONFIG_DIR, else the user's configuration folder) and the
// application folder in it; "" when the user's configuration folder is unknown.
func Dir(getenv func(string) string) string {
	base := getenv(ConfigDirVar)
	if base == "" {
		b, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		base = b
	}
	return filepath.Join(base, AppDirName)
}

// SocketPath is the socket in dir.
func SocketPath(dir string) string { return filepath.Join(dir, SocketName) }

// ErrNoWindow is what Call returns when no unlocked window listens: the window is locked or closed.
var ErrNoWindow = errors.New("no unlocked IceVault window listens")

// Call sends one request to the window that listens in dir and returns its answer. The folder must be the user's own and closed to the others.
func Call(dir string, req Request, timeout time.Duration) (Response, error) {
	var resp Response
	if err := CheckDir(dir); err != nil {
		if os.IsNotExist(err) {
			return resp, ErrNoWindow
		}
		return resp, err
	}
	if err := checkSocketFile(SocketPath(dir)); err != nil {
		if os.IsNotExist(err) {
			return resp, ErrNoWindow
		}
		return resp, err
	}
	conn, err := net.DialTimeout("unix", SocketPath(dir), timeout)
	if err != nil {
		return resp, ErrNoWindow
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	line, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return resp, err
	}
	data, err := bufio.NewReader(io.LimitReader(conn, MaxRequest)).ReadBytes('\n')
	if err != nil && len(data) == 0 {
		return resp, errors.New("the window did not answer")
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return resp, errors.New("the window answered something that is not JSON")
	}
	return resp, nil
}
