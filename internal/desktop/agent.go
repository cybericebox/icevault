package desktop

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/cybericebox/icevault/internal/agentapi"
)

// The agent API: while the window is unlocked it serves a local unix socket (agentapi.SocketName in the user's configuration folder, mode 0600, the
// folder owned by the user and closed to the others). A program of the user (an agent) asks it, through "icevault agent", to read the structure of the
// vault (names, states, never a secret value) and to change it by the same write paths as the window (agent_ops.go). A secret value is set only after the
// person says Allow in the window; no op returns a secret value. Locked or closed: no socket, no access.

// EventAgentPending is the event the page gets when a request waits for the person (or stopped waiting); its data is {"count": n}.
const EventAgentPending = "agent-pending"

// EventAgentJournal is the event the page gets when the journal changed; its data is {}.
const EventAgentJournal = "agent-journal"

// Limits of the agent API.
const (
	AgentTTLDefault = 2 * time.Minute  // a request that waits for the person is dropped after this
	AgentGapDefault = 10 * time.Second // the least time between two new requests that wait, from the same client
	agentMaxPending = 4
	agentMaxConns   = 8
	agentRingSize   = 300
	agentLogLimit   = 512 << 10
	agentMaxValue   = 64 << 10
	agentReadWait   = 10 * time.Second
)

// AgentEntry is one line of the journal: what an agent did, by names. It never holds a value.
type AgentEntry struct {
	Time   string `json:"time"`
	Op     string `json:"op"`
	Target string `json:"target"`
	Who    string `json:"who"`
	Result string `json:"result"`
}

// agentReq is a request that waits for the person: what it changes, where, who asked, and the closure that does it after Allow. The value it carries lives
// only in the closure.
// agentChange is one line of what a relink changes: the field (a word the page translates) and the old and the new names.
type agentChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

type agentReq struct {
	changes                                         []agentChange
	id, op, kind, what, where, from, who, peer, key string
	asked                                           time.Time
	apply                                           func(c Core) error
	stop                                            func()
}

type agentDone struct {
	state, code string
}

type agentHub struct {
	a      *App
	dir    string
	ttl    time.Duration
	mu     sync.Mutex // guards the fields below
	ln     net.Listener
	err    string // why the socket is not served ("" when it is or when it is simply not up)
	conns  map[net.Conn]struct{}
	gap    time.Duration
	last   map[string]time.Time
	pend   map[string]*agentReq
	ord    []string
	done   map[string]agentDone
	dord   []string
	ring   []AgentEntry
	loaded bool
	logMu  sync.Mutex
}

func newAgentHub(a *App, dir string, ttl, gap time.Duration) *agentHub {
	if gap == 0 {
		gap = AgentGapDefault
	}
	if ttl <= 0 {
		ttl = AgentTTLDefault
	}
	return &agentHub{a: a, dir: dir, ttl: ttl, gap: gap, last: map[string]time.Time{}, pend: map[string]*agentReq{}, done: map[string]agentDone{}}
}

// clean makes a name safe for a log line and a dialog: no control characters, at most n runes.
func clean(s string, n int) string {
	var b strings.Builder
	i := 0
	for _, r := range s {
		if i >= n {
			b.WriteString("...")
			break
		}
		if unicode.IsControl(r) {
			r = ' '
		} else if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) { // invisible characters make look-alike names
			r = '?'
		}
		b.WriteRune(r)
		i++
	}
	return b.String()
}

func newAgentID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return time.Now().Format("150405.000000")
	}
	return hex.EncodeToString(b)
}

// ---- lifecycle: the socket exists exactly while the window is unlocked

func (h *agentHub) start() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ln != nil {
		return
	}
	h.err = ""
	if err := agentapi.MakeDir(h.dir); err != nil {
		h.err = "agent_dir"
		h.a.say("the agent API is off: its folder is not the user's own or is open to others")
		return
	}
	path := agentapi.SocketPath(h.dir)
	if _, err := os.Lstat(path); err == nil {
		if c, derr := net.DialTimeout("unix", path, 300*time.Millisecond); derr == nil { // another window serves it
			_ = c.Close()
			h.err = "agent_busy"
			h.a.say("the agent API is off: another IceVault window serves it")
			return
		}
		if agentapi.CheckSocketFile(path) != nil { // not ours: never removed
			h.err = "agent_dir"
			h.a.say("the agent API is off: the socket path holds something that is not this user's socket")
			return
		}
		_ = os.Remove(path) // left behind by a program that did not end cleanly
	}
	ln, err := agentapi.Listen(path)
	if err != nil {
		h.err = "agent_listen"
		h.a.say("the agent API is off: the socket could not be opened")
		return
	}
	if err := os.Chmod(path, 0o600); err != nil || agentapi.CheckSocketFile(path) != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		h.err = "agent_listen"
		return
	}
	h.ln = ln
	h.conns = map[net.Conn]struct{}{}
	if !h.loaded {
		h.loaded = true
		h.ring = h.readTail()
	}
	go h.accept(ln)
	h.a.say("the agent API is on")
}

// stop closes the socket and drops what waits for the person (nothing can be allowed after a lock).
func (h *agentHub) stop() {
	h.mu.Lock()
	ln := h.ln
	h.ln = nil
	conns := h.conns
	h.conns = nil
	pend := h.pend
	h.pend, h.ord, h.done, h.dord = map[string]*agentReq{}, nil, map[string]agentDone{}, nil
	h.mu.Unlock()
	for c := range conns { // what a client is in the middle of gets no answer: the vault is locked
		_ = c.Close()
	}
	if ln != nil {
		_ = ln.Close()
		_ = os.Remove(agentapi.SocketPath(h.dir))
		h.a.say("the agent API is off")
	}
	for _, p := range pend {
		if p.stop != nil {
			p.stop()
		}
		p.apply = nil
		h.log(p.op, p.what+" in "+p.where, p.who, "dropped: locked")
	}
	if len(pend) > 0 {
		h.notifyPending()
	}
}

func (h *agentHub) accept(ln net.Listener) {
	sem := make(chan struct{}, agentMaxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				h.serve(conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (h *agentHub) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(agentReadWait)) // before anything that can take a while (the program name of the peer is asked of ps)
	peer, err := agentapi.PeerOf(conn)                  // who is there, as the system says: another user is not answered
	if err != nil || !peer.SameUser() {
		return
	}
	h.mu.Lock()
	if h.conns == nil {
		h.mu.Unlock()
		return
	}
	h.conns[conn] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.conns, conn)
		h.mu.Unlock()
	}()
	line, err := bufio.NewReader(io.LimitReader(conn, agentapi.MaxRequest)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req agentapi.Request
	var resp agentapi.Response
	if json.Unmarshal(line, &req) != nil || req.Op == "" {
		resp = agentapi.Response{Code: "bad_request"}
	} else {
		resp = h.handle(req, peer)
	}
	out, _ := json.Marshal(resp)
	_, _ = conn.Write(append(out, '\n'))
}

// ---- the journal: names and results only

func (h *agentHub) log(op, target, who, result string) {
	e := AgentEntry{Time: time.Now().UTC().Format(time.RFC3339), Op: clean(op, 40), Target: clean(target, 200), Who: clean(who, 80), Result: clean(result, 80)}
	h.mu.Lock()
	h.ring = append(h.ring, e)
	if len(h.ring) > agentRingSize {
		h.ring = append([]AgentEntry(nil), h.ring[len(h.ring)-agentRingSize:]...)
	}
	h.mu.Unlock()
	h.appendFile(e)
	if h.a.o.Notify != nil {
		h.a.o.Notify(EventAgentJournal, map[string]any{})
	}
}

func (h *agentHub) appendFile(e AgentEntry) {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	path := h.dir + string(os.PathSeparator) + agentapi.JournalName
	if st, err := os.Stat(path); err == nil && st.Size() > agentLogLimit {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	b, _ := json.Marshal(e)
	_, _ = f.Write(append(b, '\n'))
}

// readTail loads the last entries of the log file, so the panel shows what happened in earlier runs too.
func (h *agentHub) readTail() []AgentEntry {
	data, err := os.ReadFile(h.dir + string(os.PathSeparator) + agentapi.JournalName)
	if err != nil {
		return nil
	}
	var out []AgentEntry
	for _, l := range strings.Split(string(data), "\n") {
		var e AgentEntry
		if l != "" && json.Unmarshal([]byte(l), &e) == nil && e.Op != "" {
			// the file is the user's own, but not trusted for the panel: every field is cleaned and capped as when it was written
			out = append(out, AgentEntry{Time: clean(e.Time, 40), Op: clean(e.Op, 40), Target: clean(e.Target, 200), Who: clean(e.Who, 80), Result: clean(e.Result, 80)})
		}
	}
	if len(out) > agentRingSize {
		out = out[len(out)-agentRingSize:]
	}
	return out
}

// ---- requests that wait for the person

var (
	errAgentTooMany = errors.New("too many requests are waiting")
	errAgentRate    = errors.New("requests wait too often")
)

// enqueue puts a request in the queue and tells the page. It answers the id.
func (h *agentHub) enqueue(p *agentReq) (string, error) {
	h.mu.Lock()
	if len(h.pend) >= agentMaxPending {
		h.mu.Unlock()
		return "", errAgentTooMany
	}
	now := time.Now()
	if h.gap > 0 { // a client that asks again at once is not asked about: the person is not worn down with prompts
		if t, found := h.last[p.key]; found && now.Sub(t) < h.gap {
			h.mu.Unlock()
			return "", errAgentRate
		}
		h.last[p.key] = now
	}
	p.id, p.asked = newAgentID(), now
	h.pend[p.id] = p
	h.ord = append(h.ord, p.id)
	h.mu.Unlock()
	id := p.id
	p.stop = h.a.o.AfterFunc(h.ttl, func() { h.expire(id) })
	h.notifyPending()
	return id, nil
}

func (h *agentHub) take(id string) *agentReq {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.pend[id]
	if p == nil {
		return nil
	}
	delete(h.pend, id)
	for i, x := range h.ord {
		if x == id {
			h.ord = append(h.ord[:i:i], h.ord[i+1:]...)
			break
		}
	}
	return p
}

func (h *agentHub) finish(id, state, code string) {
	h.mu.Lock()
	h.done[id] = agentDone{state, code}
	h.dord = append(h.dord, id)
	if len(h.dord) > 100 {
		delete(h.done, h.dord[0])
		h.dord = h.dord[1:]
	}
	h.mu.Unlock()
}

func (h *agentHub) expire(id string) {
	p := h.take(id)
	if p == nil {
		return
	}
	p.apply = nil
	h.finish(id, agentapi.StateExpired, "")
	h.log(p.op, p.what+" in "+p.where, p.who, agentapi.StateExpired)
	h.notifyPending()
}

func (h *agentHub) pendingCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.pend)
}

func (h *agentHub) notifyPending() {
	if h.a.o.Notify != nil {
		h.a.o.Notify(EventAgentPending, map[string]any{"count": h.pendingCount()})
	}
}

// ---- what the window's page calls

// AgentPending lists the requests that wait for the person: what, where, who asked, and when it is dropped. Never a value.
func (a *App) AgentPending() Response {
	if _, e := a.store(); e != nil {
		return answer(e)
	}
	list := []map[string]any{}
	if h := a.agent; h != nil {
		h.mu.Lock()
		for _, id := range h.ord {
			p := h.pend[id]
			list = append(list, map[string]any{"id": p.id, "op": p.op, keyKind: p.kind, "what": p.what, "where": p.where, "from": p.from, "who": p.who, "peer": p.peer, "changes": p.changes,
				"asked": p.asked.UTC().Format(time.RFC3339), "expires": p.asked.Add(h.ttl).UTC().Format(time.RFC3339)})
		}
		h.mu.Unlock()
	}
	return ok(map[string]any{"list": list})
}

// AgentDecide is the person's answer to a request: allow runs it (the same write path as the window's own), anything else drops it.
func (a *App) AgentDecide(id string, allow bool) Response {
	c, e := a.store()
	if e != nil {
		return answer(e)
	}
	h := a.agent
	if h == nil {
		return fail(404, "agent_gone")
	}
	p := h.take(id)
	if p == nil {
		return fail(404, "agent_gone")
	}
	if p.stop != nil {
		p.stop()
	}
	target := p.what + " in " + p.where
	if !allow {
		p.apply = nil
		h.finish(id, agentapi.StateDenied, "")
		h.log(p.op, target, p.who, agentapi.StateDenied)
		h.notifyPending()
		return ok(map[string]any{"ok": true})
	}
	a.ops.Lock()
	if c2, e2 := a.store(); e2 != nil || c2 != c { // locked while the person was deciding
		a.ops.Unlock()
		p.apply = nil
		h.finish(id, agentapi.StateFailed, "locked")
		return fail(404, "agent_gone")
	}
	a.mu.Lock()
	mode := a.mode
	a.mu.Unlock()
	if mode != modeEdit { // as for the agent's own writes: nothing is written in view mode, whatever the person answered earlier
		a.ops.Unlock()
		p.apply = nil
		h.finish(id, agentapi.StateFailed, "view_mode")
		h.log(p.op, target, p.who, agentapi.StateFailed+": view_mode")
		h.notifyPending()
		return fail(403, "view_mode")
	}
	_, _ = a.syncDisk(false, true)
	err := p.apply(c)
	a.ops.Unlock()
	p.apply = nil
	h.notifyPending()
	if err != nil {
		code, _ := agentCode(err)
		h.finish(id, agentapi.StateFailed, code)
		h.log(p.op, target, p.who, agentapi.StateFailed+": "+code)
		return answer(err)
	}
	h.finish(id, agentapi.StateAllowed, "")
	h.log(p.op, target, p.who, agentapi.StateAllowed)
	return ok(map[string]any{"ok": true})
}

// AgentJournal answers the journal (newest first) and whether the socket is served.
func (a *App) AgentJournal() Response {
	if _, e := a.store(); e != nil {
		return answer(e)
	}
	out := map[string]any{"available": a.agent != nil, "active": false, "entries": []AgentEntry{}, "pending": 0}
	if h := a.agent; h != nil {
		h.mu.Lock()
		list := make([]AgentEntry, 0, len(h.ring))
		for i := len(h.ring) - 1; i >= 0; i-- {
			list = append(list, h.ring[i])
		}
		out["active"], out["entries"], out["pending"] = h.ln != nil, list, len(h.pend)
		if h.err != "" {
			out["code"] = h.err
		}
		h.mu.Unlock()
	}
	return ok(out)
}

func (a *App) agentStart() {
	if a.agent != nil {
		a.agent.start()
	}
}

func (a *App) agentStop() {
	if a.agent != nil {
		a.agent.stop()
	}
}

// agentCode is the code and the parameters of an error of the core.
func agentCode(err error) (string, map[string]any) {
	var e *Error
	if errors.As(err, &e) && e.Code != "" {
		return e.Code, e.Params
	}
	_, code, params := Classify(err)
	return code, params
}
