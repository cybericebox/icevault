package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cybericebox/icevault/internal/agentapi"
)

// Batches. A write op of the agent API is never run on the vault. The agent opens a batch ("batch-begin"), adds items (every write op takes "batch":ID: it is
// validated at once, on a copy of the vault where the items before it have been done, and recorded), and submits it ("batch-submit"). The window shows
// the whole batch in one dialog. Apply runs the items again, in order, on a fresh copy of the vault (every target is found again, every rule is checked
// again) and, only when every item passed, makes the copy the content of the vault in one save. Reject, a failing item, the expiry and the lock leave the
// vault as it is.

var (
	errAgentRate = errors.New("batches are submitted too often")
)

// drop releases the copy of the vault of a batch and what it holds.
func (b *agentBatch) drop() {
	if b.stop != nil {
		b.stop()
	}
	if b.release != nil {
		b.release()
	}
	b.scratch, b.release, b.stop = nil, nil, nil
	for _, it := range b.items {
		it.args = nil // the values go
	}
}

// reasonOf is the short reason an item needs a close look, by its op: a word the window translates.
func reasonOf(op, kind string) string {
	switch {
	case op == "set-value" || op == "copy-value" || op == "move-value":
		return "secret_write"
	case strings.HasSuffix(op, "-delete"):
		return "delete_" + kind
	case op == "env-create":
		return "env_copy"
	case op == "var-create":
		return "shadows"
	case op == "var-rename" || op == "other-update":
		return "rename_secret"
	case op == "site-update" || op == "product-update":
		return "relink"
	case op == "connection-create" || op == "connection-update":
		return "bound_name"
	case op == opSiteCreate:
		return "links_products"
	}
	return "sensitive"
}

// ---- the hub's batch bookkeeping

func (h *agentHub) begin(b *agentBatch) error {
	h.mu.Lock()
	if len(h.drafts) >= agentMaxDrafts {
		h.mu.Unlock()
		return errAgentTooMany
	}
	b.id, b.created = newAgentID(), time.Now()
	h.drafts[b.id] = b
	h.mu.Unlock()
	id := b.id
	b.stop = h.a.o.AfterFunc(h.ttl, func() { h.expire(id) })
	return nil
}

func (h *agentHub) draft(id string) *agentBatch {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.drafts[id]
}

func (h *agentHub) dropDraft(id string) *agentBatch {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.drafts[id]
	delete(h.drafts, id)
	return b
}

var errAgentTooMany = errors.New("too many batches are open or waiting")

// submit moves a batch from the drafts to the one place that waits for the person.
func (h *agentHub) submit(b *agentBatch) error {
	if b.stop != nil { // the timer of the draft is cancelled before the batch is taken: it must not fire on the batch that waits
		b.stop()
		b.stop = nil
	}
	rearm := func() {
		id := b.id
		if left := h.ttl - time.Since(b.created); left > 0 {
			b.stop = h.a.o.AfterFunc(left, func() { h.expire(id) })
		} else {
			go h.expire(id)
		}
	}
	h.mu.Lock()
	if len(h.pend) >= agentMaxPending {
		h.mu.Unlock()
		rearm()
		return errAgentTooMany
	}
	now := time.Now()
	if h.gap > 0 { // a client that submits again at once is not asked about: the person is not worn down with prompts
		if t, found := h.last[b.key]; found && now.Sub(t) < h.gap {
			h.mu.Unlock()
			rearm()
			return errAgentRate
		}
		h.last[b.key] = now
	}
	delete(h.drafts, b.id)
	b.asked = now
	h.pend[b.id] = b
	h.ord = append(h.ord, b.id)
	h.mu.Unlock()
	id := b.id // the time to answer starts now
	b.stop = h.a.o.AfterFunc(h.ttl, func() { h.expire(id) })
	if b.release != nil { // the copy of the draft is not needed: apply makes a new one
		b.release()
		b.scratch, b.release = nil, nil
	}
	h.notifyPending()
	return nil
}

func (h *agentHub) takePending(id string) *agentBatch {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.pend[id]
	if b == nil {
		return nil
	}
	delete(h.pend, id)
	for i, x := range h.ord {
		if x == id {
			h.ord = append(h.ord[:i:i], h.ord[i+1:]...)
			break
		}
	}
	return b
}

func (h *agentHub) finish(id, title, state, code string, results []agentResult) {
	h.mu.Lock()
	h.done[id] = agentDone{state: state, code: code, title: title, results: results}
	h.dord = append(h.dord, id)
	if len(h.dord) > 100 {
		delete(h.done, h.dord[0])
		h.dord = h.dord[1:]
	}
	h.mu.Unlock()
}

func (h *agentHub) expire(id string) {
	h.a.ops.Lock() // not while an item is being run on the copy of the batch
	defer h.a.ops.Unlock()
	if b := h.dropDraft(id); b != nil {
		b.drop()
		h.finish(id, b.title, agentapi.StateExpired, "", nil)
		h.log("batch", b.title, b.who, agentapi.StateExpired)
		return
	}
	b := h.takePending(id)
	if b == nil {
		return
	}
	b.drop()
	h.finish(id, b.title, agentapi.StateExpired, "", nil)
	h.log("batch", b.title, b.who, agentapi.StateExpired)
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

// ---- the ops of an agent

// writeOps are the ops that change the vault: only ever inside a batch.
func isAgentWrite(op string) bool {
	for _, w := range agentOps {
		if w == op {
			switch op {
			case "help", "structure", "batch-begin", "batch-submit", "batch-status", "batch-discard":
				return false
			}
			return true
		}
	}
	return false
}

// handle runs one request of a client. peer is the process on the other end of the socket, as the system says.
func (h *agentHub) handle(req agentapi.Request, peer agentapi.Peer) agentapi.Response {
	a := h.a
	who := clean(req.Client, 40)
	if who == "" {
		who = "agent"
	}
	who += " (pid " + strconv.Itoa(peer.PID) + ")"
	known := false
	for _, op := range agentOps {
		known = known || op == req.Op
	}
	if !known {
		h.log(req.Op, "", who, "refused: unknown_op")
		return agentRefused("unknown_op", nil)
	}
	a.ops.Lock()
	defer a.ops.Unlock()
	c, e := a.store() // after the lock of the operations: a lock of the vault in between is seen here
	if e != nil {
		return agentRefused("locked", nil)
	}
	args := req.Args
	if args == nil {
		args = map[string]any{}
	}
	x := &agentCtx{h: h, c: c, args: args, who: who, peer: peer.Describe(), pkey: strconv.Itoa(peer.UID), owner: ownerOf(peer), by: byOf(who, peer)} // one bucket for the user: new processes do not get round the limit
	var resp agentapi.Response
	switch req.Op {
	case "help":
		resp = okData(map[string]any{"ops": agentOps})
	case "batch-status":
		resp = h.batchStatus(as(args, "id"))
	case "structure":
		_, _ = a.syncDisk(false, true)
		resp = x.run("structure")
	case "batch-begin":
		resp = h.batchBegin(x)
	case "batch-submit":
		resp = h.batchSubmit(x)
	case "batch-discard":
		resp = h.batchDiscard(x)
	default:
		resp = h.batchItem(x, req.Op)
	}
	if req.Op != "batch-status" { // a client polls the status: that is not an action
		result := "ok"
		switch {
		case resp.State == agentapi.StatePending:
			result = agentapi.StatePending
		case !resp.OK:
			result = "refused: " + resp.Code
		}
		h.log(req.Op, targetOf(args), who, result)
	}
	return resp
}

// ownerOf names the program that began a batch: the user and the process that started the client (the client itself is a new process at every call).
func ownerOf(p agentapi.Peer) string {
	pid := p.PPID
	if pid <= 0 {
		pid = p.PID
	}
	return strconv.Itoa(p.UID) + ":" + strconv.Itoa(pid)
}

func byOf(who string, p agentapi.Peer) string {
	s := who
	if p.Parent != "" {
		s += " via " + p.Parent + " (pid " + strconv.Itoa(p.PPID) + ")"
	}
	return clean(s, 200)
}

// draftOf is the open batch of that id when this client began it; for any other client there is none.
func (h *agentHub) draftOf(id, owner string) *agentBatch {
	b := h.draft(id)
	if b == nil || b.owner != owner {
		return nil
	}
	return b
}

func (x *agentCtx) editing() bool {
	x.h.a.mu.Lock()
	defer x.h.a.mu.Unlock()
	return x.h.a.mode == modeEdit
}

func (h *agentHub) batchBegin(x *agentCtx) agentapi.Response {
	if !x.editing() {
		return agentRefused("view_mode", nil)
	}
	runner, can := x.c.(BatchRunner)
	if !can {
		return agentRefused("no_batch", nil)
	}
	h.mu.Lock() // batches are not begun too often either: every one is a copy of the vault
	if t, found := h.begun[x.pkey]; h.gap > 0 && found && time.Since(t) < h.gap/10 {
		h.mu.Unlock()
		return agentRefused("rate_limited", nil)
	}
	h.begun[x.pkey] = time.Now()
	h.mu.Unlock()
	_, _ = h.a.syncDisk(false, true)
	sc, release, err := runner.BatchScratch()
	if err != nil {
		return refusedErr(err)
	}
	title := clean(as(x.args, keyTitle), 80)
	if title == "" {
		title = "batch"
	}
	b := &agentBatch{title: title, who: x.who, peer: clean(x.peer, 200), key: x.pkey, owner: x.owner, scratch: sc, release: release}
	if err := h.begin(b); err != nil {
		release()
		return agentRefused("too_many_batches", nil)
	}
	return okData(map[string]any{"id": b.id})
}

func (h *agentHub) batchDiscard(x *agentCtx) agentapi.Response {
	if h.draftOf(as(x.args, "id"), x.owner) == nil {
		return agentRefused("not_found", nil)
	}
	b := h.dropDraft(as(x.args, "id"))
	if b == nil {
		return agentRefused("not_found", nil)
	}
	b.drop()
	h.finish(b.id, b.title, agentapi.StateRejected, "discarded", nil)
	return okData(map[string]any{"ok": true})
}

// batchItem validates one write op on the copy of the batch (where the items before it were done) and records it.
func (h *agentHub) batchItem(x *agentCtx, op string) agentapi.Response {
	if !isAgentWrite(op) {
		return agentRefused("unknown_op", nil)
	}
	id := as(x.args, "batch")
	if id == "" {
		return agentRefused("batch_required", nil)
	}
	b := h.draftOf(id, x.owner)
	if b == nil {
		return agentRefused("not_found", nil)
	}
	if !x.editing() {
		return agentRefused("view_mode", nil)
	}
	if len(b.items) >= agentMaxItems {
		return agentRefused("batch_full", nil)
	}
	args := copyMap(x.args)
	delete(args, "batch")
	ex := &agentCtx{h: h, c: b.scratch, args: args, who: x.who, peer: x.peer, pkey: x.pkey, by: x.by, rec: &agentItem{op: op}}
	resp := ex.run(op)
	if !resp.OK {
		return resp
	}
	it := ex.describe()
	it.args, it.by = args, x.by
	b.items = append(b.items, it)
	return okData(map[string]any{"item": len(b.items), "sensitive": it.sens})
}

func (h *agentHub) batchSubmit(x *agentCtx) agentapi.Response {
	if !x.editing() {
		return agentRefused("view_mode", nil)
	}
	b := h.draftOf(as(x.args, "id"), x.owner)
	if b == nil {
		return agentRefused("not_found", nil)
	}
	if len(b.items) == 0 {
		return agentRefused("empty_batch", nil)
	}
	if err := h.submit(b); err != nil {
		if errors.Is(err, errAgentRate) {
			return agentRefused("rate_limited", nil)
		}
		return agentRefused("batch_pending", nil)
	}
	return agentapi.Response{OK: true, State: agentapi.StatePending, ID: b.id}
}

func (h *agentHub) batchStatus(id string) agentapi.Response {
	h.mu.Lock()
	defer h.mu.Unlock()
	if b := h.drafts[id]; b != nil {
		return agentapi.Response{OK: true, State: agentapi.StateOpen, ID: id, Data: map[string]any{keyTitle: b.title, "items": len(b.items)}}
	}
	if b := h.pend[id]; b != nil {
		return agentapi.Response{OK: true, State: agentapi.StatePending, ID: id, Data: map[string]any{keyTitle: b.title, "items": len(b.items)}}
	}
	if d, found := h.done[id]; found {
		return agentapi.Response{OK: true, State: d.state, ID: id, Code: d.code, Data: map[string]any{keyTitle: d.title, "results": d.results}}
	}
	return agentRefused("not_found", nil)
}

// ---- what the window's page calls

// AgentPending lists the batch that waits for the person: its title, who sent it, and every item by names. Never a value.
func (a *App) AgentPending() Response {
	if _, e := a.store(); e != nil {
		return answer(e)
	}
	list := []map[string]any{}
	if h := a.agent; h != nil {
		h.mu.Lock()
		for _, id := range h.ord {
			b := h.pend[id]
			items := []map[string]any{}
			nonlatin := false
			clash := prefixClashes(b.items)
			seen, contributors := map[string]bool{}, []string{}
			for i, it := range b.items {
				items = append(items, map[string]any{"op": it.op, "target": it.target, "what": it.what, "where": it.where, "from": it.from, "changes": it.changes, "sens": it.sens, "details": it.details, "nonlatin": it.nonlatin, "prefix": clash[i]})
				nonlatin = nonlatin || it.nonlatin
				if !seen[it.by] {
					seen[it.by] = true
					contributors = append(contributors, it.by)
				}
			}
			list = append(list, map[string]any{"id": b.id, keyTitle: b.title, "who": b.who, "peer": b.peer, "items": items, "contributors": contributors, "nonlatin": nonlatin || hasNonLatin(b.title+b.who),
				"asked": b.asked.UTC().Format(time.RFC3339), "expires": b.asked.Add(h.ttl).UTC().Format(time.RFC3339)})
		}
		h.mu.Unlock()
	}
	return ok(map[string]any{"list": list})
}

// replay runs the items on a core, in order, as the first run did: every target is found again and every rule is checked again. It answers what became of
// each item and the first failure (-1: none).
func (h *agentHub) replay(c Core, items []*agentItem, abort func() bool) (results []agentResult, failed int, code string) {
	failed = -1
	for i, it := range items {
		if failed < 0 && abort != nil && abort() { // the vault was locked: nothing more is done
			failed, code = i, "locked"
			results = append(results, agentResult{Index: i + 1, Op: it.op, Target: it.target, Result: "failed: locked"})
			continue
		}
		if failed >= 0 {
			results = append(results, agentResult{Index: i + 1, Op: it.op, Target: it.target, Result: "skipped"})
			continue
		}
		x := &agentCtx{h: h, c: c, args: copyMap(it.args), rec: &agentItem{op: it.op}}
		resp := x.run(it.op)
		if resp.OK && x.describe().sig() != it.sig() { // the rules or the names see the item differently than when the person was shown it
			resp = agentRefused("gone", nil)
		}
		if !resp.OK {
			failed, code = i, resp.Code
			results = append(results, agentResult{Index: i + 1, Op: it.op, Target: it.target, Result: "failed: " + resp.Code})
			continue
		}
		results = append(results, agentResult{Index: i + 1, Op: it.op, Target: it.target, Result: "ok"})
	}
	return results, failed, code
}

// AgentDecide is the person's answer to the batch: apply runs it, anything else rejects it. The vault changes only when every item passed.
func (a *App) AgentDecide(id string, allow bool) Response {
	c, e := a.store()
	if e != nil {
		return answer(e)
	}
	h := a.agent
	if h == nil {
		return fail(404, "agent_gone")
	}
	b := h.takePending(id)
	if b == nil {
		return fail(404, "agent_gone")
	}
	if b.stop != nil {
		b.stop()
		b.stop = nil
	}
	title := b.title
	h.notifyPending()
	if !allow {
		b.drop()
		h.finish(id, title, agentapi.StateRejected, "", nil)
		h.log("batch", title, b.who, agentapi.StateRejected)
		return ok(map[string]any{"ok": true})
	}
	defer b.drop()
	a.ops.Lock()
	defer a.ops.Unlock()
	if c2, e2 := a.store(); e2 != nil || c2 != c { // locked while the person was deciding
		h.finish(id, title, agentapi.StateFailed, "locked", nil)
		return fail(404, "agent_gone")
	}
	a.mu.Lock()
	mode := a.mode
	a.mu.Unlock()
	if mode != modeEdit { // nothing is written in view mode, whatever the person answered
		h.finish(id, title, agentapi.StateFailed, "view_mode", nil)
		h.log("batch", title, b.who, agentapi.StateFailed+": view_mode")
		return fail(403, "view_mode")
	}
	runner, can := c.(BatchRunner)
	if !can {
		h.finish(id, title, agentapi.StateFailed, "no_batch", nil)
		return fail(409, "no_batch")
	}
	_, _ = a.syncDisk(false, true)
	sc, release, err := runner.BatchScratch() // a fresh copy of what the vault is now
	if err != nil {
		h.finish(id, title, agentapi.StateFailed, "batch_copy", nil)
		return answer(err)
	}
	defer release()
	abort := func() bool { c2, e2 := a.store(); return e2 != nil || c2 != c }
	results, failed, code := h.replay(sc, b.items, abort)
	if failed >= 0 {
		h.finishBatch(id, title, b.who, agentapi.StateFailed, code, results)
		return Response{409, map[string]any{keyCode: "batch_failed", keyParams: map[string]any{"n": failed + 1, "op": results[failed].Op, "why": code}}}
	}
	if abort() { // locked while the items were run: the copy is dropped
		h.finishBatch(id, title, b.who, agentapi.StateFailed, "locked", results)
		return fail(404, "agent_gone")
	}
	if err := runner.BatchAdopt(sc); err != nil {
		if errors.Is(err, ErrBatchSaved) { // it is on disk; the window reads the vault again
			h.finishBatch(id, title, b.who, agentapi.StateApplied, "reload_failed", results)
			return ok(map[string]any{"ok": true, "warning": "reload_failed"})
		}
		code, _ := agentCode(err)
		h.finishBatch(id, title, b.who, agentapi.StateFailed, code, results)
		return answer(err)
	}
	h.finishBatch(id, title, b.who, agentapi.StateApplied, "", results)
	return ok(map[string]any{"ok": true})
}

// finishBatch records the end of a batch and writes it, and each of its items, to the journal.
func (h *agentHub) finishBatch(id, title, who, state, code string, results []agentResult) {
	h.finish(id, title, state, code, results)
	r := state
	if code != "" {
		r += ": " + code
	}
	h.log("batch", title+" ("+strconv.Itoa(len(results))+" items)", who, r)
	for _, it := range results {
		h.log(it.Op, it.Target, who, it.Result)
	}
}

// describe fills what the dialog shows of the item that was just run: the names, every argument that is used, and whether a name has non-Latin letters.
func (x *agentCtx) describe() *agentItem {
	it := x.rec
	it.target = clean(targetOf(x.args), 300)
	it.details = append(detailsOf(x.args, it.hideValue), x.extra...)
	it.nonlatin = hasNonLatin(it.target + it.what + it.where + it.from)
	for _, c := range it.changes {
		it.nonlatin = it.nonlatin || hasNonLatin(c.Old+c.New)
	}
	for _, d := range it.details {
		it.nonlatin = it.nonlatin || hasNonLatin(d.Field+d.Value)
	}
	return it
}

// sig is what must be the same when the item is run again: what the person was shown.
func (it *agentItem) sig() string {
	b, _ := json.Marshal([]any{it.op, it.target, it.what, it.where, it.from, it.changes, it.sens, it.details, it.nonlatin})
	return string(b)
}

// detailsOf lists every argument of an item (but "batch") as text: strings cleaned and cut with a "…", flags, lists, and the targets of a copy. A secret value is
// not shown, the dialog says that it is one.
func detailsOf(args map[string]any, hideValue bool) []agentDetail {
	var out []agentDetail
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			f := prefix + k
			switch v := m[k].(type) {
			case string:
				d := agentDetail{Field: clean(f, 60), Value: clean(v, 200)}
				if f == keyValue && hideValue {
					d.Value, d.Hidden = "", true
				}
				out = append(out, d)
			case bool:
				out = append(out, agentDetail{Field: clean(f, 60), Value: strconv.FormatBool(v)})
			case float64:
				out = append(out, agentDetail{Field: clean(f, 60), Value: strconv.FormatFloat(v, 'f', -1, 64)})
			case []any:
				var s []string
				for _, e := range v {
					s = append(s, clean(fmt.Sprint(e), 200))
				}
				out = append(out, agentDetail{Field: clean(f, 60), Value: strings.Join(s, ", ")})
			case map[string]any:
				walk(f+".", v)
			}
		}
	}
	walk("", args)
	return out
}

// prefixClashes marks the items that use two different names that start alike (a long common beginning): read to the end, the dialog says.
func prefixClashes(items []*agentItem) []bool {
	names := map[string][]int{}
	for i, it := range items {
		add := func(s string) {
			if s != "" {
				names[s] = append(names[s], i)
			}
		}
		add(it.what)
		add(it.where)
		for _, d := range it.details {
			f := d.Field
			if j := strings.LastIndex(f, "."); j >= 0 {
				f = f[j+1:]
			}
			switch f {
			case "name", "key", "new_key", "new_name", "scope", keyConn, "field", "other", "title", "new_title", "env", "site":
				add(d.Value)
			}
		}
	}
	out := make([]bool, len(items))
	list := make([]string, 0, len(names))
	for n := range names {
		list = append(list, n)
	}
	for i := range list {
		for j := i + 1; j < len(list); j++ {
			a, c := []rune(list[i]), []rune(list[j])
			n := 0
			for n < len(a) && n < len(c) && a[n] == c[n] {
				n++
			}
			if n >= 20 && (n < len(a) || n < len(c)) {
				for _, k := range names[list[i]] {
					out[k] = true
				}
				for _, k := range names[list[j]] {
					out[k] = true
				}
			}
		}
	}
	return out
}
