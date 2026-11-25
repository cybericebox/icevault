package desktop

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/cybericebox/icevault/internal/agentapi"
)

// The ops of the agent API. Reads answer names, states and plain values; writes go through Core.Write with the same ops the environment screen uses
// ("m-var", "m-field", "m-site", ...), so validation, the model check, Sync into the vault and Save are the window's own. What is removed goes to the
// vault's recycle bin (Sync does that). No op answers a secret value, and none can switch the confirmation off.
//
// A value is set directly only where the place is plain. A secret place (a secret or sealed variable, a secret field, an other secret) is set only
// after the person says Allow in the window (a pending request).

// Words the ops repeat.
const (
	stSet    = "set"
	kindVar  = "var"
	keyField = "field"
	keyUUID  = "uuid"
	actUpd   = "update"
	keyKind  = "kind"
	keyName  = "name"
)

const (
	keyKey    = "key"
	keyScope  = "scope"
	visPlain  = "plain"
	opStatus  = "status"
	modeEdit  = "edit"
	keyEnv    = "env"
	keyAction = "action"
	actDelete = "delete"
)

type agentCtx struct {
	h    *agentHub
	c    Core
	args map[string]any
	who  string
	peer string
	pkey string // the client the rate limit counts: the program that started the command
	nav  map[string]any
}

// agentOps are the names the API knows, in the order "help" lists them.
var agentOps = []string{"help", opStatus, "structure",
	"var-create", "var-rename", "var-delete", "var-meta", "set-value", "copy-value", "move-value",
	"connection-create", "connection-update", "connection-delete", "field-create", "field-update", "field-delete",
	"site-create", "site-update", "site-delete", "product-create", "product-update", "product-delete",
	"env-create", "env-update", "env-delete", "other-create", "other-update", "other-delete"}

func as(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func ab(m map[string]any, k string) bool   { b, _ := m[k].(bool); return b }
func ahas(m map[string]any, k string) bool { _, f := m[k]; return f }
func asub(m map[string]any, k string) map[string]any {
	s, _ := m[k].(map[string]any)
	return s
}
func alist(m map[string]any, k string) []map[string]any {
	var out []map[string]any
	l, _ := m[k].([]any)
	for _, x := range l {
		if r, isMap := x.(map[string]any); isMap {
			out = append(out, r)
		}
	}
	return out
}

func okData(data any) agentapi.Response { return agentapi.Response{OK: true, Data: data} }
func agentRefused(code string, params map[string]any) agentapi.Response {
	return agentapi.Response{Code: code, Params: params}
}
func refusedErr(err error) agentapi.Response {
	code, params := agentCode(err)
	return agentRefused(code, params)
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
	if req.Op != "help" && req.Op != opStatus && req.Op != "structure" { // the writes need the window in edit mode, as the window's own do
		a.mu.Lock()
		mode := a.mode
		a.mu.Unlock()
		if mode != modeEdit {
			h.log(req.Op, targetOf(args), who, "refused: view_mode")
			return agentRefused("view_mode", nil)
		}
	}
	if req.Op != opStatus && req.Op != "help" {
		_, _ = a.syncDisk(false, true)
	}
	pk := peer.PPID
	if pk <= 0 {
		pk = peer.PID
	}
	x := &agentCtx{h: h, c: c, args: args, who: who, peer: peer.Describe(), pkey: strconv.Itoa(pk)}
	resp := x.run(req.Op)
	if req.Op != opStatus { // a client polls status: that is not an action
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

// targetOf names what a request is about: the names it carries, never a value.
func targetOf(args map[string]any) string {
	out := ""
	add := func(prefix string, m map[string]any) {
		for _, k := range []string{keyEnv, keyScope, keyName, keyKey, "new_key", "new_name", "title", "new_title", "connection", keyField, "other", keyKind, "site", "from", "state", "visibility"} {
			if s, isStr := m[k].(string); isStr && s != "" {
				if out != "" {
					out += " "
				}
				out += prefix + k + "=" + clean(s, 60)
			}
		}
	}
	add("", args)
	for _, k := range []string{"from", "to"} {
		if m := asub(args, k); m != nil {
			add(k+".", m)
		}
	}
	return out
}

func (x *agentCtx) loadNav() error {
	if x.nav != nil {
		return nil
	}
	d, err := x.c.Read("nav", map[string]any{})
	if err != nil {
		return err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	x.nav = m
	return nil
}

func (x *agentCtx) write(op string, args map[string]any) error {
	x.nav = nil
	_, err := x.c.Write(op, args)
	return err
}

func (x *agentCtx) run(op string) agentapi.Response {
	switch op {
	case "help":
		return okData(map[string]any{"ops": agentOps})
	case opStatus:
		return x.status()
	}
	if err := x.loadNav(); err != nil {
		return refusedErr(err)
	}
	if op == "structure" {
		return okData(x.structure(as(x.args, keyEnv)))
	}
	a := x.args
	switch op {
	case "var-create":
		if r := x.varRow(as(a, keyScope), as(a, keyKey)); r != nil && !ab(r, "missing") {
			return agentRefused("name_exists", map[string]any{keyName: as(a, keyKey)})
		}
		w := pick(a, keyScope, keyKey, "visibility", "description", "expires")
		if x.secretKeyAnywhere(as(a, keyKey)) { // a plain variable of that name would shadow a secret one: it is made secret, and its value waits for Allow
			if v := as(a, "visibility"); v != "" && rank(v) < 1 {
				if x.secretByModel(as(a, keyKey)) {
					return agentRefused("no_lowering", nil)
				}
				return agentRefused("shadows_secret", nil)
			}
			if as(a, "visibility") == "" {
				w["visibility"] = "secret"
			}
		}
		return x.done(x.write("m-var", w))
	case "var-rename":
		return x.varRename()
	case "var-delete":
		return x.varDelete()
	case "var-meta":
		r := x.varRow(as(a, keyScope), as(a, keyKey))
		if r == nil || ab(r, "missing") {
			return agentRefused("not_found", nil)
		}
		if v := as(a, "visibility"); v != "" {
			if rank(v) < 0 {
				return agentRefused("bad_request", nil)
			}
			if rank(v) < rank(as(r, "visibility")) { // a secret never becomes plain through the API: the list would show its value
				return agentRefused("no_lowering", nil)
			}
		}
		return x.done(x.write("m-var", pick(a, keyScope, keyKey, "description", "visibility", "expires")))
	case "set-value":
		return x.setValue()
	case "copy-value":
		return x.copyValue(false)
	case "move-value":
		return x.copyValue(true)
	case "connection-create":
		w := withAction(pick(a, keyName, keyKind, "description"), "create")
		if x.boundName(as(a, keyName)) { // the commands that fill an environment link a connection by this name: it is not made without Allow
			return x.queue(op, "connection", as(a, keyName), "", "", func(nx *agentCtx) error { return nx.write("m-connection", w) })
		}
		return x.done(x.write("m-connection", w))
	case "connection-update":
		cn := x.conn(as(a, "connection"))
		if cn == nil {
			return agentRefused("not_found", nil)
		}
		w := map[string]any{keyUUID: as(cn, keyUUID), keyAction: actUpd, keyName: as(a, "new_name")}
		copyIf(w, a, "description")
		if nn := as(a, "new_name"); nn != "" && nn != as(a, "connection") && x.boundName(nn) { // a rename to a name the project binds redirects where environments link
			uuid, name := as(cn, keyUUID), as(a, "connection")
			return x.queue("connection-update", "connection", name+" -> "+nn, "", "", func(nx *agentCtx) error {
				if c2 := nx.conn(name); c2 == nil || as(c2, keyUUID) != uuid {
					return errGone
				}
				c := copyMap(w)
				c["confirm"] = true
				return nx.write("m-connection", c)
			})
		}
		return x.writeAsk("m-connection", w, "connection-update", "connection", as(a, "connection"), "")
	case "connection-delete":
		return x.connectionDelete()
	case "field-create", "field-update", "field-delete":
		return x.fieldOp(op)
	case "site-create", "site-update", "site-delete":
		return x.siteOp(op)
	case "product-create", "product-update", "product-delete":
		return x.productOp(op)
	case "env-create":
		return x.envCreate()
	case "env-update":
		return x.done(x.write("m-env", withAction(pick(a, keyName, "new_name", "title"), actUpd)))
	case "env-delete":
		return x.envDelete()
	case "other-create":
		return x.done(x.write("m-other", withAction(pick(a, "title", "expires"), "create")))
	case "other-update", "other-delete":
		o := x.other(as(a, "other"))
		if o == nil {
			return agentRefused("not_found", nil)
		}
		w := map[string]any{keyUUID: as(o, keyUUID), keyAction: actUpd}
		if op == "other-delete" {
			w[keyAction] = actDelete
			if as(o, "state") == stSet { // a secret that is filled goes only after Allow
				uuid, title := as(o, keyUUID), as(a, "other")
				return x.queue(op, "other", title, "", "", func(nx *agentCtx) error {
					if o2 := nx.other(title); o2 == nil || as(o2, keyUUID) != uuid {
						return errGone
					}
					return nx.write("m-other", w)
				})
			}
		} else {
			w["title"] = as(a, "new_title")
			copyIf(w, a, "expires")
			if nt := as(a, "new_title"); nt != "" && nt != as(a, "other") && as(o, "state") == stSet { // a filled secret is renamed only after Allow
				uuid, title := as(o, keyUUID), as(a, "other")
				return x.queue(op, "other", title+" -> "+nt, "", "", func(nx *agentCtx) error {
					if o2 := nx.other(title); o2 == nil || as(o2, keyUUID) != uuid {
						return errGone
					}
					return nx.write("m-other", w)
				})
			}
		}
		return x.done(x.write("m-other", w))
	}
	return agentRefused("unknown_op", nil)
}

func (x *agentCtx) done(err error) agentapi.Response {
	if err != nil {
		return refusedErr(err)
	}
	return okData(map[string]any{"ok": true})
}

// pick copies the named arguments that are present (only strings and booleans: a list or a map is not an argument of these ops).
func pick(a map[string]any, keys ...string) map[string]any {
	w := map[string]any{}
	copyIf(w, a, keys...)
	return w
}

func copyIf(w, a map[string]any, keys ...string) {
	for _, k := range keys {
		switch v := a[k].(type) {
		case string, bool:
			w[k] = v
		}
	}
}

func withAction(w map[string]any, action string) map[string]any { w[keyAction] = action; return w }

func copyMap(w map[string]any) map[string]any {
	c := make(map[string]any, len(w)+1)
	for k, v := range w {
		c[k] = v
	}
	return c
}

// writeAsk writes at once; when the core says that something uses the thing (a refusal "confirm_*"), the person is asked, and only Allow writes it with the
// confirmation. The agent's own "confirm" is never passed on.
func (x *agentCtx) writeAsk(coreOp string, w map[string]any, op, kind, what, where string) agentapi.Response {
	err := x.write(coreOp, w)
	if err == nil {
		return okData(map[string]any{"ok": true})
	}
	code, _ := agentCode(err)
	if !strings.HasPrefix(code, "confirm_") {
		return refusedErr(err)
	}
	return x.queue(op, kind, what, where, "", func(nx *agentCtx) error {
		c := copyMap(w)
		c["confirm"] = true
		return nx.write(coreOp, c)
	})
}

func isSecretRow(r map[string]any) bool { return as(r, "visibility") != visPlain || ab(r, "secret") }

func filledRow(r map[string]any) bool { return as(r, "state") == stSet }

// secretKeyAnywhere says whether a variable of that name is secret anywhere in the vault (shared, General, a site, a product, or by the description of the
// project): a plain variable of the same name must not shadow it.
// secretByModel says whether the project (or the name rule) makes a variable of that name secret.
func (x *agentCtx) boundName(name string) bool {
	b, can := x.c.(ConnNameBinder)
	return can && b.BoundConnectionName(name)
}

func (x *agentCtx) secretByModel(key string) bool {
	vd, can := x.c.(VisDefaulter)
	return can && vd.DefaultVisibility(key) != visPlain
}

func (x *agentCtx) secretKeyAnywhere(key string) bool {
	if x.secretByModel(key) {
		return true
	}
	has := func(rows []map[string]any) bool {
		for _, r := range rows {
			if as(r, keyKey) == key && isSecretRow(r) {
				return true
			}
		}
		return false
	}
	if has(alist(x.nav, "shared")) {
		return true
	}
	for _, e := range alist(x.nav, "envs") {
		if has(alist(e, "general")) {
			return true
		}
		for _, s := range alist(e, "sites") {
			if has(alist(s, "vars")) {
				return true
			}
		}
		for _, p := range alist(e, "products") {
			if has(alist(p, "vars")) || (asub(p, "sub") != nil && has(alist(asub(p, "sub"), "vars"))) {
				return true
			}
		}
	}
	return false
}

// varRename renames a variable. A plain one never takes the name of a secret one; a secret or filled one is renamed only after Allow (a rename away and a
// new plain variable of the old name would be a way round the rules).
func (x *agentCtx) varRename() agentapi.Response {
	scope, key, nk := as(x.args, keyScope), as(x.args, keyKey), as(x.args, "new_key")
	r := x.varRow(scope, key)
	if r == nil || ab(r, "missing") {
		return agentRefused("not_found", nil)
	}
	if nk != "" && !isSecretRow(r) && x.secretKeyAnywhere(nk) {
		return agentRefused("shadows_secret", nil)
	}
	w := map[string]any{keyScope: scope, keyKey: key, "new_key": nk}
	if !isSecretRow(r) && !filledRow(r) {
		return x.done(x.write("m-var", w))
	}
	return x.queue("var-rename", kindVar, key+" -> "+nk, scope, "", func(nx *agentCtx) error {
		r2 := nx.varRow(scope, key)
		if r2 == nil {
			return errGone
		}
		if nk != "" && !isSecretRow(r2) && nx.secretKeyAnywhere(nk) {
			return &Error{Status: 409, Code: "shadows_secret"}
		}
		return nx.write("m-var", w)
	})
}

func (x *agentCtx) varDelete() agentapi.Response {
	scope, key := as(x.args, keyScope), as(x.args, keyKey)
	r := x.varRow(scope, key)
	if r == nil {
		return agentRefused("not_found", nil)
	}
	w := map[string]any{keyScope: scope, keyKey: key, actDelete: true}
	if filledRow(r) && isSecretRow(r) { // a filled secret goes to the recycle bin only after Allow
		return x.queue("var-delete", kindVar, key, scope, "", func(nx *agentCtx) error {
			if r2 := nx.varRow(scope, key); r2 == nil || !isSecretRow(r2) {
				return errGone
			}
			c := copyMap(w)
			c["confirm"] = true
			return nx.write("m-var", c)
		})
	}
	return x.writeAsk("m-var", w, "var-delete", kindVar, key, scope)
}

func rank(vis string) int {
	switch vis {
	case visPlain:
		return 0
	case "secret":
		return 1
	case "sealed":
		return 2
	}
	return -1
}

// ---- lookups in the nav

func (x *agentCtx) conn(name string) map[string]any {
	for _, c := range alist(x.nav, "connections") {
		if as(c, keyName) == name && name != "" {
			return c
		}
	}
	return nil
}

func (x *agentCtx) other(title string) map[string]any {
	for _, o := range alist(x.nav, "other") {
		if as(o, "title") == title && title != "" {
			return o
		}
	}
	return nil
}

func (x *agentCtx) env(name string) map[string]any {
	for _, e := range alist(x.nav, "envs") {
		if as(e, keyName) == name {
			return e
		}
	}
	return nil
}

// connUUIDs turns connection names into ids ("" stays "": none).
func (x *agentCtx) connUUID(name string) (string, bool) {
	if name == "" {
		return "", true
	}
	if c := x.conn(name); c != nil {
		return as(c, keyUUID), true
	}
	return "", false
}

func (x *agentCtx) varRow(scope, key string) map[string]any {
	var rows []map[string]any
	p := splitScope(scope)
	switch {
	case scope == "shared":
		rows = alist(x.nav, "shared")
	case len(p) >= 3 && p[0] == keyEnv:
		e := x.env(p[1])
		if e == nil {
			return nil
		}
		switch {
		case p[2] == "general" && len(p) == 3:
			for _, r := range alist(e, "general") {
				if !ab(r, "imported") || ab(r, "overridden") {
					rows = append(rows, r)
				}
			}
		case p[2] == "site" && len(p) == 4:
			for _, s := range alist(e, "sites") {
				if as(s, keyName) == p[3] {
					rows = alist(s, "vars")
				}
			}
		case p[2] == "product" && len(p) >= 4:
			for _, pr := range alist(e, "products") {
				if as(pr, keyName) != p[3] {
					continue
				}
				if len(p) == 4 {
					rows = alist(pr, "vars")
				} else if sub := asub(pr, "sub"); sub != nil && as(sub, keyKind) == p[4] {
					rows = alist(sub, "vars")
				}
			}
		}
	}
	for _, r := range rows {
		if as(r, keyKey) == key && key != "" {
			return r
		}
	}
	return nil
}

func splitScope(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '/' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

// ---- targets of a value

type agentTarget struct {
	kind                    string // kindVar, keyField, "other"
	scope, key, field, name string // name: the connection or the other secret
	uuid                    string
	secret, filled, system  bool
}

func (t *agentTarget) what() string {
	if t.kind == kindVar {
		return t.key
	}
	if t.kind == keyField {
		return t.field
	}
	return t.name
}

func (t *agentTarget) where() string {
	if t.kind == kindVar {
		return t.scope
	}
	if t.kind == keyField {
		return t.name
	}
	return ""
}

func (x *agentCtx) target(m map[string]any) (*agentTarget, error) {
	switch {
	case as(m, "other") != "":
		o := x.other(as(m, "other"))
		if o == nil {
			return nil, &Error{Status: 404, Code: "not_found"}
		}
		return &agentTarget{kind: "other", name: as(m, "other"), uuid: as(o, keyUUID), secret: true, filled: as(o, "state") == stSet}, nil
	case as(m, "connection") != "":
		cn := x.conn(as(m, "connection"))
		if cn == nil {
			return nil, &Error{Status: 404, Code: "not_found"}
		}
		for _, f := range alist(cn, "fields") {
			if as(f, keyName) == as(m, keyField) {
				return &agentTarget{kind: keyField, name: as(m, "connection"), field: as(m, keyField), uuid: as(cn, keyUUID), secret: ab(f, "secret"), filled: as(f, "state") == stSet}, nil
			}
		}
		return nil, &Error{Status: 404, Code: "not_found"}
	default:
		r := x.varRow(as(m, keyScope), as(m, keyKey))
		if r == nil {
			return nil, &Error{Status: 404, Code: "not_found"}
		}
		return &agentTarget{kind: kindVar, scope: as(m, keyScope), key: as(m, keyKey), secret: isSecretRow(r) || x.secretKeyAnywhere(as(m, keyKey)), filled: as(r, "state") == stSet,
			system: ab(r, "system") || as(r, "managed") == "system"}, nil
	}
}

func (t *agentTarget) put(x *agentCtx, value string) error {
	switch t.kind {
	case kindVar:
		return x.write("m-var", map[string]any{keyScope: t.scope, keyKey: t.key, "value": value})
	case keyField:
		return x.write("m-field", map[string]any{keyUUID: t.uuid, keyField: t.field, "value": value})
	}
	return x.write("m-other", map[string]any{keyAction: actUpd, keyUUID: t.uuid, "value": value})
}

func (t *agentTarget) read(c Core) (string, error) {
	switch t.kind {
	case kindVar:
		return c.Reveal("m", t.scope, "", t.key)
	case keyField:
		return c.Reveal("m", "conn/"+t.uuid, "", t.field)
	}
	return c.Reveal("m", "other/"+t.uuid, "", "")
}

func (t *agentTarget) label() string {
	switch t.kind {
	case kindVar:
		return t.scope + " / " + t.key
	case keyField:
		return t.name + " / " + t.field
	}
	return t.name
}

// queue puts a request that needs the person's Allow in the queue; fn runs after Allow, on a core that may have changed meanwhile, so it looks again at
// what it was about (nav) and refuses with "gone" when that is not the same thing any more.
func (x *agentCtx) queue(op, kind, what, where, from string, fn func(nx *agentCtx) error) agentapi.Response {
	h := x.h
	id, err := h.enqueue(&agentReq{op: op, kind: kind, what: clean(what, 120), where: clean(where, 200), from: clean(from, 200), who: x.who, peer: clean(x.peer, 200), key: x.pkey,
		apply: func(c Core) error {
			nx := &agentCtx{h: h, c: c}
			if err := nx.loadNav(); err != nil {
				return err
			}
			return fn(nx)
		}})
	if errors.Is(err, errAgentRate) {
		return agentRefused("rate_limited", nil)
	}
	if err != nil {
		return agentRefused("too_many_pending", nil)
	}
	return agentapi.Response{OK: true, State: agentapi.StatePending, ID: id}
}

var errGone = &Error{Status: 409, Code: "gone"}

// id is the target without what may change between the request and the answer of the person (whether it is filled).
func (t agentTarget) id() agentTarget { t.filled = false; return t }

// targetArgs keeps the names of a target: what the request is aimed at.
func targetArgs(m map[string]any) map[string]any {
	return pick(m, keyScope, keyKey, "connection", "field", "other")
}

// setValue sets a value: at once where the place is plain, after the person's Allow where it is secret. The value never comes back.
func (x *agentCtx) setValue() agentapi.Response {
	value, isStr := x.args["value"].(string)
	if !isStr || len(value) > agentMaxValue {
		return agentRefused("bad_request", nil)
	}
	t, err := x.target(x.args)
	if err != nil {
		return refusedErr(err)
	}
	if !t.secret {
		return x.done(t.put(x, value))
	}
	if t.system {
		return agentRefused("system_managed", map[string]any{keyKey: t.key})
	}
	saved, args := t.id(), targetArgs(x.args)
	return x.queue("set-value", t.kind, t.what(), t.where(), "", func(nx *agentCtx) error {
		t2, err := nx.target(args)
		if err != nil || t2.id() != saved || !t2.secret || t2.system { // deleted and made again as something else while it waited
			return errGone
		}
		return t2.put(nx, value)
	})
}

// copyValue copies or moves a value from one place of the vault to another. The value passes through the program only; it is never answered.
// Everything that lands in a secret place, and a move that empties a secret place, waits for the person.
func (x *agentCtx) copyValue(move bool) agentapi.Response {
	fromArgs, toArgs := targetArgs(asub(x.args, "from")), targetArgs(asub(x.args, "to"))
	from, err := x.target(fromArgs)
	if err != nil {
		return refusedErr(err)
	}
	to, err := x.target(toArgs)
	if err != nil {
		return refusedErr(err)
	}
	if from.id() == to.id() {
		return agentRefused("same_target", nil)
	}
	savedFrom, savedTo := from.id(), to.id()
	// look at both places now (also after the answer, on what is then there)
	run := func(nx *agentCtx) error {
		f, err := nx.target(fromArgs)
		if err != nil || f.id() != savedFrom {
			return errGone
		}
		t, err := nx.target(toArgs)
		if err != nil || t.id() != savedTo {
			return errGone
		}
		if f.secret && !t.secret {
			return &Error{Status: 409, Code: "would_expose"} // a secret never becomes a plain value: it would show in the list
		}
		if (move && f.system) || t.system {
			return &Error{Status: 409, Code: "system_managed"}
		}
		v, err := f.read(nx.c) // a sealed value is refused here
		if err != nil {
			return err
		}
		if v == "" {
			return &Error{Status: 409, Code: "empty_source"}
		}
		if err := t.put(nx, v); err != nil {
			return err
		}
		if move {
			return f.put(nx, "")
		}
		return nil
	}
	// the refusals that need no answer of the person come first
	if from.secret && !to.secret {
		return agentRefused("would_expose", nil)
	}
	if (move && from.system) || to.system {
		return agentRefused("system_managed", nil)
	}
	if v, err := from.read(x.c); err != nil {
		return refusedErr(err)
	} else if v == "" {
		return agentRefused("empty_source", nil)
	}
	if !to.secret && (!move || !from.secret) {
		return x.done(run(x))
	}
	op := "copy-value"
	if move {
		op = "move-value"
	}
	return x.queue(op, to.kind, to.what(), to.where(), from.label(), run)
}

// ---- deletes and copies that wait for the person

func (x *agentCtx) connectionDelete() agentapi.Response {
	name := as(x.args, "connection")
	cn := x.conn(name)
	if cn == nil {
		return agentRefused("not_found", nil)
	}
	w := map[string]any{keyUUID: as(cn, keyUUID), keyAction: actDelete}
	filledSecret := false
	for _, f := range alist(cn, "fields") {
		filledSecret = filledSecret || (ab(f, "secret") && as(f, "state") == stSet)
	}
	if len(alist(cn, "users")) == 0 && !filledSecret {
		return x.done(x.write("m-connection", w))
	}
	uuid := as(cn, keyUUID)
	return x.queue("connection-delete", "connection", name, "", "", func(nx *agentCtx) error {
		if c2 := nx.conn(name); c2 == nil || as(c2, keyUUID) != uuid {
			return errGone
		}
		c := copyMap(w)
		c["confirm"] = true
		return nx.write("m-connection", c)
	})
}

func (x *agentCtx) envDelete() agentapi.Response {
	name := as(x.args, keyName)
	if x.env(name) == nil {
		return agentRefused("no_env", map[string]any{keyEnv: name})
	}
	return x.queue("env-delete", keyEnv, name, "", "", func(nx *agentCtx) error {
		if nx.env(name) == nil {
			return errGone
		}
		return nx.write("m-env", map[string]any{keyAction: actDelete, keyName: name, "confirm": true})
	})
}

// hasSecrets says whether an environment holds a filled variable that is not plain.
func hasSecrets(e map[string]any) bool {
	secret := func(rows []map[string]any) bool {
		for _, r := range rows {
			if as(r, "state") == stSet && (as(r, "visibility") != visPlain || ab(r, "secret")) {
				return true
			}
		}
		return false
	}
	if secret(alist(e, "general")) || len(alist(e, "file_list")) > 0 { // any kept file counts, sealed or not
		return true
	}
	for _, s := range alist(e, "sites") {
		if secret(alist(s, "vars")) || len(alist(s, "file_list")) > 0 {
			return true
		}
	}
	for _, p := range alist(e, "products") {
		if secret(alist(p, "vars")) || (asub(p, "sub") != nil && secret(alist(asub(p, "sub"), "vars"))) {
			return true
		}
	}
	return false
}

// envPrint names an environment by what it holds (the ids of its sites and products): the same name over other contents is another source.
func envPrint(e map[string]any) string {
	var ids []string
	for _, s := range alist(e, "sites") {
		ids = append(ids, "s:"+as(s, keyUUID))
	}
	for _, p := range alist(e, "products") {
		ids = append(ids, "p:"+as(p, keyUUID))
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

// envCreate makes an environment, empty or as a copy of another. A copy that carries secrets waits for the person.
func (x *agentCtx) envCreate() agentapi.Response {
	a := x.args
	w := withAction(pick(a, keyName, "title"), "create")
	from := as(a, "from")
	if from == "" {
		return x.done(x.write("m-env", w))
	}
	src := x.env(from)
	if src == nil {
		return agentRefused("no_env", map[string]any{keyEnv: from})
	}
	w[keyAction], w["from"] = "copy", from
	secrets := hasSecrets(src)
	if sc, can := x.c.(SecretCounter); can { // the core also sees the groups of site kinds that no site shows
		secrets = secrets || sc.EnvHoldsSecrets(from)
	}
	if !secrets {
		return x.done(x.write("m-env", w))
	}
	saved := envPrint(src)
	return x.queue("env-create", "envcopy", as(a, keyName), "", from, func(nx *agentCtx) error {
		if e2 := nx.env(from); e2 == nil || envPrint(e2) != saved { // the source is the same one: the same sites and products
			return errGone
		}
		return nx.write("m-env", w)
	})
}

// ---- connection fields, sites, products

func (x *agentCtx) fieldOp(op string) agentapi.Response {
	a := x.args
	cn := x.conn(as(a, "connection"))
	if cn == nil {
		return agentRefused("not_found", nil)
	}
	var row map[string]any
	for _, f := range alist(cn, "fields") {
		if as(f, keyName) == as(a, keyField) {
			row = f
		}
	}
	w := map[string]any{keyUUID: as(cn, keyUUID), keyField: as(a, keyField)}
	if v, given := a["secret"]; given { // a secret flag goes up only: a field that is secret stays secret, whatever is asked
		b, isBool := v.(bool)
		if !isBool {
			return agentRefused("bad_request", nil)
		}
		if !b && row != nil && ab(row, "secret") {
			return agentRefused("no_lowering", nil)
		}
	}
	switch op {
	case "field-create":
		if row != nil && ab(row, "present") {
			return agentRefused("name_exists", map[string]any{keyName: as(a, keyField)})
		}
		copyIf(w, a, "secret", "expires")
	case "field-update":
		if row == nil || !ab(row, "present") {
			return agentRefused("not_found", nil)
		}
		copyIf(w, a, "secret", "expires") // a field can become secret, never plain
	case "field-delete":
		w[actDelete] = true
		if row != nil && ab(row, "secret") && as(row, "state") == stSet { // a filled secret field goes only after Allow
			uuid, conn, field := as(cn, keyUUID), as(a, "connection"), as(a, keyField)
			return x.queue(op, keyField, field, conn, "", func(nx *agentCtx) error {
				if c2 := nx.conn(conn); c2 == nil || as(c2, keyUUID) != uuid {
					return errGone
				}
				return nx.write("m-field", w)
			})
		}
	}
	return x.done(x.write("m-field", w))
}

func (x *agentCtx) siteOp(op string) agentapi.Response {
	if op == "site-delete" {
		return x.siteDelete()
	}
	a := x.args
	w := pick(a, keyEnv, keyName, "new_name", keyKind)
	w[keyAction] = actUpd
	if op == "site-create" {
		w[keyAction] = "create"
	}
	for _, k := range []string{"connection", "state"} {
		if ahas(a, k) {
			u, found := x.connUUID(as(a, k))
			if !found {
				return agentRefused("not_found", nil)
			}
			w[k] = u
		}
	}
	if op == "site-create" {
		if e := x.env(as(a, keyEnv)); e != nil { // the core links every product that has no site to a new site: that changes what those products run with
			for _, p := range alist(e, "products") {
				if as(p, "site") == "" {
					return x.queue("site-create", "site", as(a, keyName), as(a, keyEnv), "", func(nx *agentCtx) error { return nx.write("m-site", w) })
				}
			}
		}
		return x.done(x.write("m-site", w))
	}
	cur := x.thing(as(a, keyEnv), "sites", as(a, keyName))
	if cur == nil {
		return agentRefused("not_found", nil)
	}
	// another connection, another state connection or another kind changes what the products on the site run with: the person decides
	relink := (ahas(a, "connection") && as(w, "connection") != as(cur, "connection")) || (ahas(a, "state") && as(w, "state") != as(cur, "state")) ||
		(as(a, keyKind) != "" && as(a, keyKind) != as(cur, keyKind))
	if relink {
		uuid, env, name := as(cur, keyUUID), as(a, keyEnv), as(a, keyName)
		return x.queue("site-update", "site", name, env, "", func(nx *agentCtx) error {
			if s2 := nx.thing(env, "sites", name); s2 == nil || as(s2, keyUUID) != uuid {
				return errGone
			}
			c := copyMap(w)
			c["confirm"] = true
			return nx.write("m-site", c)
		})
	}
	return x.writeAsk("m-site", w, "site-update", "site", as(a, keyName), as(a, keyEnv))
}

// thing finds a site or a product of an environment by name.
func (x *agentCtx) thing(env, list, name string) map[string]any {
	if e := x.env(env); e != nil {
		for _, t := range alist(e, list) {
			if as(t, keyName) == name {
				return t
			}
		}
	}
	return nil
}

func (x *agentCtx) productOp(op string) agentapi.Response {
	if op == "product-delete" {
		return x.productDelete()
	}
	a := x.args
	w := pick(a, keyEnv, keyName, "new_name", "enabled")
	w[keyAction] = actUpd
	if op == "product-create" {
		w[keyAction] = "create"
	}
	if ahas(a, "site") {
		w["site"] = ""
		if name := as(a, "site"); name != "" {
			if x.env(as(a, keyEnv)) == nil {
				return agentRefused("no_env", map[string]any{keyEnv: as(a, keyEnv)})
			}
			s := x.thing(as(a, keyEnv), "sites", name)
			if s == nil {
				return agentRefused("not_found", nil)
			}
			w["site"] = as(s, keyUUID)
		}
	}
	if ahas(a, "connections") {
		names, _ := a["connections"].([]any)
		ids := []any{}
		for _, n := range names {
			s, isStr := n.(string)
			u, found := x.connUUID(s)
			if !isStr || !found || s == "" {
				return agentRefused("not_found", nil)
			}
			ids = append(ids, u)
		}
		w["connections"] = ids
	}
	if op == "product-create" {
		return x.done(x.write("m-product", w))
	}
	cur := x.thing(as(a, keyEnv), "products", as(a, keyName))
	if cur == nil {
		return agentRefused("not_found", nil)
	}
	relink := (ahas(a, "site") && as(w, "site") != as(cur, "site")) || (ahas(a, "connections") && !sameIDs(w["connections"], cur["connections"]))
	if relink { // another site or other connections change what the product runs with: the person decides
		uuid, env, name := as(cur, keyUUID), as(a, keyEnv), as(a, keyName)
		return x.queue("product-update", "product", name, env, "", func(nx *agentCtx) error {
			if p2 := nx.thing(env, "products", name); p2 == nil || as(p2, keyUUID) != uuid {
				return errGone
			}
			c := copyMap(w)
			c["confirm"] = true
			return nx.write("m-product", c)
		})
	}
	return x.writeAsk("m-product", w, "product-update", "product", as(a, keyName), as(a, keyEnv))
}

func sameIDs(a, b any) bool {
	ids := func(v any) string {
		var s []string
		l, _ := v.([]any)
		for _, x := range l {
			if t, isStr := x.(string); isStr {
				s = append(s, t)
			}
		}
		sort.Strings(s)
		return strings.Join(s, ",")
	}
	return ids(a) == ids(b)
}

// siteDelete and productDelete wait for the person: the things that run on a site, and a product with its variables, go to the recycle bin only after Allow.
func (x *agentCtx) siteDelete() agentapi.Response {
	return x.thingDelete("site-delete", "site", "sites", "m-site")
}

func (x *agentCtx) productDelete() agentapi.Response {
	return x.thingDelete("product-delete", "product", "products", "m-product")
}

func (x *agentCtx) thingDelete(op, kind, list, write string) agentapi.Response {
	env, name := as(x.args, keyEnv), as(x.args, keyName)
	find := func(nx *agentCtx) string {
		if e := nx.env(env); e != nil {
			for _, t := range alist(e, list) {
				if as(t, keyName) == name {
					return as(t, keyUUID)
				}
			}
		}
		return ""
	}
	uuid := find(x)
	if uuid == "" {
		return agentRefused("not_found", nil)
	}
	return x.queue(op, kind, name, env, "", func(nx *agentCtx) error {
		if find(nx) != uuid {
			return errGone
		}
		return nx.write(write, map[string]any{keyEnv: env, keyAction: actDelete, keyName: name, "confirm": true})
	})
}

// ---- status of a request that waited for the person

func (x *agentCtx) status() agentapi.Response {
	id := as(x.args, "id")
	h := x.h
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pend[id] != nil {
		return agentapi.Response{OK: true, State: agentapi.StatePending, ID: id}
	}
	if d, found := h.done[id]; found {
		return agentapi.Response{OK: true, State: d.state, ID: id, Code: d.code}
	}
	return agentRefused("not_found", nil)
}

// ---- the structure: names, states, plain values; never a secret value

func varOut(scope string, r map[string]any) map[string]any {
	out := map[string]any{keyScope: scope, keyKey: r[keyKey], "filled": as(r, "state") == stSet}
	for _, k := range []string{"visibility", "managed", "description", "changed", "expires", "expiry", "label", "required", "secret", "system", "missing", "imported", "overridden", "active"} {
		if v, found := r[k]; found && v != nil {
			out[k] = v
		}
	}
	if as(r, "visibility") == visPlain && !ab(r, "secret") && as(r, "state") == stSet {
		if v, isStr := r["value"].(string); isStr {
			out["value"] = v
		}
	}
	return out
}

func varsOut(scope string, rows []map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, r := range rows {
		out = append(out, varOut(scope, r))
	}
	return out
}

func filesOut(rows []map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, f := range rows {
		out = append(out, map[string]any{"rel": f["rel"], "site": f["site"], "sealed": f["sealed"], "changed": f["changed"]})
	}
	return out
}

func (x *agentCtx) structure(envOnly string) map[string]any {
	n := x.nav
	connName := map[string]string{}
	for _, c := range alist(n, "connections") {
		connName[as(c, keyUUID)] = as(c, keyName)
	}
	nameOf := func(u string) any {
		if u == "" {
			return nil
		}
		return connName[u]
	}
	envs := []map[string]any{}
	for _, e := range alist(n, "envs") {
		en := as(e, keyName)
		if envOnly != "" && envOnly != en {
			continue
		}
		siteName := map[string]string{}
		sites := []map[string]any{}
		for _, s := range alist(e, "sites") {
			siteName[as(s, keyUUID)] = as(s, keyName)
			sites = append(sites, map[string]any{keyName: s[keyName], keyKind: s[keyKind], "connection": nameOf(as(s, "connection")), "state_connection": nameOf(as(s, "state")),
				"variables": varsOut("env/"+en+"/site/"+as(s, keyName), alist(s, "vars")), "files": filesOut(alist(s, "file_list")), "products": s["users"]})
		}
		products := []map[string]any{}
		for _, p := range alist(e, "products") {
			cs := []any{}
			cl, _ := p["connections"].([]any)
			for _, u := range cl {
				if s, isStr := u.(string); isStr {
					cs = append(cs, connName[s])
				}
			}
			ps := "env/" + en + "/product/" + as(p, keyName)
			po := map[string]any{keyName: p[keyName], "enabled": p["enabled"], "place": p["place"], "site": nil, "connections": cs, "variables": varsOut(ps, alist(p, "vars")), "missing": len(alist(p, "missing"))}
			if s := as(p, "site"); s != "" {
				po["site"] = siteName[s]
			}
			if sub := asub(p, "sub"); sub != nil {
				po["sub"] = map[string]any{keyKind: sub[keyKind], "variables": varsOut(ps+"/"+as(sub, keyKind), alist(sub, "vars"))}
			}
			products = append(products, po)
		}
		general := []map[string]any{}
		for _, r := range alist(e, "general") {
			if !ab(r, "imported") || ab(r, "overridden") {
				general = append(general, varOut("env/"+en+"/general", r))
			}
		}
		envs = append(envs, map[string]any{keyName: en, "title": e["title"], "general": general, "imports": e["imports"], "sites": sites, "products": products, "files": filesOut(alist(e, "file_list"))})
	}
	shared := []map[string]any{}
	for _, r := range alist(n, "shared") {
		o := varOut("shared", r)
		o["users"] = r["users"]
		shared = append(shared, o)
	}
	conns := []map[string]any{}
	for _, c := range alist(n, "connections") {
		fields := []map[string]any{}
		for _, f := range alist(c, "fields") {
			fo := map[string]any{keyName: f[keyName], "label": f["label"], "secret": ab(f, "secret"), "present": ab(f, "present"), "filled": as(f, "state") == stSet}
			for _, k := range []string{"expires", "expiry"} {
				if v, found := f[k]; found {
					fo[k] = v
				}
			}
			if !ab(f, "secret") && as(f, "state") == stSet {
				if v, isStr := f["value"].(string); isStr {
					fo["value"] = v
				}
			}
			fields = append(fields, fo)
		}
		conns = append(conns, map[string]any{keyName: c[keyName], keyKind: c[keyKind], "description": c["description"], "changed": c["changed"], "fields": fields, "users": c["users"]})
	}
	other := []map[string]any{}
	for _, o := range alist(n, "other") {
		other = append(other, map[string]any{"title": o["title"], "filled": as(o, "state") == stSet, "expires": o["expires"], "expiry": o["expiry"]})
	}
	sort.SliceStable(other, func(i, j int) bool { return as(other[i], "title") < as(other[j], "title") })
	return map[string]any{"read_only": n["read_only"], "environments": envs, "shared": shared, "connections": conns, "other": other}
}

var _ = errors.New
