package desktop

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"

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

type agentCtx struct {
	h    *agentHub
	c    Core
	args map[string]any
	who  string
	nav  map[string]any
}

// agentOps are the names the API knows, in the order "help" lists them.
var agentOps = []string{"help", "status", "structure",
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

// handle runs one request of a client.
func (h *agentHub) handle(req agentapi.Request) agentapi.Response {
	a := h.a
	who := clean(req.Client, 40)
	if who == "" {
		who = "agent"
	}
	if req.PID > 0 {
		who += " (pid " + strconv.Itoa(req.PID) + ")"
	}
	c, e := a.store()
	if e != nil {
		return agentRefused("locked", nil)
	}
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
	if req.Op != "status" && req.Op != "help" {
		_, _ = a.syncDisk(false, true)
	}
	args := req.Args
	if args == nil {
		args = map[string]any{}
	}
	x := &agentCtx{h: h, c: c, args: args, who: who}
	resp := x.run(req.Op)
	if req.Op != "status" { // a client polls status: that is not an action
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
		for _, k := range []string{"env", "scope", keyName, "key", "new_key", "new_name", "title", "new_title", "connection", keyField, "other", keyKind, "site", "from", "state", "visibility"} {
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
	case "status":
		return x.status()
	}
	if err := x.loadNav(); err != nil {
		return refusedErr(err)
	}
	if op == "structure" {
		return okData(x.structure(as(x.args, "env")))
	}
	a := x.args
	switch op {
	case "var-create":
		if r := x.varRow(as(a, "scope"), as(a, "key")); r != nil && !ab(r, "missing") {
			return agentRefused("name_exists", map[string]any{keyName: as(a, "key")})
		}
		return x.done(x.write("m-var", pick(a, "scope", "key", "visibility", "description", "expires")))
	case "var-rename":
		if r := x.varRow(as(a, "scope"), as(a, "key")); r == nil || ab(r, "missing") {
			return agentRefused("not_found", nil)
		}
		return x.done(x.write("m-var", pick(a, "scope", "key", "new_key")))
	case "var-delete":
		return x.done(x.write("m-var", withConfirm(pick(a, "scope", "key"), a, "delete", true)))
	case "var-meta":
		r := x.varRow(as(a, "scope"), as(a, "key"))
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
		return x.done(x.write("m-var", pick(a, "scope", "key", "description", "visibility", "expires")))
	case "set-value":
		return x.setValue()
	case "copy-value":
		return x.copyValue(false)
	case "move-value":
		return x.copyValue(true)
	case "connection-create":
		return x.done(x.write("m-connection", withAction(pick(a, keyName, keyKind, "description"), "create")))
	case "connection-update", "connection-delete":
		cn := x.conn(as(a, "connection"))
		if cn == nil {
			return agentRefused("not_found", nil)
		}
		w := map[string]any{keyUUID: as(cn, keyUUID)}
		if op == "connection-delete" {
			w["action"] = "delete"
		} else {
			w["action"] = actUpd
			w[keyName] = as(a, "new_name")
			copyIf(w, a, "description")
		}
		return x.done(x.write("m-connection", withConfirm(w, a)))
	case "field-create", "field-update", "field-delete":
		return x.fieldOp(op)
	case "site-create", "site-update", "site-delete":
		return x.siteOp(op)
	case "product-create", "product-update", "product-delete":
		return x.productOp(op)
	case "env-create":
		w := withAction(pick(a, keyName, "title"), "create")
		if f := as(a, "from"); f != "" {
			w["action"], w["from"] = "copy", f
		}
		return x.done(x.write("m-env", w))
	case "env-update":
		return x.done(x.write("m-env", withAction(pick(a, keyName, "new_name", "title"), actUpd)))
	case "env-delete":
		return x.done(x.write("m-env", withConfirm(withAction(pick(a, keyName), "delete"), a)))
	case "other-create":
		return x.done(x.write("m-other", withAction(pick(a, "title", "expires"), "create")))
	case "other-update", "other-delete":
		o := x.other(as(a, "other"))
		if o == nil {
			return agentRefused("not_found", nil)
		}
		w := map[string]any{keyUUID: as(o, keyUUID), "action": actUpd}
		if op == "other-delete" {
			w["action"] = "delete"
		} else {
			w["title"] = as(a, "new_title")
			copyIf(w, a, "expires")
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

func withAction(w map[string]any, action string) map[string]any { w["action"] = action; return w }

// withConfirm passes "confirm" on: the refusals "confirm_*" name what uses the thing, and the agent says again, on purpose, that it goes on. Removed
// things go to the recycle bin.
func withConfirm(w, a map[string]any, kv ...any) map[string]any {
	if ab(a, "confirm") {
		w["confirm"] = true
	}
	for i := 0; i+1 < len(kv); i += 2 {
		w[kv[i].(string)] = kv[i+1]
	}
	return w
}

func rank(vis string) int {
	switch vis {
	case "plain":
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
	case len(p) >= 3 && p[0] == "env":
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
		if as(r, "key") == key && key != "" {
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
		r := x.varRow(as(m, "scope"), as(m, "key"))
		if r == nil {
			return nil, &Error{Status: 404, Code: "not_found"}
		}
		return &agentTarget{kind: kindVar, scope: as(m, "scope"), key: as(m, "key"), secret: as(r, "visibility") != "plain" || ab(r, "secret"), filled: as(r, "state") == stSet,
			system: ab(r, "system") || as(r, "managed") == "system"}, nil
	}
}

func (t *agentTarget) put(x *agentCtx, value string) error {
	switch t.kind {
	case kindVar:
		return x.write("m-var", map[string]any{"scope": t.scope, "key": t.key, "value": value})
	case keyField:
		return x.write("m-field", map[string]any{keyUUID: t.uuid, keyField: t.field, "value": value})
	}
	return x.write("m-other", map[string]any{"action": actUpd, keyUUID: t.uuid, "value": value})
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

func (x *agentCtx) queue(op string, t *agentTarget, from string, apply func(c Core) error) agentapi.Response {
	id, err := x.h.enqueue(&agentReq{op: op, kind: t.kind, what: clean(t.what(), 120), where: clean(t.where(), 200), from: clean(from, 200), who: x.who, apply: apply})
	if err != nil {
		return agentRefused("too_many_pending", nil)
	}
	return agentapi.Response{OK: true, State: agentapi.StatePending, ID: id}
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
		return agentRefused("system_managed", map[string]any{"key": t.key})
	}
	return x.queue("set-value", t, "", func(c Core) error { return t.put(&agentCtx{h: x.h, c: c}, value) })
}

// copyValue copies or moves a value from one place of the vault to another. The value passes through the program only; it is never answered.
func (x *agentCtx) copyValue(move bool) agentapi.Response {
	from, err := x.target(asub(x.args, "from"))
	if err != nil {
		return refusedErr(err)
	}
	to, err := x.target(asub(x.args, "to"))
	if err != nil {
		return refusedErr(err)
	}
	if *from == *to {
		return agentRefused("same_target", nil)
	}
	if from.secret && !to.secret {
		return agentRefused("would_expose", nil) // a secret never becomes a plain value: it would show in the list
	}
	if (move && from.system) || to.system {
		return agentRefused("system_managed", nil)
	}
	op := "copy-value"
	if move {
		op = "move-value"
	}
	run := func(c Core) error {
		nx := &agentCtx{c: c}
		v, err := from.read(c)
		if err != nil {
			return err
		}
		if v == "" {
			return &Error{Status: 409, Code: "empty_source"}
		}
		if err := to.put(nx, v); err != nil {
			return err
		}
		if move {
			return from.put(nx, "")
		}
		return nil
	}
	if v, err := from.read(x.c); err != nil { // refused now, not after the person was asked (a sealed value is never read)
		return refusedErr(err)
	} else if v == "" {
		return agentRefused("empty_source", nil)
	}
	if to.secret && to.filled { // a secret that is there would be replaced: the person decides
		return x.queue(op, to, from.label(), run)
	}
	return x.done(run(x.c))
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
		w["delete"] = true
	}
	return x.done(x.write("m-field", w))
}

func (x *agentCtx) siteOp(op string) agentapi.Response {
	a := x.args
	w := pick(a, "env", keyName, "new_name", keyKind)
	switch op {
	case "site-create":
		w["action"] = "create"
	case "site-update":
		w["action"] = actUpd
	default:
		w["action"] = "delete"
	}
	for _, k := range []string{"connection", "state"} {
		if ahas(a, k) && op != "site-delete" {
			u, found := x.connUUID(as(a, k))
			if !found {
				return agentRefused("not_found", nil)
			}
			w[k] = u
		}
	}
	return x.done(x.write("m-site", withConfirm(w, a)))
}

func (x *agentCtx) productOp(op string) agentapi.Response {
	a := x.args
	w := pick(a, "env", keyName, "new_name", "enabled")
	switch op {
	case "product-create":
		w["action"] = "create"
	case "product-update":
		w["action"] = actUpd
	default:
		w["action"] = "delete"
	}
	if op != "product-delete" {
		if ahas(a, "site") {
			w["site"] = ""
			if name := as(a, "site"); name != "" {
				e := x.env(as(a, "env"))
				if e == nil {
					return agentRefused("no_env", map[string]any{"env": as(a, "env")})
				}
				found := false
				for _, s := range alist(e, "sites") {
					if as(s, keyName) == name {
						w["site"], found = as(s, keyUUID), true
					}
				}
				if !found {
					return agentRefused("not_found", nil)
				}
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
	}
	return x.done(x.write("m-product", withConfirm(w, a)))
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
	out := map[string]any{"scope": scope, "key": r["key"], "filled": as(r, "state") == stSet}
	for _, k := range []string{"visibility", "managed", "description", "changed", "expires", "expiry", "label", "required", "secret", "system", "missing", "imported", "overridden", "active"} {
		if v, found := r[k]; found && v != nil {
			out[k] = v
		}
	}
	if as(r, "visibility") == "plain" && !ab(r, "secret") && as(r, "state") == stSet {
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
