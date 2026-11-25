package desktop

import (
	"encoding/json"
	"errors"
	"sort"
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
	keyKey       = "key"
	keyScope     = "scope"
	visPlain     = "plain"
	keySite      = "site"
	keyState     = "state"
	keyTitle     = "title"
	opSiteCreate = "site-create"
	opStatus     = "status"
	modeEdit     = "edit"
	keyEnv       = "env"
	keyAction    = "action"
	actDelete    = "delete"
)

type agentCtx struct {
	h       *agentHub
	c       Core
	args    map[string]any
	who     string
	peer    string
	changes []agentChange // what the item changes (names old and new), for the dialog
	rec     *agentItem    // the item that is being recorded (nil when it is replayed)
	pkey    string        // the client the rate limit counts: the program that started the command
	nav     map[string]any
}

// agentOps are the names the API knows, in the order "help" lists them.
var agentOps = []string{"help", "structure", "batch-begin", "batch-submit", "batch-status", "batch-discard",
	"var-create", "var-rename", "var-delete", "var-meta", "set-value", "copy-value", "move-value",
	"connection-create", "connection-update", "connection-delete", "field-create", "field-update", "field-delete",
	opSiteCreate, "site-update", "site-delete", "product-create", "product-update", "product-delete",
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

// targetOf names what a request is about: the names it carries, never a value.
func targetOf(args map[string]any) string {
	out := ""
	add := func(prefix string, m map[string]any) {
		for _, k := range []string{keyEnv, keyScope, keyName, keyKey, "new_key", "new_name", keyTitle, "new_title", "connection", keyField, "other", keyKind, keySite, "from", keyState, "visibility"} {
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
	if err := x.loadNav(); err != nil {
		return refusedErr(err)
	}
	if op == "structure" {
		return okData(x.structure(as(x.args, keyEnv)))
	}
	a := x.args
	switch op {
	case "var-create":
		return x.varCreate()
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
		return x.connectionCreate()
	case "connection-update":
		return x.connectionUpdate()
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
		return x.done(x.write("m-env", withAction(pick(a, keyName, "new_name", keyTitle), actUpd)))
	case "env-delete":
		return x.envDelete()
	case "other-create":
		return x.done(x.write("m-other", withAction(pick(a, keyTitle, "expires"), "create")))
	case "other-update", "other-delete":
		o := x.other(as(a, "other"))
		if o == nil {
			return agentRefused("not_found", nil)
		}
		w := map[string]any{keyUUID: as(o, keyUUID), keyAction: actUpd}
		if op == "other-delete" {
			w[keyAction] = actDelete
			if otherFilled(o) { // a secret that is filled goes only after Allow
				uuid, title := as(o, keyUUID), as(a, "other")
				return x.queue(op, "other", title, "", "", func(nx *agentCtx) error {
					if o2 := nx.other(title); o2 == nil || as(o2, keyUUID) != uuid {
						return errGone
					}
					return nx.write("m-other", w)
				})
			}
		} else {
			w[keyTitle] = as(a, "new_title")
			copyIf(w, a, "expires")
			if nt := as(a, "new_title"); nt != "" && nt != as(a, "other") && otherFilled(o) { // a filled secret is renamed only after Allow
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

// otherFilled: an other secret counts as filled with a value, a file or notes.
func otherFilled(o map[string]any) bool {
	return as(o, keyState) == stSet || ab(o, "file") || as(o, "notes") != ""
}

func isSecretRow(r map[string]any) bool { return as(r, "visibility") != visPlain || ab(r, "secret") }

func filledRow(r map[string]any) bool { return as(r, keyState) == stSet }

// secretKeyAnywhere says whether a variable of that name is secret anywhere in the vault (shared, General, a site, a product, or by the description of the
// project): a plain variable of the same name must not shadow it.
// secretByModel says whether the project (or the name rule) makes a variable of that name secret.
func (x *agentCtx) boundName(name string) bool {
	b, can := x.c.(ConnNameBinder)
	return can && b.BoundConnectionName(name)
}

// varExists asks the core whether the key is in exactly that scope, and falls back to the answer of nav.
func (x *agentCtx) varExists(scope, key string) bool {
	if vp, can := x.c.(VarProbe); can {
		return vp.VarExists(scope, key)
	}
	r := x.varRow(scope, key)
	return r != nil && !ab(r, "missing")
}

// envOfScope is the environment a scope belongs to ("" for shared).
func envOfScope(s string) string {
	if p := splitScope(s); len(p) >= 2 && p[0] == keyEnv {
		return p[1]
	}
	return ""
}

// shadowedPlaces lists the places of the same environment that already hold a variable of the key: a new one in another scope of it would override them (or
// they would override it).
func (x *agentCtx) shadowedPlaces(scope, key string) (all []string, secret bool) {
	vp, can := x.c.(VarProbe)
	if !can {
		return nil, false
	}
	env := envOfScope(scope)
	for _, p := range vp.KeyPlaces(key) {
		if p.Scope == "shared" || (p.Scope == scope && !p.Imported) || env == "" || envOfScope(p.Scope) != env {
			continue
		}
		all = append(all, p.Scope)
		secret = secret || p.Secret
	}
	return all, secret
}

func (x *agentCtx) varCreate() agentapi.Response {
	a := x.args
	scope, key := as(a, keyScope), as(a, keyKey)
	if x.varExists(scope, key) {
		return agentRefused("name_exists", map[string]any{keyName: key})
	}
	w := pick(a, keyScope, keyKey, "visibility", "description", "expires")
	w["create_only"] = true
	if x.secretKeyAnywhere(key) { // a plain variable of that name would shadow a secret one: it is made secret, and its value waits for Allow
		if v := as(a, "visibility"); v != "" && rank(v) < 1 {
			if x.secretByModel(key) {
				return agentRefused("no_lowering", nil)
			}
			return agentRefused("shadows_secret", nil)
		}
		if as(a, "visibility") == "" {
			w["visibility"] = "secret"
		}
	}
	shadows, secret := x.shadowedPlaces(scope, key)
	if secret {
		return agentRefused("shadows_secret", nil)
	}
	if len(shadows) > 0 { // it would override a value of the same environment: the person decides
		x.changes = []agentChange{{Field: "shadows", Old: clean(strings.Join(shadows, ", "), 200), New: clean(scope, 200)}}
		return x.queue("var-create", kindVar, key, scope, "", func(nx *agentCtx) error {
			if nx.varExists(scope, key) {
				return &Error{Status: 409, Code: "name_exists"}
			}
			if _, sec := nx.shadowedPlaces(scope, key); sec {
				return &Error{Status: 409, Code: "shadows_secret"}
			}
			return nx.write("m-var", w)
		})
	}
	return x.done(x.write("m-var", w))
}

func (x *agentCtx) secretByModel(key string) bool {
	vd, can := x.c.(VisDefaulter)
	return can && vd.DefaultVisibility(key) != visPlain
}

func (x *agentCtx) secretKeyAnywhere(key string) bool {
	if x.secretByModel(key) {
		return true
	}
	if vp, can := x.c.(VarProbe); can { // the core sees every group, also the ones of site kinds that no site shows
		for _, p := range vp.KeyPlaces(key) {
			if p.Secret {
				return true
			}
		}
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
		if as(o, keyTitle) == title && title != "" {
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
		case p[2] == keySite && len(p) == 4:
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
		return &agentTarget{kind: "other", name: as(m, "other"), uuid: as(o, keyUUID), secret: true, filled: as(o, keyState) == stSet}, nil
	case as(m, "connection") != "":
		cn := x.conn(as(m, "connection"))
		if cn == nil {
			return nil, &Error{Status: 404, Code: "not_found"}
		}
		for _, f := range alist(cn, "fields") {
			if as(f, keyName) == as(m, keyField) {
				return &agentTarget{kind: keyField, name: as(m, "connection"), field: as(m, keyField), uuid: as(cn, keyUUID), secret: ab(f, "secret"), filled: as(f, keyState) == stSet}, nil
			}
		}
		return nil, &Error{Status: 404, Code: "not_found"}
	default:
		r := x.varRow(as(m, keyScope), as(m, keyKey))
		if r == nil {
			return nil, &Error{Status: 404, Code: "not_found"}
		}
		return &agentTarget{kind: kindVar, scope: as(m, keyScope), key: as(m, keyKey), secret: isSecretRow(r) || x.secretKeyAnywhere(as(m, keyKey)), filled: as(r, keyState) == stSet,
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

// queue marks the item as one that needs a close look (the window flags it with the reason) and runs it; fn finds again what the op is about, and refuses
// with "gone" when it is not the same thing. what, where and from are the names the window shows.
func (x *agentCtx) queue(op, kind, what, where, from string, fn func(nx *agentCtx) error) agentapi.Response {
	if x.rec != nil {
		x.rec.sens = append(x.rec.sens, reasonOf(op, kind))
		x.rec.what, x.rec.where, x.rec.from = clean(what, 120), clean(where, 200), clean(from, 200)
		x.rec.changes = append(x.rec.changes, x.changes...)
	}
	nx := &agentCtx{h: x.h, c: x.c}
	if err := nx.loadNav(); err != nil {
		return refusedErr(err)
	}
	return x.done(fn(nx))
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
	if !t.secret && !strings.Contains(value, "${{") { // a plain value that refers to other values is not made at once: what it refers to may be a secret
		return x.done(t.put(x, value))
	}
	if t.system {
		return agentRefused("system_managed", map[string]any{keyKey: t.key})
	}
	saved, args := t.id(), targetArgs(x.args)
	return x.queue("set-value", t.kind, t.what(), t.where(), "", func(nx *agentCtx) error {
		t2, err := nx.target(args)
		if err != nil || t2.id() != saved || t2.system { // deleted and made again as something else while it waited
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

// connectionCreate makes a connection. The name is normalized as the core does (spaces trimmed). A name the project binds, or the first connection of a kind
// some use needs, waits for Allow: the commands that fill an environment link a connection by that name, or the only one of its kind.
func (x *agentCtx) connectionCreate() agentapi.Response {
	a := x.args
	name := strings.TrimSpace(as(a, keyName))
	w := withAction(pick(a, keyKind, "description"), "create")
	w[keyName] = name
	first := true
	for _, c := range alist(x.nav, "connections") {
		first = first && as(c, keyKind) != as(a, keyKind)
	}
	if x.boundName(name) || (first && x.kindNeeded(as(a, keyKind))) {
		return x.queue("connection-create", "connection", name, "", "", func(nx *agentCtx) error { return nx.write("m-connection", w) })
	}
	return x.done(x.write("m-connection", w))
}

func (x *agentCtx) connectionUpdate() agentapi.Response {
	a := x.args
	cn := x.conn(as(a, "connection"))
	if cn == nil {
		return agentRefused("not_found", nil)
	}
	nn := strings.TrimSpace(as(a, "new_name"))
	w := map[string]any{keyUUID: as(cn, keyUUID), keyAction: actUpd, keyName: nn}
	copyIf(w, a, "description")
	if nn != "" && nn != as(a, "connection") && x.boundName(nn) { // a rename to a name the project binds redirects where environments link
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
}

func (x *agentCtx) kindServed(kind string) bool {
	b, can := x.c.(ConnNameBinder)
	return can && b.ConnectionKindServed(kind)
}

func (x *agentCtx) connectionsOfKind(kind string) int {
	n := 0
	for _, c := range alist(x.nav, "connections") {
		if as(c, keyKind) == kind {
			n++
		}
	}
	return n
}

func (x *agentCtx) kindNeeded(kind string) bool {
	b, can := x.c.(ConnNameBinder)
	return can && b.ConnectionKindNeeded(kind)
}

func (x *agentCtx) connectionDelete() agentapi.Response {
	name := as(x.args, "connection")
	cn := x.conn(name)
	if cn == nil {
		return agentRefused("not_found", nil)
	}
	w := map[string]any{keyUUID: as(cn, keyUUID), keyAction: actDelete}
	filledSecret := false
	for _, f := range alist(cn, "fields") {
		filledSecret = filledSecret || (ab(f, "secret") && as(f, keyState) == stSet)
	}
	same := 0
	for _, c := range alist(x.nav, "connections") {
		if as(c, keyKind) == as(cn, keyKind) {
			same++
		}
	}
	lastButOne := same == 2 && x.kindNeeded(as(cn, keyKind)) // the one left would be linked by the commands that fill an environment
	served := x.kindServed(as(cn, keyKind))                  // a program asks for a connection of this kind by name
	if len(alist(cn, "users")) == 0 && !filledSecret && !lastButOne && !served {
		return x.done(x.write("m-connection", w))
	}
	uuid := as(cn, keyUUID)
	return x.queue("connection-delete", "connection", name, "", "", func(nx *agentCtx) error {
		c2 := nx.conn(name)
		if c2 == nil || as(c2, keyUUID) != uuid {
			return errGone
		}
		if (nx.connectionsOfKind(as(c2, keyKind)) == 2 && nx.kindNeeded(as(c2, keyKind))) != lastButOne { // what the person was told is not true any more
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
			if as(r, keyState) == stSet && (as(r, "visibility") != visPlain || ab(r, "secret")) {
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
	w := withAction(pick(a, keyName, keyTitle), "create")
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
		if row != nil && ab(row, "secret") { // a field the kind declares secret is made secret, whatever is asked
			w["secret"] = true
		}
	case "field-update":
		if row == nil || !ab(row, "present") {
			return agentRefused("not_found", nil)
		}
		copyIf(w, a, "secret", "expires") // a field can become secret, never plain
	case "field-delete":
		w[actDelete] = true
		_, declared := row["required"]                                                     // only the fields a kind declares have it
		if row != nil && ((ab(row, "secret") && as(row, keyState) == stSet) || declared) { // a filled secret field, and a field the kind declares, go only after Allow
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
	for _, k := range []string{"connection", keyState} {
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
				if as(p, keySite) == "" {
					return x.queue("site-create", keySite, as(a, keyName), as(a, keyEnv), "", func(nx *agentCtx) error { return nx.write("m-site", w) })
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
	relink := (ahas(a, "connection") && as(w, "connection") != as(cur, "connection")) || (ahas(a, keyState) && as(w, keyState) != as(cur, keyState)) ||
		(as(a, keyKind) != "" && as(a, keyKind) != as(cur, keyKind))
	if relink {
		uuid, env, name := as(cur, keyUUID), as(a, keyEnv), as(a, keyName)
		x.changes = x.siteChanges(cur, w)
		return x.queue("site-update", keySite, name, env, "", func(nx *agentCtx) error {
			if s2 := nx.thing(env, "sites", name); s2 == nil || as(s2, keyUUID) != uuid {
				return errGone
			}
			c := copyMap(w)
			c["confirm"] = true
			return nx.write("m-site", c)
		})
	}
	return x.writeAsk("m-site", w, "site-update", keySite, as(a, keyName), as(a, keyEnv))
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
	if ahas(a, keySite) {
		w[keySite] = ""
		if name := as(a, keySite); name != "" {
			if x.env(as(a, keyEnv)) == nil {
				return agentRefused("no_env", map[string]any{keyEnv: as(a, keyEnv)})
			}
			s := x.thing(as(a, keyEnv), "sites", name)
			if s == nil {
				return agentRefused("not_found", nil)
			}
			w[keySite] = as(s, keyUUID)
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
	relink := (ahas(a, keySite) && as(w, keySite) != as(cur, keySite)) || (ahas(a, "connections") && !sameIDs(w["connections"], cur["connections"]))
	if relink { // another site or other connections change what the product runs with: the person decides
		uuid, env, name := as(cur, keyUUID), as(a, keyEnv), as(a, keyName)
		x.changes = x.productChanges(cur, w)
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

func (x *agentCtx) connNameOf(uuid string) string {
	for _, c := range alist(x.nav, "connections") {
		if as(c, keyUUID) == uuid && uuid != "" {
			return as(c, keyName)
		}
	}
	return ""
}

func (x *agentCtx) siteChanges(cur, w map[string]any) []agentChange {
	var out []agentChange
	for _, k := range []string{"connection", keyState} {
		if _, given := w[k]; given && as(w, k) != as(cur, k) {
			out = append(out, agentChange{Field: k, Old: clean(x.connNameOf(as(cur, k)), 120), New: clean(x.connNameOf(as(w, k)), 120)})
		}
	}
	if k := as(w, keyKind); k != "" && k != as(cur, keyKind) {
		out = append(out, agentChange{Field: keyKind, Old: clean(as(cur, keyKind), 120), New: clean(k, 120)})
	}
	return out
}

func (x *agentCtx) productChanges(cur, w map[string]any) []agentChange {
	var out []agentChange
	siteName := func(env, uuid string) string {
		if e := x.env(env); e != nil {
			for _, s := range alist(e, "sites") {
				if as(s, keyUUID) == uuid && uuid != "" {
					return as(s, keyName)
				}
			}
		}
		return ""
	}
	env := as(x.args, keyEnv)
	if _, given := w[keySite]; given && as(w, keySite) != as(cur, keySite) {
		out = append(out, agentChange{Field: keySite, Old: clean(siteName(env, as(cur, keySite)), 120), New: clean(siteName(env, as(w, keySite)), 120)})
	}
	if v, given := w["connections"]; given && !sameIDs(v, cur["connections"]) {
		names := func(v any) string {
			var s []string
			l, _ := v.([]any)
			for _, u := range l {
				if t, isStr := u.(string); isStr {
					s = append(s, x.connNameOf(t))
				}
			}
			return strings.Join(s, ", ")
		}
		out = append(out, agentChange{Field: "connections", Old: clean(names(cur["connections"]), 200), New: clean(names(v), 200)})
	}
	return out
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
	return x.thingDelete("site-delete", keySite, "sites", "m-site")
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

// ---- the structure: names, states, plain values; never a secret value

func varOut(scope string, r map[string]any) map[string]any {
	out := map[string]any{keyScope: scope, keyKey: r[keyKey], "filled": as(r, keyState) == stSet}
	for _, k := range []string{"visibility", "managed", "description", "changed", "expires", "expiry", "label", "required", "secret", "system", "missing", "imported", "overridden", "active"} {
		if v, found := r[k]; found && v != nil {
			out[k] = v
		}
	}
	if as(r, "visibility") == visPlain && !ab(r, "secret") && as(r, keyState) == stSet {
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
		out = append(out, map[string]any{"rel": f["rel"], keySite: f[keySite], "sealed": f["sealed"], "changed": f["changed"]})
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
			sites = append(sites, map[string]any{keyName: s[keyName], keyKind: s[keyKind], "connection": nameOf(as(s, "connection")), "state_connection": nameOf(as(s, keyState)),
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
			po := map[string]any{keyName: p[keyName], "enabled": p["enabled"], "place": p["place"], keySite: nil, "connections": cs, "variables": varsOut(ps, alist(p, "vars")), "missing": len(alist(p, "missing"))}
			if s := as(p, keySite); s != "" {
				po[keySite] = siteName[s]
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
		envs = append(envs, map[string]any{keyName: en, keyTitle: e[keyTitle], "general": general, "imports": e["imports"], "sites": sites, "products": products, "files": filesOut(alist(e, "file_list"))})
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
			fo := map[string]any{keyName: f[keyName], "label": f["label"], "secret": ab(f, "secret"), "present": ab(f, "present"), "filled": as(f, keyState) == stSet}
			for _, k := range []string{"expires", "expiry"} {
				if v, found := f[k]; found {
					fo[k] = v
				}
			}
			if !ab(f, "secret") && as(f, keyState) == stSet {
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
		other = append(other, map[string]any{keyTitle: o[keyTitle], "filled": as(o, keyState) == stSet, "expires": o["expires"], "expiry": o["expiry"]})
	}
	sort.SliceStable(other, func(i, j int) bool { return as(other[i], keyTitle) < as(other[j], keyTitle) })
	return map[string]any{"read_only": n["read_only"], "environments": envs, "shared": shared, "connections": conns, "other": other}
}

var _ = errors.New
