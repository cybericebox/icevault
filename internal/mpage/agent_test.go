package mpage

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/agentapi"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// The agent API over a throwaway vault: the window (desktop.App) with the real model core, a client on its socket. Every write goes through a batch.

// lockCore is the model core with the Lock the window asks of every core (the window's own wrapper drops the password it holds; here nothing is held).
type lockCore struct{ *Core }

func (lockCore) Lock() {}

type coreUnlocker struct{ c desktop.Core }

func (u coreUnlocker) Open([]byte) (desktop.Core, error) { return u.c, nil }
func (coreUnlocker) Touch() ([]byte, error)              { return nil, nil }
func (coreUnlocker) HasKeyFile() bool                    { return false }

// every secret the fixture holds, and the ones the tests send: none may ever show in an answer or in the journal
var agentSecrets = []string{"gkey-secret-1", "blob-secret-1", "sig-secret-1", "wifi-secret-1", "new-secret-value-77", "other-secret-value-88", "moved-secret-value-99"}

type agentRig struct {
	t      *testing.T
	app    *desktop.App
	core   *Core
	v      *vault.Vault
	dir    string
	events []string
	seen   []string // every answer of the API, as text
}

func newRig(t *testing.T, ttl time.Duration) *agentRig { return newRigGap(t, ttl, -1) }

func newRigGap(t *testing.T, ttl, gap time.Duration) *agentRig {
	t.Helper()
	c, v := newCore(t)
	base, err := os.MkdirTemp("/tmp", "ivag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	r := &agentRig{t: t, core: c, v: v, dir: filepath.Join(base, agentapi.AppDirName)}
	r.app = desktop.New(desktop.Options{Unlocker: coreUnlocker{lockCore{c}}, AgentDir: r.dir, AgentTTL: ttl, AgentGap: gap, SyncEvery: -1,
		Notify: func(event string, _ any) { r.events = append(r.events, event) }})
	return r
}

func (r *agentRig) unlock() {
	r.t.Helper()
	if resp := r.app.Unlock("password", "throwaway-window-pw"); resp.Status != 200 {
		r.t.Fatalf("unlock: %v", resp)
	}
	if resp := r.app.SetMode("edit"); resp.Status != 200 { // the agent's writes need the window in edit mode
		r.t.Fatalf("edit mode: %v", resp)
	}
}

func (r *agentRig) call(op string, args map[string]any) agentapi.Response {
	r.t.Helper()
	resp, err := agentapi.Call(r.dir, agentapi.Request{Op: op, Args: args, Client: "test agent", PID: 4242}, 10*time.Second)
	if err != nil {
		r.t.Fatalf("%s: %v", op, err)
	}
	raw, _ := json.Marshal(resp)
	r.seen = append(r.seen, string(raw))
	return resp
}

func (r *agentRig) begin(title string) string {
	r.t.Helper()
	resp := r.call("batch-begin", map[string]any{"title": title})
	if !resp.OK {
		r.t.Fatalf("batch-begin: %+v", resp)
	}
	return resp.Data.(map[string]any)["id"].(string)
}

func (r *agentRig) item(id, op string, args map[string]any) agentapi.Response {
	r.t.Helper()
	a := map[string]any{"batch": id}
	for k, v := range args {
		a[k] = v
	}
	return r.call(op, a)
}

func (r *agentRig) status(id string) agentapi.Response {
	r.t.Helper()
	return r.call("batch-status", map[string]any{"id": id})
}

// step is one item of a batch.
type step struct {
	op   string
	args map[string]any
}

// batch records the steps in one batch, submits it and answers Apply; it answers the status of the batch (or the refusal of the step that was refused).
func (r *agentRig) batch(steps ...step) agentapi.Response {
	r.t.Helper()
	id := r.begin("test batch")
	for _, s := range steps {
		if resp := r.item(id, s.op, s.args); !resp.OK {
			r.call("batch-discard", map[string]any{"id": id})
			return resp
		}
	}
	if resp := r.call("batch-submit", map[string]any{"id": id}); !resp.OK || resp.State != agentapi.StatePending {
		r.t.Fatalf("batch-submit: %+v", resp)
	}
	r.app.AgentDecide(id, true)
	return r.status(id)
}

func (r *agentRig) ok(op string, args map[string]any) {
	r.t.Helper()
	if resp := r.batch(step{op, args}); !resp.OK || resp.State != agentapi.StateApplied {
		r.t.Fatalf("%s %v: %+v", op, args, resp)
	}
}

func (r *agentRig) okAll(steps ...step) {
	r.t.Helper()
	if resp := r.batch(steps...); !resp.OK || resp.State != agentapi.StateApplied {
		r.t.Fatalf("batch: %+v", resp)
	}
}

// refused: the op is refused when it is recorded (the batch is discarded).
func (r *agentRig) refused(op string, args map[string]any, code string) {
	r.t.Helper()
	id := r.begin("refusal")
	resp := r.item(id, op, args)
	r.call("batch-discard", map[string]any{"id": id})
	if resp.OK || resp.Code != code {
		r.t.Fatalf("%s %v: want refusal %s, got %+v", op, args, code, resp)
	}
}

// sens records the op in a batch and answers the reasons it is flagged with (nil: none); the batch is discarded.
func (r *agentRig) sens(op string, args map[string]any) []string {
	r.t.Helper()
	id := r.begin("sens")
	resp := r.item(id, op, args)
	r.call("batch-discard", map[string]any{"id": id})
	if !resp.OK {
		r.t.Fatalf("%s %v refused: %s", op, args, resp.Code)
	}
	var out []string
	if l, isList := resp.Data.(map[string]any)["sensitive"].([]any); isList {
		for _, x := range l {
			out = append(out, x.(string))
		}
	}
	return out
}

func (r *agentRig) flagged(op string, args map[string]any, reason string) {
	r.t.Helper()
	for _, s := range r.sens(op, args) {
		if s == reason {
			return
		}
	}
	r.t.Fatalf("%s %v is not flagged %q", op, args, reason)
}

func (r *agentRig) notFlagged(op string, args map[string]any) {
	r.t.Helper()
	if s := r.sens(op, args); len(s) > 0 {
		r.t.Fatalf("%s %v is flagged %v", op, args, s)
	}
}

func (r *agentRig) reveal(name, key string) string {
	r.t.Helper()
	v, err := r.core.Reveal("m", name, "", key)
	if err != nil {
		r.t.Fatalf("reveal %s %s: %v", name, key, err)
	}
	return v
}

func (r *agentRig) connUUID(name string) string { return r.core.Model().Connection(name).UUID }

// mutate changes the model of the window's core and saves it (a batch works on a copy of the saved vault).
func (r *agentRig) mutate(fn func(m *vmodel.Vault)) {
	r.t.Helper()
	fn(r.core.Model())
	if err := r.core.commit(); err != nil {
		r.t.Fatal(err)
	}
}

// onDisk reads the vault file again, as another program would.
func (r *agentRig) onDisk() *vmodel.Vault {
	r.t.Helper()
	v, err := vault.Open(r.v.Path(), vault.Credentials{Password: []byte("pw-throwaway-1")})
	if err != nil {
		r.t.Fatal(err)
	}
	defer v.Close()
	m, err := vmodel.Load(v)
	if err != nil {
		r.t.Fatal(err)
	}
	return m
}

// noSecrets scans every answer the API gave and the journal (the window's and the file) for the secrets.
func (r *agentRig) noSecrets() {
	r.t.Helper()
	all := strings.Join(r.seen, "\n")
	j, _ := json.Marshal(r.app.AgentJournal())
	all += string(j)
	if b, err := os.ReadFile(filepath.Join(r.dir, agentapi.JournalName)); err == nil {
		all += string(b)
	}
	pend, _ := json.Marshal(r.app.AgentPending())
	all += string(pend)
	for _, s := range agentSecrets {
		if strings.Contains(all, s) {
			r.t.Fatalf("a secret value (%s...) is in an answer or in the journal", s[:6])
		}
	}
}

func TestAgentSocketOnlyWhileUnlockedAndPrivate(t *testing.T) {
	r := newRig(t, 0)
	if _, err := agentapi.Call(r.dir, agentapi.Request{Op: "help"}, time.Second); err == nil {
		t.Fatal("a locked window answered")
	}
	r.unlock()
	sock := agentapi.SocketPath(r.dir)
	st, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", st.Mode())
	}
	if d, _ := os.Stat(r.dir); d.Mode().Perm()&0o077 != 0 {
		t.Fatalf("folder mode %v", d.Mode())
	}
	if resp := r.call("help", nil); !resp.OK || resp.Data == nil {
		t.Fatal("help is empty")
	}
	r.app.Lock()
	if _, err := os.Lstat(sock); err == nil {
		t.Fatal("the socket stays after the lock")
	}
	if _, err := agentapi.Call(r.dir, agentapi.Request{Op: "structure"}, time.Second); err == nil {
		t.Fatal("a locked window answered")
	}
	r.unlock()
	if resp := r.call("structure", nil); !resp.OK {
		t.Fatal("unlocking again did not bring it back")
	}
	r.app.Close()
	if _, err := os.Lstat(sock); err == nil {
		t.Fatal("the socket stays after closing")
	}
}

func TestAgentRefusesAFolderOthersCanReachOrWriteInto(t *testing.T) {
	for _, mode := range []os.FileMode{0o777, 0o750} {
		r := newRig(t, 0)
		if err := os.MkdirAll(r.dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(r.dir, mode); err != nil {
			t.Fatal(err)
		}
		r.unlock()
		if _, err := os.Lstat(agentapi.SocketPath(r.dir)); err == nil {
			t.Fatalf("a socket was made in a folder of mode %v", mode)
		}
		if _, err := agentapi.Call(r.dir, agentapi.Request{Op: "help"}, time.Second); err == nil {
			t.Fatal("the client used an open folder")
		}
		j, _ := json.Marshal(r.app.AgentJournal())
		if !strings.Contains(string(j), "agent_dir") || strings.Contains(string(j), "\"active\":true") {
			t.Fatalf("the window does not say the API is off: %s", j)
		}
	}
}

func TestAgentStructureHasNamesAndPlainValuesOnly(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	resp := r.call("structure", nil)
	raw, _ := json.Marshal(resp.Data)
	for _, want := range []string{"prod", "main", "portal", "GCP", "Blob store", "credentials", "wifi", "CONTACT_ADDRESS", "COOKIE_KEY", "hello@example.net", "example.org", "lumen-prod"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the structure lacks %q", want)
		}
	}
	if one := r.call("structure", map[string]any{"env": "nope"}); strings.Contains(mustJSON(one.Data), "PUBLIC_HOST") {
		t.Error("the env filter does not filter")
	}
	r.noSecrets()
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestAgentOnlyReadsWorkWithoutABatch(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	for _, op := range []string{"var-create", "set-value", "env-delete", "connection-create", "other-delete"} {
		if resp := r.call(op, map[string]any{"scope": "shared", "key": "X", "name": "x", "value": "v"}); resp.OK || resp.Code != "batch_required" {
			t.Fatalf("%s without a batch: %+v", op, resp)
		}
	}
	if resp := r.call("var-create", map[string]any{"batch": "nope", "scope": "shared", "key": "X"}); resp.OK || resp.Code != "not_found" {
		t.Fatalf("%+v", resp)
	}
	if len(r.core.Model().Shared) != 1 || r.core.Model().Env("prod") == nil {
		t.Fatal("something changed")
	}
	for _, op := range []string{"help", "structure"} {
		if !r.call(op, nil).OK {
			t.Fatalf("%s is refused", op)
		}
	}
}

func TestAgentBatchIsAppliedWholeAndSaved(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	id := r.begin("make a mail relay")
	steps := []step{
		{"connection-create", map[string]any{"name": "Mail relay", "kind": "s3"}},
		{"field-create", map[string]any{"connection": "Mail relay", "field": "region"}},
		{"set-value", map[string]any{"connection": "Mail relay", "field": "region", "value": "eu-1"}},
		{"var-create", map[string]any{"scope": "env/prod/general", "key": "RELAY_NOTE", "visibility": "plain"}},
		{"set-value", map[string]any{"scope": "env/prod/general", "key": "RELAY_NOTE", "value": "ready"}},
		{"set-value", map[string]any{"other": "wifi", "value": "new-secret-value-77"}},
	}
	for i, s := range steps { // later items depend on earlier ones: the connection made first is there for the field
		if resp := r.item(id, s.op, s.args); !resp.OK {
			t.Fatalf("item %d %s: %+v", i+1, s.op, resp)
		}
	}
	if r.core.Model().Connection("Mail relay") != nil || r.status(id).State != agentapi.StateOpen {
		t.Fatal("a recorded item changed the vault")
	}
	if resp := r.call("batch-submit", map[string]any{"id": id}); resp.State != agentapi.StatePending {
		t.Fatalf("%+v", resp)
	}
	if r.core.Model().Connection("Mail relay") != nil || r.onDisk().Connection("Mail relay") != nil {
		t.Fatal("a batch that waits changed the vault")
	}
	pend := mustJSON(r.app.AgentPending())
	for _, want := range []string{"make a mail relay", "connection-create", "set-value", "secret_write", "\"id\":\"" + id, "pid " + strconv.Itoa(os.Getpid())} {
		if !strings.Contains(pend, want) {
			t.Errorf("the dialog data lacks %q: %s", want, pend)
		}
	}
	if d := r.app.AgentDecide(id, true); d.Status != 200 {
		t.Fatalf("apply: %+v", d)
	}
	st := r.status(id)
	if st.State != agentapi.StateApplied || !strings.Contains(mustJSON(st.Data), "\"result\":\"ok\"") {
		t.Fatalf("%+v", st)
	}
	for _, m := range []*vmodel.Vault{r.core.Model(), r.onDisk()} { // in the window and in the file
		if m.Connection("Mail relay") == nil || m.Connection("Mail relay").Field("region").Value != "eu-1" || m.Other[0].Value != "new-secret-value-77" {
			t.Fatal("the batch is not all there")
		}
	}
	r.noSecrets()
}

func TestAgentFailingItemSavesNothing(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "WILL_VANISH", "visibility": "plain"})
	id := r.begin("two changes")
	r.item(id, "var-create", map[string]any{"scope": "env/prod/general", "key": "FIRST_OF_TWO", "visibility": "plain"})
	if resp := r.item(id, "var-delete", map[string]any{"scope": "env/prod/general", "key": "WILL_VANISH"}); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	r.call("batch-submit", map[string]any{"id": id})
	// while it waits, the second target is deleted by someone else
	if _, err := r.core.Write("m-var", map[string]any{"scope": "env/prod/general", "key": "WILL_VANISH", "delete": true}); err != nil {
		t.Fatal(err)
	}
	d := r.app.AgentDecide(id, true)
	if d.Status != 409 || !strings.Contains(mustJSON(d.Data), "batch_failed") {
		t.Fatalf("%+v", d)
	}
	st := r.status(id)
	if st.State != agentapi.StateFailed || !strings.Contains(mustJSON(st.Data), "failed: not_found") || !strings.Contains(mustJSON(st.Data), "\"index\":2") {
		t.Fatalf("%+v", st)
	}
	for _, m := range []*vmodel.Vault{r.core.Model(), r.onDisk()} {
		for _, v := range m.Env("prod").General {
			if v.Key == "FIRST_OF_TWO" {
				t.Fatal("the first item stayed although the second failed")
			}
		}
	}
}

func TestAgentTargetThatChangedWhileWaitingIsFoundOutAtApply(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "AIM_SPOT", "visibility": "secret"})
	id := r.begin("aimed")
	if resp := r.item(id, "set-value", map[string]any{"scope": "env/prod/general", "key": "AIM_SPOT", "value": "new-secret-value-77"}); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	r.call("batch-submit", map[string]any{"id": id})
	// the place is deleted and made again as a plain one
	if _, err := r.core.Write("m-var", map[string]any{"scope": "env/prod/general", "key": "AIM_SPOT", "delete": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.core.Write("m-var", map[string]any{"scope": "env/prod/general", "key": "AIM_SPOT", "visibility": "plain"}); err != nil {
		t.Fatal(err)
	}
	if d := r.app.AgentDecide(id, true); d.Status == 200 {
		t.Fatal("a batch that was re-aimed was applied")
	}
	if got := r.reveal("env/prod/general", "AIM_SPOT"); got != "" {
		t.Fatalf("a value landed in the plain place: %q", got)
	}
	r.noSecrets()
}

func TestAgentRefusalsAreMadeWhenAnItemIsRecorded(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.okAll(step{"var-create", map[string]any{"scope": "env/prod/general", "key": "PLAIN_SPOT", "visibility": "plain"}},
		step{"var-create", map[string]any{"scope": "env/prod/general", "key": "LEVEL_UP", "visibility": "secret"}},
		step{"var-create", map[string]any{"scope": "env/prod/general", "key": "OTHER_SPOT", "visibility": "secret"}})
	r.refused("copy-value", map[string]any{"from": map[string]any{"connection": "GCP", "field": "credentials"}, "to": map[string]any{"scope": "env/prod/general", "key": "PLAIN_SPOT"}}, "would_expose")
	r.refused("copy-value", map[string]any{"from": map[string]any{"scope": "env/prod/product/portal", "key": "COOKIE_KEY"}, "to": map[string]any{"scope": "env/prod/general", "key": "LEVEL_UP"}}, "sealed")
	r.refused("copy-value", map[string]any{"from": map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"}, "to": map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"}}, "same_target")
	r.refused("copy-value", map[string]any{"from": map[string]any{"scope": "env/prod/general", "key": "LEVEL_UP"}, "to": map[string]any{"scope": "env/prod/general", "key": "OTHER_SPOT"}}, "empty_source")
	r.refused("set-value", map[string]any{"scope": "env/prod/product/portal", "key": "COOKIE_KEY", "value": "other-secret-value-88"}, "system_managed")
	r.refused("set-value", map[string]any{"scope": "shared", "key": "NOPE", "value": "x"}, "not_found")
	r.refused("set-value", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"}, "bad_request")
	r.refused("var-meta", map[string]any{"scope": "env/prod/product/portal", "key": "COOKIE_KEY", "visibility": "secret"}, "no_lowering")
	r.refused("var-meta", map[string]any{"scope": "env/prod/general", "key": "LEVEL_UP", "visibility": "plain"}, "no_lowering")
	r.refused("var-meta", map[string]any{"scope": "env/prod/general", "key": "LEVEL_UP", "visibility": "loud"}, "bad_request")
	r.refused("var-create", map[string]any{"scope": "env/prod/general", "key": "PLAIN_SPOT"}, "name_exists")
	r.refused("var-create", map[string]any{"scope": "env/prod/general", "key": "DB_PASSWORD", "visibility": "plain"}, "no_lowering")
	r.refused("var-create", map[string]any{"scope": "env/prod/general", "key": "COOKIE_KEY"}, "shadows_secret")
	r.refused("var-rename", map[string]any{"scope": "env/prod/general", "key": "PLAIN_SPOT", "new_key": "DB_PASSWORD"}, "shadows_secret")
	r.refused("field-update", map[string]any{"connection": "GCP", "field": "credentials", "secret": false}, "no_lowering")
	r.refused("field-update", map[string]any{"connection": "GCP", "field": "credentials", "secret": "no"}, "bad_request")
	r.refused("field-create", map[string]any{"connection": "GCP", "field": "credentials", "secret": false}, "no_lowering")
	r.refused("connection-create", map[string]any{"name": "GCP", "kind": "google"}, "name_exists")
	r.refused("site-create", map[string]any{"env": "prod", "name": "x", "kind": "google-cluster", "connection": "Nope"}, "not_found")
	r.refused("other-delete", map[string]any{"other": "nope"}, "not_found")
	r.refused("nonsense", nil, "unknown_op")
	if raw := mustJSON(r.call("structure", nil).Data); strings.Contains(raw, "gkey-secret-1") {
		t.Fatal("the structure shows a secret")
	}
	if !r.core.Model().Connection("GCP").Field("credentials").Secret {
		t.Fatal("a field was lowered")
	}
	r.noSecrets()
}

func TestAgentWhatNeedsACloseLookIsFlaggedWithItsReason(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.okAll(step{"var-create", map[string]any{"scope": "env/prod/general", "key": "KEEP_SECRET", "visibility": "secret"}},
		step{"set-value", map[string]any{"scope": "env/prod/general", "key": "KEEP_SECRET", "value": "new-secret-value-77"}},
		step{"var-create", map[string]any{"scope": "env/prod/general", "key": "FILLED_PLAIN", "visibility": "plain"}},
		step{"set-value", map[string]any{"scope": "env/prod/general", "key": "FILLED_PLAIN", "value": "text"}})
	for _, c := range []struct {
		op     string
		args   map[string]any
		reason string
	}{
		{"set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"}, "secret_write"},
		{"set-value", map[string]any{"scope": "env/prod/general", "key": "FILLED_PLAIN", "value": "${{ self.PUBLIC_HOST }}"}, "secret_write"},
		{"var-delete", map[string]any{"scope": "env/prod/general", "key": "KEEP_SECRET"}, "delete_var"},
		{"var-delete", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"}, "delete_var"},
		{"var-rename", map[string]any{"scope": "env/prod/general", "key": "FILLED_PLAIN", "new_key": "FILLED_PLAIN_2"}, "rename_secret"},
		{"var-rename", map[string]any{"scope": "env/prod/general", "key": "KEEP_SECRET", "new_key": "KEEP_SECRET_2"}, "rename_secret"},
		{"var-create", map[string]any{"scope": "env/prod/site/main", "key": "PUBLIC_HOST"}, "shadows"},
		{"var-create", map[string]any{"scope": "env/prod/general", "key": "CONTACT_ADDRESS"}, "shadows"},
		{"env-delete", map[string]any{"name": "prod"}, "delete_env"},
		{"env-create", map[string]any{"name": "copy1", "from": "prod"}, "env_copy"},
		{"site-delete", map[string]any{"env": "prod", "name": "main"}, "delete_site"},
		{"product-delete", map[string]any{"env": "prod", "name": "portal"}, "delete_product"},
		{"connection-delete", map[string]any{"connection": "GCP"}, "delete_connection"},
		{"field-delete", map[string]any{"connection": "GCP", "field": "credentials"}, "delete_field"},
		{"field-delete", map[string]any{"connection": "GCP", "field": "project"}, "delete_field"},
		{"other-delete", map[string]any{"other": "wifi"}, "delete_other"},
		{"other-update", map[string]any{"other": "wifi", "new_title": "wifi 2"}, "rename_secret"},
		{"site-update", map[string]any{"env": "prod", "name": "main", "connection": ""}, "relink"},
		{"site-update", map[string]any{"env": "prod", "name": "main", "kind": "compose"}, "relink"},
		{"product-update", map[string]any{"env": "prod", "name": "portal", "connections": []any{}}, "relink"},
		{"product-update", map[string]any{"env": "prod", "name": "portal", "site": ""}, "relink"},
		{"connection-update", map[string]any{"connection": "GCP", "new_name": "GCP 2"}, "sensitive"}, // used: the core asks
	} {
		if c.op == "connection-update" { // the core's own "are you sure" is flagged
			if s := r.sens(c.op, c.args); len(s) == 0 {
				t.Fatalf("%s %v is not flagged", c.op, c.args)
			}
			continue
		}
		r.flagged(c.op, c.args, c.reason)
	}
	// at once: plain, unused, empty
	r.notFlagged("var-create", map[string]any{"scope": "env/prod/general", "key": "BRAND_NEW", "visibility": "plain"})
	r.notFlagged("connection-create", map[string]any{"name": "Spare", "kind": "s3"})
	r.notFlagged("set-value", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS", "value": "plain@example.net"})
	r.notFlagged("env-create", map[string]any{"name": "bare"})
	r.notFlagged("site-update", map[string]any{"env": "prod", "name": "main", "connection": "GCP"})
	if m := r.core.Model(); m.Env("prod") == nil || len(m.Shared) != 1 || m.Connection("Spare") != nil {
		t.Fatal("recording changed the vault")
	}
}

func TestAgentSiteCreateThatLinksProductsAndRelinkDialog(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.okAll(step{"product-update", map[string]any{"env": "prod", "name": "portal", "site": ""}})
	r.flagged("site-create", map[string]any{"env": "prod", "name": "extra", "kind": "google-cluster"}, "links_products")
	r.okAll(step{"connection-create", map[string]any{"name": "Other cloud", "kind": "google"}})
	id := r.begin("relink")
	r.item(id, "site-update", map[string]any{"env": "prod", "name": "main", "connection": "Other cloud"})
	r.call("batch-submit", map[string]any{"id": id})
	raw := mustJSON(r.app.AgentPending())
	for _, want := range []string{"\"field\":\"connection\"", "\"old\":\"GCP\"", "\"new\":\"Other cloud\"", "relink"} {
		if !strings.Contains(raw, want) {
			t.Errorf("the dialog data lacks %s: %s", want, raw)
		}
	}
	r.app.AgentDecide(id, false)
	if r.core.Model().Env("prod").Site("main").Connection.Name != "GCP" {
		t.Fatal("a rejected relink was applied")
	}
}

func TestAgentVarCreateSeesHiddenGroupsAndShadows(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.mutate(func(m *vmodel.Vault) {
		m.Env("prod").Product("portal").Sub["compose"] = []*vmodel.Var{{Key: "HIDDEN_PLAIN", Value: "x", Vis: vmodel.VisPlain}, {Key: "HIDDEN_VALUE", Value: "hidden-value", Vis: vmodel.VisSecret}}
	})
	r.refused("var-create", map[string]any{"scope": "env/prod/product/portal/compose", "key": "HIDDEN_PLAIN"}, "name_exists") // the group no site shows
	r.refused("var-create", map[string]any{"scope": "env/prod/general", "key": "HIDDEN_VALUE", "visibility": "plain"}, "shadows_secret")
	r.refused("var-create", map[string]any{"scope": "env/prod/site/main", "key": "HIDDEN_VALUE"}, "shadows_secret")
	r.okAll(step{"env-create", map[string]any{"name": "bare"}})
	r.notFlagged("var-create", map[string]any{"scope": "env/bare/general", "key": "X_PLAIN"}) // another environment is not touched
	r.mutate(func(m *vmodel.Vault) {
		m.Env("prod").Products = append(m.Env("prod").Products, &vmodel.Product{Name: "hidden", Enabled: true, Sub: map[string][]*vmodel.Var{"compose": {{Key: "HID_KEY", Value: "hidden-value", Vis: vmodel.VisSecret}}}})
	})
	r.okAll(step{"env-create", map[string]any{"name": "subby"}})
	r.mutate(func(m *vmodel.Vault) {
		e := m.Env("subby")
		e.Products = append(e.Products, &vmodel.Product{Name: "hidden", Enabled: true, Sub: map[string][]*vmodel.Var{"compose": {{Key: "HID_KEY", Value: "hidden-value", Vis: vmodel.VisSecret}}}})
	})
	r.flagged("env-create", map[string]any{"name": "subby2", "from": "subby"}, "env_copy") // a secret in a group no site shows
}

func TestAgentCoreNeverChangesAnExistingVariableOnCreateOnly(t *testing.T) {
	r := newRig(t, 0)
	_, err := r.core.Write("m-var", map[string]any{"scope": "env/prod/general", "key": "PUBLIC_HOST", "visibility": "secret", "create_only": true})
	if code(err) != "name_exists" {
		t.Fatalf("%v", err)
	}
	for _, v := range r.core.Model().Env("prod").General {
		if v.Key == "PUBLIC_HOST" && v.Vis != vmodel.VisPlain {
			t.Fatal("the visibility was changed")
		}
	}
}

func TestAgentConnectionNamesTheProjectBindsAndNeededKinds(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	bound, kind := "", ""
	count := map[string]int{}
	for _, c := range r.core.Model().Connections {
		count[c.Kind]++
	}
	one, none := "", ""
	for _, p := range r.core.d.Products {
		for _, u := range p.Connections {
			if u.Name != "" && r.core.BoundConnectionName(u.Name) && r.core.Model().Connection(u.Name) == nil {
				bound = u.Name
			}
			if kind == "" && r.core.Model().Connection(u.Kind) == nil && u.Kind != "" {
				kind = u.Kind
			}
			if count[u.Kind] == 1 && one == "" {
				one = u.Kind
			}
			if count[u.Kind] == 0 && none == "" {
				none = u.Kind
			}
		}
	}
	if bound == "" || kind == "" || one == "" || none == "" {
		t.Fatalf("the example lacks what the test needs: %q %q %q %q", bound, kind, one, none)
	}
	r.flagged("connection-update", map[string]any{"connection": "Blob store", "new_name": "  " + strings.ToUpper(bound) + "  "}, "bound_name") // trimmed, other case
	r.flagged("connection-create", map[string]any{"name": bound, "kind": "s3"}, "bound_name")
	r.flagged("connection-create", map[string]any{"name": kind, "kind": "s3"}, "bound_name") // a kind id
	r.flagged("connection-create", map[string]any{"name": "First of its kind", "kind": none}, "bound_name")
	r.okAll(step{"connection-create", map[string]any{"name": "Second of its kind", "kind": one}})
	r.flagged("connection-delete", map[string]any{"connection": "Second of its kind"}, "delete_connection") // leaves exactly one
}

func TestAgentSiteKindUsesCountAsBoundAndNeeded(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	used, have := map[string]bool{}, map[string]bool{}
	for _, p := range r.core.d.Products {
		for _, u := range p.Connections {
			used[u.Kind] = true
		}
	}
	for _, c := range r.core.Model().Connections {
		have[c.Kind] = true
	}
	kind := ""
	for _, k := range r.core.kinds().Kinds() {
		if !used[k.ID] && !have[k.ID] {
			kind = k.ID
		}
	}
	if kind == "" {
		t.Fatal("every kind is used or present")
	}
	r.core.d.SiteKinds["only-here"] = project.SiteKind{Connection: &project.ConnectionUse{Kind: kind, Name: "Bound by a site kind", ServeAs: "served-by-site"}}
	if !r.core.BoundConnectionName("bound by a SITE kind") || !r.core.BoundConnectionName("served-by-site") || !r.core.ConnectionKindNeeded(kind) || !r.core.ConnectionKindServed(kind) {
		t.Fatal("a use of a site kind is not seen")
	}
	r.flagged("connection-create", map[string]any{"name": "Plain name", "kind": kind}, "bound_name")
	r.flagged("connection-update", map[string]any{"connection": "Blob store", "new_name": "Bound by a site kind"}, "bound_name")
	r.okAll(step{"connection-create", map[string]any{"name": "Bound by a site kind", "kind": kind}}) // the batch is what the person approves
}

func TestAgentCopyAndMoveStayInsideTheVault(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	cred := "conn/" + r.connUUID("GCP")
	r.okAll(step{"var-create", map[string]any{"scope": "env/prod/general", "key": "SECRET_SPOT", "visibility": "secret"}},
		step{"var-create", map[string]any{"scope": "env/prod/general", "key": "MOVED_SPOT", "visibility": "secret"}},
		step{"var-create", map[string]any{"scope": "env/prod/general", "key": "PLAIN_SPOT", "visibility": "plain"}})
	r.okAll(
		step{"copy-value", map[string]any{"from": map[string]any{"connection": "GCP", "field": "credentials"}, "to": map[string]any{"scope": "env/prod/general", "key": "SECRET_SPOT"}}},
		step{"move-value", map[string]any{"from": map[string]any{"scope": "env/prod/general", "key": "SECRET_SPOT"}, "to": map[string]any{"scope": "env/prod/general", "key": "MOVED_SPOT"}}},
		step{"copy-value", map[string]any{"from": map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"}, "to": map[string]any{"scope": "env/prod/general", "key": "PLAIN_SPOT"}}})
	if r.reveal("env/prod/general", "MOVED_SPOT") != "gkey-secret-1" || r.reveal("env/prod/general", "SECRET_SPOT") != "" || r.reveal(cred, "credentials") != "gkey-secret-1" ||
		r.reveal("env/prod/general", "PLAIN_SPOT") != "hello@example.net" {
		t.Fatal("copy and move did not do what they say")
	}
	r.flagged("copy-value", map[string]any{"from": map[string]any{"connection": "Blob store", "field": "secret_access_key"}, "to": map[string]any{"connection": "GCP", "field": "credentials"}}, "secret_write")
	r.noSecrets()
}

func TestAgentRejectLeavesTheVaultAsItIs(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	id := r.begin("to reject")
	r.item(id, "set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"})
	r.call("batch-submit", map[string]any{"id": id})
	if d := r.app.AgentDecide(id, false); d.Status != 200 {
		t.Fatalf("%+v", d)
	}
	if st := r.status(id); st.State != agentapi.StateRejected {
		t.Fatalf("%+v", st)
	}
	if r.reveal("other/"+r.core.Model().Other[0].UUID, "") != "wifi-secret-1" {
		t.Fatal("Reject changed the secret")
	}
	if d := r.app.AgentDecide(id, true); d.Status == 200 {
		t.Fatal("a rejected batch was applied")
	}
	r.noSecrets()
}

func TestAgentApplyFailsInViewMode(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	id := r.begin("view")
	r.item(id, "var-create", map[string]any{"scope": "shared", "key": "VIEWONLY"})
	r.call("batch-submit", map[string]any{"id": id})
	open := r.begin("still open")
	r.app.SetMode("view")
	if d := r.app.AgentDecide(id, true); d.Status == 200 {
		t.Fatal("Apply wrote in view mode")
	}
	if st := r.status(id); st.State != agentapi.StateFailed || st.Code != "view_mode" {
		t.Fatalf("%+v", st)
	}
	if resp := r.item(open, "var-create", map[string]any{"scope": "shared", "key": "VIEWONLY2"}); resp.OK || resp.Code != "view_mode" { // recording needs edit mode too
		t.Fatalf("%+v", resp)
	}
	if resp := r.call("batch-begin", map[string]any{"title": "x"}); resp.OK || resp.Code != "view_mode" {
		t.Fatalf("%+v", resp)
	}
	if !r.call("structure", nil).OK {
		t.Fatal("reads work in view mode")
	}
	if len(r.core.Model().Shared) != 1 {
		t.Fatal("a write got through in view mode")
	}
}

func TestAgentBatchesExpire(t *testing.T) {
	r := newRig(t, 150*time.Millisecond)
	r.unlock()
	draft := r.begin("draft")
	sent := r.begin("sent")
	r.item(sent, "var-create", map[string]any{"scope": "shared", "key": "LATE_ONE"})
	r.call("batch-submit", map[string]any{"id": sent})
	time.Sleep(500 * time.Millisecond)
	if resp := r.item(draft, "var-create", map[string]any{"scope": "shared", "key": "X"}); resp.OK {
		t.Fatal("an expired draft took an item")
	}
	for _, id := range []string{draft, sent} {
		if st := r.status(id); st.State != agentapi.StateExpired {
			t.Fatalf("%s: %+v", id, st)
		}
	}
	if d := r.app.AgentDecide(sent, true); d.Status == 200 {
		t.Fatal("an expired batch was applied")
	}
	if len(r.core.Model().Shared) != 1 {
		t.Fatal("an expired batch changed the vault")
	}
}

func TestAgentLockDropsBatchesAndConnections(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	id := r.begin("lost")
	r.item(id, "set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"})
	r.call("batch-submit", map[string]any{"id": id})
	conn, err := net.Dial("unix", agentapi.SocketPath(r.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(100 * time.Millisecond)
	r.app.Lock()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("an open connection survived the lock")
	}
	r.unlock()
	if d := r.app.AgentDecide(id, true); d.Status == 200 {
		t.Fatal("a batch survived the lock")
	}
	if r.reveal("other/"+r.core.Model().Other[0].UUID, "") != "wifi-secret-1" {
		t.Fatal("a batch survived the lock and changed the secret")
	}
}

func TestAgentLimits(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	a, b := r.begin("a"), r.begin("b")
	r.begin("c")
	r.begin("d")
	if resp := r.call("batch-begin", map[string]any{"title": "e"}); resp.OK || resp.Code != "too_many_batches" {
		t.Fatalf("%+v", resp)
	}
	if resp := r.call("batch-submit", map[string]any{"id": a}); resp.OK || resp.Code != "empty_batch" {
		t.Fatalf("%+v", resp)
	}
	for i := 0; i < 50; i++ {
		if resp := r.item(a, "var-create", map[string]any{"scope": "shared", "key": "ITEM_" + strconv.Itoa(i), "visibility": "plain"}); !resp.OK {
			t.Fatalf("item %d: %+v", i, resp)
		}
	}
	if resp := r.item(a, "var-create", map[string]any{"scope": "shared", "key": "ONE_TOO_MANY"}); resp.OK || resp.Code != "batch_full" {
		t.Fatalf("%+v", resp)
	}
	r.item(b, "var-create", map[string]any{"scope": "shared", "key": "OTHER"})
	if resp := r.call("batch-submit", map[string]any{"id": a}); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if resp := r.call("batch-submit", map[string]any{"id": b}); resp.OK || resp.Code != "batch_pending" {
		t.Fatalf("only one batch waits at a time: %+v", resp)
	}
	r.app.AgentDecide(a, true)
	if n := len(r.core.Model().Shared); n != 51 {
		t.Fatalf("the full batch was not applied: %d", n)
	}
	if resp := r.call("batch-submit", map[string]any{"id": b}); !resp.OK {
		t.Fatalf("the next batch can wait now: %+v", resp)
	}
}

func TestAgentSubmittedBatchesAreRateLimited(t *testing.T) {
	r := newRigGap(t, 0, 400*time.Millisecond)
	r.unlock()
	a, b := r.begin("a"), r.begin("b")
	r.item(a, "var-create", map[string]any{"scope": "shared", "key": "ONE"})
	r.item(b, "var-create", map[string]any{"scope": "shared", "key": "TWO"})
	if resp := r.call("batch-submit", map[string]any{"id": a}); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	r.app.AgentDecide(a, false)
	if resp := r.call("batch-submit", map[string]any{"id": b}); resp.OK || resp.Code != "rate_limited" {
		t.Fatalf("%+v", resp)
	}
	time.Sleep(500 * time.Millisecond)
	if resp := r.call("batch-submit", map[string]any{"id": b}); !resp.OK {
		t.Fatalf("%+v", resp)
	}
}

func TestAgentJournalHasTheBatchAndItsItemsWithoutValues(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.okAll(step{"set-value", map[string]any{"connection": "GCP", "field": "credentials", "value": "moved-secret-value-99"}},
		step{"var-create", map[string]any{"scope": "env/prod/general", "key": "JOURNALED", "visibility": "plain"}})
	b, err := os.ReadFile(filepath.Join(r.dir, agentapi.JournalName))
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(r.dir, agentapi.JournalName)); st.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode %v", st.Mode())
	}
	for _, want := range []string{"batch-begin", "batch-submit", "\"op\":\"batch\"", "applied", "2 items", "set-value", "connection=GCP", "field=credentials", "JOURNALED", "\"result\":\"ok\"", "test agent (pid " + strconv.Itoa(os.Getpid()) + ")"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the journal file lacks %q:\n%s", want, b)
		}
	}
	r.app.Lock()
	r.app.Unlock("password", "x")
	if j := mustJSON(r.app.AgentJournal()); !strings.Contains(j, "batch-begin") {
		t.Errorf("the journal panel lost the earlier entries: %s", j)
	}
	r.noSecrets()
}

func TestAgentJournalFileIsCleanedWhenRead(t *testing.T) {
	r := newRig(t, 0)
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 5000)
	line, _ := json.Marshal(map[string]string{"time": long, "op": "set-value\u001b[31m", "target": long, "who": "a\u202eb" + long, "result": long})
	if err := os.WriteFile(filepath.Join(r.dir, agentapi.JournalName), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	r.unlock()
	raw := mustJSON(r.app.AgentJournal())
	if len(raw) > 1500 || strings.Contains(raw, "\\u001b") || strings.Contains(raw, "\\u202e") {
		t.Fatalf("the journal panel got the file as it was: %d bytes", len(raw))
	}
}

func TestAgentShowsThatANameHasNonLatinLetters(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.okAll(step{"other-create", map[string]any{"title": "w\u0456fi"}}) // a Cyrillic i
	id := r.begin("look-alike")
	r.item(id, "set-value", map[string]any{"other": "w\u0456fi", "value": "other-secret-value-88"})
	r.call("batch-submit", map[string]any{"id": id})
	if raw := mustJSON(r.app.AgentPending()); !strings.Contains(raw, "\"nonlatin\":true") {
		t.Fatalf("%s", raw)
	}
}

func TestAgentBoundaryOfAFilledOtherAndDeclaredFields(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.okAll(step{"other-create", map[string]any{"title": "only notes"}}, step{"connection-create", map[string]any{"name": "Declared", "kind": "s3"}},
		step{"field-create", map[string]any{"connection": "Declared", "field": "secret_access_key"}})
	if f := r.core.Model().Connection("Declared").Field("secret_access_key"); f == nil || !f.Secret {
		t.Fatal("a field the kind declares secret was made plain")
	}
	r.mutate(func(m *vmodel.Vault) {
		for _, o := range m.Other {
			if o.Title == "only notes" {
				o.Notes = "a note"
			}
		}
	})
	r.flagged("other-delete", map[string]any{"other": "only notes"}, "delete_other")
}

func TestAgentAdoptRefusesWhenThePasswordChangedAfterTheCopy(t *testing.T) {
	r := newRig(t, 0)
	sc, release, err := r.core.BatchScratch()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := r.v.SetPassword([]byte("another-throwaway-pw-2")); err != nil {
		t.Fatal(err)
	}
	if err := r.core.BatchAdopt(sc); code(err) != "changed" {
		t.Fatalf("a copy made before a password change was adopted: %v", err)
	}
	v, err := vault.Open(r.v.Path(), vault.Credentials{Password: []byte("another-throwaway-pw-2")}) // the new password still opens it
	if err != nil {
		t.Fatalf("the password change was undone: %v", err)
	}
	v.Close()
}

func TestAgentDialogShowsEveryArgumentThatIsUsed(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.okAll(step{"var-create", map[string]any{"scope": "env/prod/general", "key": "SHOWN_PLAIN", "visibility": "plain"}})
	id := r.begin("everything")
	long := strings.Repeat("x", 300)
	for _, s := range []step{
		{"var-create", map[string]any{"scope": "env/prod/general", "key": "SHOWN_TWO", "visibility": "plain", "description": "made by test", "expires": "2099-01-01"}},
		{"set-value", map[string]any{"scope": "env/prod/general", "key": "SHOWN_PLAIN", "value": long}},
		{"set-value", map[string]any{"scope": "env/prod/general", "key": "SHOWN_TWO", "value": "${{ self.PUBLIC_HOST }}"}},
		{"set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"}},
		{"product-update", map[string]any{"env": "prod", "name": "portal", "enabled": false, "connections": []any{"Blob store"}}},
	} {
		if resp := r.item(id, s.op, s.args); !resp.OK {
			t.Fatalf("%s: %+v", s.op, resp)
		}
	}
	r.call("batch-submit", map[string]any{"id": id})
	raw := mustJSON(r.app.AgentPending())
	for _, want := range []string{"\"field\":\"description\"", "made by test", "\"field\":\"expires\"", "2099-01-01", "\"field\":\"visibility\"", "…", "${{ self.PUBLIC_HOST }}",
		"\"hidden\":true", "\"field\":\"enabled\"", "\"value\":\"false\"", "\"field\":\"connections\"", "Blob store", "contributors", "test agent (pid"} {
		if !strings.Contains(raw, want) {
			t.Errorf("the dialog data lacks %q", want)
		}
	}
	if strings.Contains(raw, long) {
		t.Error("a long value is shown whole")
	}
	r.noSecrets()
}

func TestAgentItemSeenDifferentlyAtApplyFails(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.okAll(step{"connection-create", map[string]any{"name": "Other cloud", "kind": "google"}}, step{"connection-create", map[string]any{"name": "Third cloud", "kind": "google"}})
	id := r.begin("relink")
	r.item(id, "site-update", map[string]any{"env": "prod", "name": "main", "connection": "Other cloud"})
	r.call("batch-submit", map[string]any{"id": id})
	// what the dialog said (GCP to Other cloud) is not true any more: the site was relinked meanwhile
	m := r.core.Model()
	s := m.Env("prod").Site("main")
	s.Connection = m.Connection("Third cloud")
	if err := r.core.commit(); err != nil {
		t.Fatal(err)
	}
	if d := r.app.AgentDecide(id, true); d.Status == 200 {
		t.Fatal("an item whose old value changed was applied")
	}
	if r.core.Model().Env("prod").Site("main").Connection.Name != "Third cloud" {
		t.Fatal("the vault changed")
	}
}

func TestAgentSweepsOldCopiesOnly(t *testing.T) {
	old, err := os.MkdirTemp("", "icevault-batch-")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := os.MkdirTemp("", "icevault-batch-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(fresh)
	when := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, when, when); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, 0)
	r.unlock()
	if _, err := os.Stat(old); err == nil {
		os.RemoveAll(old)
		t.Fatal("a left-over copy was not swept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("a fresh copy was swept")
	}
}

func TestAgentBatchesAreNotBegunTooOften(t *testing.T) {
	r := newRigGap(t, 0, 10*time.Second)
	r.unlock()
	r.begin("one")
	if resp := r.call("batch-begin", map[string]any{"title": "two"}); resp.OK || resp.Code != "rate_limited" {
		t.Fatalf("%+v", resp)
	}
}

func TestAgentNonLatinClientNameIsMarked(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	call := func(op string, args map[string]any) agentapi.Response {
		resp, err := agentapi.Call(r.dir, agentapi.Request{Op: op, Args: args, Client: "\u0430gent"}, 10*time.Second) // a Cyrillic a
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	id := call("batch-begin", map[string]any{"title": "t"}).Data.(map[string]any)["id"].(string)
	call("var-create", map[string]any{"batch": id, "scope": "shared", "key": "ABC"})
	call("batch-submit", map[string]any{"id": id})
	if raw := mustJSON(r.app.AgentPending()); !strings.Contains(raw, "\"nonlatin\":true") {
		t.Fatalf("%s", raw)
	}
}

func TestAgentSubmitKeepsTheBatchPastTheDeadlineOfTheDraft(t *testing.T) {
	r := newRig(t, 2*time.Second)
	r.unlock()
	id := r.begin("late")
	r.item(id, "var-create", map[string]any{"scope": "shared", "key": "LATE_ONE", "visibility": "plain"})
	time.Sleep(1200 * time.Millisecond)
	r.call("batch-submit", map[string]any{"id": id})
	time.Sleep(1500 * time.Millisecond) // past the deadline of the draft, before the deadline of the batch
	if st := r.status(id); st.State != agentapi.StatePending {
		t.Fatalf("the timer of the draft expired the batch: %+v", st)
	}
}
