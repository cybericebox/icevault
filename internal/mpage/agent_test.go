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
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// The agent API over a throwaway vault: the window (desktop.App) with the real model core, a client on its socket.

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
	resp, err := agentapi.Call(r.dir, agentapi.Request{Op: op, Args: args, Client: "test agent", PID: 4242}, 5*time.Second)
	if err != nil {
		r.t.Fatalf("%s: %v", op, err)
	}
	raw, _ := json.Marshal(resp)
	r.seen = append(r.seen, string(raw))
	return resp
}

func (r *agentRig) ok(op string, args map[string]any) agentapi.Response {
	r.t.Helper()
	resp := r.call(op, args)
	if !resp.OK {
		r.t.Fatalf("%s %v refused: %s %v", op, args, resp.Code, resp.Params)
	}
	return resp
}

func (r *agentRig) refused(op string, args map[string]any, code string) {
	r.t.Helper()
	resp := r.call(op, args)
	if resp.OK || resp.Code != code {
		r.t.Fatalf("%s %v: want refusal %s, got %+v", op, args, code, resp)
	}
}

// allow runs an op that waits for the person and answers Allow.
func (r *agentRig) allow(op string, args map[string]any) {
	r.t.Helper()
	resp := r.call(op, args)
	if !resp.OK || resp.State != agentapi.StatePending {
		r.t.Fatalf("%s %v must wait for the window: %+v", op, args, resp)
	}
	if d := r.app.AgentDecide(resp.ID, true); d.Status != 200 {
		r.t.Fatalf("%s: allow: %+v", op, d)
	}
	if st := r.status(resp.ID); st.State != agentapi.StateAllowed {
		r.t.Fatalf("%s: %+v", op, st)
	}
}

func (r *agentRig) status(id string) agentapi.Response {
	return r.ok("status", map[string]any{"id": id})
}

func (r *agentRig) reveal(name, key string) string {
	r.t.Helper()
	v, err := r.core.Reveal("m", name, "", key)
	if err != nil {
		r.t.Fatalf("reveal %s %s: %v", name, key, err)
	}
	return v
}

func (r *agentRig) connUUID(name string) string {
	return r.core.Model().Connection(name).UUID
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
	if resp := r.ok("help", nil); resp.Data == nil {
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
	r.ok("structure", nil) // unlocking again brings it back
	r.app.Close()
	if _, err := os.Lstat(sock); err == nil {
		t.Fatal("the socket stays after closing")
	}
}

func TestAgentRefusesAFolderOthersCanWrite(t *testing.T) {
	r := newRig(t, 0)
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(r.dir, 0o777); err != nil {
		t.Fatal(err)
	}
	r.unlock()
	if _, err := os.Lstat(agentapi.SocketPath(r.dir)); err == nil {
		t.Fatal("a socket was made in a folder others can write into")
	}
	if _, err := agentapi.Call(r.dir, agentapi.Request{Op: "help"}, time.Second); err == nil {
		t.Fatal("the client used an open folder")
	}
	j, _ := json.Marshal(r.app.AgentJournal())
	if !strings.Contains(string(j), "agent_dir") || strings.Contains(string(j), "\"active\":true") {
		t.Fatalf("the window does not say the API is off: %s", j)
	}
}

func TestAgentStructureHasNamesAndPlainValuesOnly(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	resp := r.ok("structure", nil)
	raw, _ := json.Marshal(resp.Data)
	text := string(raw)
	for _, want := range []string{"prod", "main", "portal", "GCP", "Blob store", "credentials", "wifi", "CONTACT_ADDRESS", "COOKIE_KEY", "hello@example.net", "example.org", "lumen-prod"} {
		if !strings.Contains(text, want) {
			t.Errorf("the structure lacks %q", want)
		}
	}
	var s struct {
		Connections []struct {
			Name   string
			Fields []map[string]any
		}
	}
	_ = json.Unmarshal(raw, &s)
	for _, c := range s.Connections {
		for _, f := range c.Fields {
			if f["secret"] == true && f["value"] != nil {
				t.Errorf("secret field %s.%v has a value", c.Name, f["name"])
			}
		}
	}
	one := r.ok("structure", map[string]any{"env": "nope"})
	if raw, _ := json.Marshal(one.Data); strings.Contains(string(raw), "PUBLIC_HOST") {
		t.Error("the env filter does not filter")
	}
	r.noSecrets()
}

func TestAgentStructureOps(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	// variables: create, set a plain value, rename, label and expiry, delete (to the recycle bin)
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "AGENT_NOTE", "visibility": "plain", "description": "made by an agent"})
	r.refused("var-create", map[string]any{"scope": "env/prod/general", "key": "AGENT_NOTE"}, "name_exists")
	r.ok("set-value", map[string]any{"scope": "env/prod/general", "key": "AGENT_NOTE", "value": "plain text"})
	if got := r.reveal("env/prod/general", "AGENT_NOTE"); got != "plain text" {
		t.Fatalf("plain value not set: %q", got)
	}
	r.ok("var-meta", map[string]any{"scope": "env/prod/general", "key": "AGENT_NOTE", "description": "a label", "expires": "2099-01-02"})
	r.allow("var-rename", map[string]any{"scope": "env/prod/general", "key": "AGENT_NOTE", "new_key": "AGENT_NOTE_2"}) // it holds a value: it waits
	r.refused("var-rename", map[string]any{"scope": "env/prod/general", "key": "AGENT_NOTE", "new_key": "AGENT_NOTE_3"}, "not_found")
	st, _ := json.Marshal(r.ok("structure", nil).Data)
	if !strings.Contains(string(st), "AGENT_NOTE_2") || !strings.Contains(string(st), "a label") || !strings.Contains(string(st), "plain text") || !strings.Contains(string(st), "2099-01-02") {
		t.Fatalf("the structure lacks the new variable: %s", st)
	}
	r.ok("var-delete", map[string]any{"scope": "env/prod/general", "key": "AGENT_NOTE_2"})
	if x := r.core.Model().Env("prod"); x != nil {
		for _, v := range x.General {
			if v.Key == "AGENT_NOTE_2" {
				t.Fatal("deleted variable is still in the model")
			}
		}
	}
	bin, err := r.v.Entries(vault.RecycleBinName)
	if err != nil || len(bin) == 0 {
		t.Fatalf("the deleted variable is not in the recycle bin: %v %d", err, len(bin))
	}
	// connections and fields
	r.ok("connection-create", map[string]any{"name": "Mail relay", "kind": "s3", "description": "x"})
	r.refused("connection-create", map[string]any{"name": "Mail relay", "kind": "s3"}, "name_exists")
	r.ok("field-create", map[string]any{"connection": "Mail relay", "field": "region"})
	r.ok("set-value", map[string]any{"connection": "Mail relay", "field": "region", "value": "eu-1"})
	r.ok("field-update", map[string]any{"connection": "Mail relay", "field": "region", "expires": "2099-05-05"})
	r.ok("connection-update", map[string]any{"connection": "Mail relay", "new_name": "Mail relay 2"})
	// sites, products, links
	r.ok("site-create", map[string]any{"env": "prod", "name": "edge", "kind": "google-cluster", "connection": "GCP"})
	r.ok("product-create", map[string]any{"env": "prod", "name": "wiki", "site": "edge", "connections": []any{"Blob store"}})
	r.ok("product-update", map[string]any{"env": "prod", "name": "wiki", "new_name": "wiki2", "enabled": false})
	r.allow("product-delete", map[string]any{"env": "prod", "name": "wiki2"})
	r.ok("site-update", map[string]any{"env": "prod", "name": "edge", "new_name": "edge2"})
	r.allow("site-delete", map[string]any{"env": "prod", "name": "edge2"})
	r.refused("site-create", map[string]any{"env": "prod", "name": "x", "kind": "google-cluster", "connection": "Nope"}, "not_found")
	r.ok("field-delete", map[string]any{"connection": "Mail relay 2", "field": "region"})
	r.ok("connection-delete", map[string]any{"connection": "Mail relay 2"})
	// environments
	r.allow("env-create", map[string]any{"name": "stage", "from": "prod", "title": "Stage"}) // prod holds secrets: a copy of it waits
	r.ok("env-update", map[string]any{"name": "stage", "new_name": "stage2"})
	r.allow("env-delete", map[string]any{"name": "stage2", "confirm": true})
	// other secrets
	r.ok("other-create", map[string]any{"title": "gate code"})
	r.ok("other-update", map[string]any{"other": "gate code", "new_title": "gate code 2"})
	r.ok("other-delete", map[string]any{"other": "gate code 2"})
	r.refused("other-delete", map[string]any{"other": "gate code 2"}, "not_found")
	r.refused("nonsense", nil, "unknown_op")
	// the vault on disk holds what the window holds (Save ran)
	if _, err := vault.Open(r.v.Path(), vault.Credentials{Password: []byte("pw-throwaway-1")}); err != nil {
		t.Fatalf("the saved vault does not open: %v", err)
	}
	r.noSecrets()
}

func TestAgentVisibilityOnlyGoesUp(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.refused("var-meta", map[string]any{"scope": "env/prod/product/portal", "key": "COOKIE_KEY", "visibility": "secret"}, "no_lowering") // sealed never lowers
	r.refused("var-meta", map[string]any{"scope": "env/prod/product/portal", "key": "COOKIE_KEY", "visibility": "plain"}, "no_lowering")
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "LEVEL_UP", "visibility": "secret"})
	r.refused("var-meta", map[string]any{"scope": "env/prod/general", "key": "LEVEL_UP", "visibility": "plain"}, "no_lowering")
	r.ok("var-meta", map[string]any{"scope": "env/prod/general", "key": "LEVEL_UP", "visibility": "sealed"})
	r.refused("var-meta", map[string]any{"scope": "env/prod/general", "key": "LEVEL_UP", "visibility": "secret"}, "no_lowering")
	r.refused("var-meta", map[string]any{"scope": "env/prod/general", "key": "LEVEL_UP", "visibility": "loud"}, "bad_request")
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "RISING"})
	r.ok("set-value", map[string]any{"scope": "env/prod/general", "key": "RISING", "value": "was plain"})
	r.ok("var-meta", map[string]any{"scope": "env/prod/general", "key": "RISING", "visibility": "secret"})
	if raw, _ := json.Marshal(r.ok("structure", nil).Data); strings.Contains(string(raw), "was plain") {
		t.Fatal("a variable made secret still shows its value")
	}
}

func TestAgentSecretWriteWaitsForTheWindow(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	set := map[string]any{"connection": "GCP", "field": "credentials", "value": "new-secret-value-77"}
	first := r.call("set-value", set)
	if !first.OK || first.State != agentapi.StatePending || first.ID == "" {
		t.Fatalf("a secret write must wait: %+v", first)
	}
	if got := r.reveal("conn/"+r.connUUID("GCP"), "credentials"); got != "gkey-secret-1" {
		t.Fatalf("the secret changed before the person said Allow: %q", got)
	}
	if st := r.status(first.ID); st.State != agentapi.StatePending {
		t.Fatalf("status %+v", st)
	}
	// the window shows what, where and who; never the value
	pend, _ := json.Marshal(r.app.AgentPending())
	for _, want := range []string{"credentials", "GCP", "test agent", "set-value", first.ID} {
		if !strings.Contains(string(pend), want) {
			t.Errorf("the pending list lacks %q: %s", want, pend)
		}
	}
	if !contains(r.events, desktop.EventAgentPending) {
		t.Error("the page was not told")
	}
	if resp := r.app.AgentDecide(first.ID, true); resp.Status != 200 {
		t.Fatalf("allow: %+v", resp)
	}
	if st := r.status(first.ID); st.State != agentapi.StateAllowed {
		t.Fatalf("after Allow: %+v", st)
	}
	if got := r.reveal("conn/"+r.connUUID("GCP"), "credentials"); got != "new-secret-value-77" {
		t.Fatalf("Allow did not set the value: %q", got)
	}
	if resp := r.app.AgentDecide(first.ID, true); resp.Status == 200 {
		t.Fatal("a request was allowed twice")
	}
	// Deny leaves it
	second := r.call("set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"})
	if second.State != agentapi.StatePending {
		t.Fatalf("%+v", second)
	}
	r.app.AgentDecide(second.ID, false)
	if st := r.status(second.ID); st.State != agentapi.StateDenied {
		t.Fatalf("after Deny: %+v", st)
	}
	if got := r.reveal("other/"+r.core.Model().Other[0].UUID, ""); got != "wifi-secret-1" {
		t.Fatalf("Deny changed the secret: %q", got)
	}
	// a secret variable waits too, and the sealed one is system-managed and refused
	third := r.call("set-value", map[string]any{"scope": "env/prod/product/portal", "key": "COOKIE_KEY", "value": "other-secret-value-88"})
	if third.OK {
		t.Fatalf("a sealed system variable took a value: %+v", third)
	}
	// the journal knows all of it, by names
	j, _ := json.Marshal(r.app.AgentJournal())
	for _, want := range []string{"set-value", "allowed", "denied", "pending", "GCP"} {
		if !strings.Contains(string(j), want) {
			t.Errorf("the journal lacks %q", want)
		}
	}
	r.noSecrets()
}

func TestAgentPendingExpiresAndDiesWithTheLock(t *testing.T) {
	r := newRig(t, 80*time.Millisecond)
	r.unlock()
	a := r.call("set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"})
	time.Sleep(250 * time.Millisecond)
	if st := r.status(a.ID); st.State != agentapi.StateExpired {
		t.Fatalf("not expired: %+v", st)
	}
	if resp := r.app.AgentDecide(a.ID, true); resp.Status == 200 {
		t.Fatal("an expired request was allowed")
	}
	if got := r.reveal("other/"+r.core.Model().Other[0].UUID, ""); got != "wifi-secret-1" {
		t.Fatalf("an expired request changed the secret")
	}
	r2 := newRig(t, 0)
	r2.unlock()
	b := r2.call("set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"})
	r2.app.Lock()
	r2.unlock()
	if resp := r2.app.AgentDecide(b.ID, true); resp.Status == 200 {
		t.Fatal("a request survived the lock")
	}
	if got := r2.reveal("other/"+r2.core.Model().Other[0].UUID, ""); got != "wifi-secret-1" {
		t.Fatal("a request survived the lock and changed the secret")
	}
	r.noSecrets()
	r2.noSecrets()
}

func TestAgentCopyAndMoveStayInsideTheVault(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	cred := "conn/" + r.connUUID("GCP")
	// a secret never lands in a plain place: it would show in the list
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "PLAIN_SPOT", "visibility": "plain"})
	r.refused("copy-value", map[string]any{"from": map[string]any{"connection": "GCP", "field": "credentials"}, "to": map[string]any{"scope": "env/prod/general", "key": "PLAIN_SPOT"}}, "would_expose")
	// a secret into an empty secret place: at once, and the value is not in the answer
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "SECRET_SPOT", "visibility": "secret"})
	r.allow("copy-value", map[string]any{"from": map[string]any{"connection": "GCP", "field": "credentials"}, "to": map[string]any{"scope": "env/prod/general", "key": "SECRET_SPOT"}})
	if r.reveal("env/prod/general", "SECRET_SPOT") != "gkey-secret-1" || r.reveal(cred, "credentials") != "gkey-secret-1" {
		t.Fatal("copy")
	}
	// move: the source is emptied
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "MOVED_SPOT", "visibility": "secret"})
	r.allow("move-value", map[string]any{"from": map[string]any{"scope": "env/prod/general", "key": "SECRET_SPOT"}, "to": map[string]any{"scope": "env/prod/general", "key": "MOVED_SPOT"}})
	if r.reveal("env/prod/general", "MOVED_SPOT") != "gkey-secret-1" || r.reveal("env/prod/general", "SECRET_SPOT") != "" {
		t.Fatal("move did not move")
	}
	// plain to plain, plain to secret
	r.ok("copy-value", map[string]any{"from": map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"}, "to": map[string]any{"scope": "env/prod/general", "key": "PLAIN_SPOT"}})
	if r.reveal("env/prod/general", "PLAIN_SPOT") != "hello@example.net" {
		t.Fatal("plain copy")
	}
	// replacing a filled secret waits for the window
	pend := r.call("copy-value", map[string]any{"from": map[string]any{"connection": "Blob store", "field": "secret_access_key"}, "to": map[string]any{"connection": "GCP", "field": "credentials"}})
	if pend.State != agentapi.StatePending {
		t.Fatalf("overwrite of a filled secret must wait: %+v", pend)
	}
	if r.reveal(cred, "credentials") != "gkey-secret-1" {
		t.Fatal("overwritten before Allow")
	}
	r.app.AgentDecide(pend.ID, true)
	if r.reveal(cred, "credentials") != "blob-secret-1" {
		t.Fatal("Allow did not copy")
	}
	// a sealed value is never moved, an empty source is refused, the same place is refused
	r.refused("copy-value", map[string]any{"from": map[string]any{"scope": "env/prod/product/portal", "key": "COOKIE_KEY"}, "to": map[string]any{"scope": "env/prod/general", "key": "MOVED_SPOT"}}, "sealed")
	r.refused("copy-value", map[string]any{"from": map[string]any{"scope": "env/prod/general", "key": "SECRET_SPOT"}, "to": map[string]any{"scope": "env/prod/general", "key": "MOVED_SPOT"}}, "empty_source")
	r.refused("copy-value", map[string]any{"from": map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"}, "to": map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"}}, "same_target")
	r.noSecrets()
}

func TestAgentSetPlainValueOnlyWherePlain(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("set-value", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS", "value": "ops@example.net"})
	r.ok("set-value", map[string]any{"connection": "GCP", "field": "project", "value": "lumen-stage"})
	if r.reveal("shared", "CONTACT_ADDRESS") != "ops@example.net" || r.reveal("conn/"+r.connUUID("GCP"), "project") != "lumen-stage" {
		t.Fatal("plain values not set")
	}
	r.refused("set-value", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"}, "bad_request") // no value
	r.refused("set-value", map[string]any{"scope": "shared", "key": "NOPE", "value": "x"}, "not_found")
	r.refused("set-value", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS", "value": "a\nb"}, "line_break")
	if n := len(r.core.Model().Shared); n != 1 {
		t.Fatalf("shared has %d entries", n)
	}
}

func TestAgentJournalIsKeptInAFileWithoutValues(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("structure", nil)
	r.refused("set-value", map[string]any{"scope": "shared", "key": "NOPE", "value": "moved-secret-value-99"}, "not_found")
	p := r.call("set-value", map[string]any{"connection": "GCP", "field": "credentials", "value": "moved-secret-value-99"})
	r.app.AgentDecide(p.ID, true)
	b, err := os.ReadFile(filepath.Join(r.dir, agentapi.JournalName))
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(r.dir, agentapi.JournalName)); st.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode %v", st.Mode())
	}
	for _, want := range []string{"structure", "set-value", "connection=GCP", "field=credentials", "allowed", "refused: not_found", "test agent (pid " + strconv.Itoa(os.Getpid()) + ")"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the journal file lacks %q:\n%s", want, b)
		}
	}
	// a second window run reads the earlier entries
	r.app.Lock()
	h := r.app
	h.Unlock("password", "x")
	if j, _ := json.Marshal(h.AgentJournal()); !strings.Contains(string(j), "structure") {
		t.Errorf("the journal panel lost the earlier entries: %s", j)
	}
	r.noSecrets()
}

func TestAgentWritesNeedEditMode(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.app.SetMode("view")
	r.refused("var-create", map[string]any{"scope": "shared", "key": "VIEWONLY"}, "view_mode")
	r.refused("set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"}, "view_mode")
	r.ok("structure", nil) // reads work
	r.ok("help", nil)
	if len(r.core.Model().Shared) != 1 {
		t.Fatal("a write got through in view mode")
	}
	r.app.SetMode("edit")
	r.ok("var-create", map[string]any{"scope": "shared", "key": "EDITOK"})
}

func TestAgentCannotLowerASecretField(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.refused("field-update", map[string]any{"connection": "GCP", "field": "credentials", "secret": false}, "no_lowering")
	r.refused("field-update", map[string]any{"connection": "GCP", "field": "credentials", "secret": "no"}, "bad_request")
	r.refused("field-create", map[string]any{"connection": "GCP", "field": "credentials", "secret": false}, "no_lowering")
	r.ok("field-update", map[string]any{"connection": "GCP", "field": "credentials", "secret": true})
	if raw, _ := json.Marshal(r.ok("structure", nil).Data); strings.Contains(string(raw), "gkey-secret-1") {
		t.Fatal("the structure shows a secret field")
	}
	if !r.core.Model().Connection("GCP").Field("credentials").Secret {
		t.Fatal("the field was lowered")
	}
	r.noSecrets()
}

func TestAgentQueuedRequestIsNotReaimed(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "AIM_SPOT", "visibility": "secret"})
	set := r.call("set-value", map[string]any{"scope": "env/prod/general", "key": "AIM_SPOT", "value": "new-secret-value-77"})
	cp := r.call("copy-value", map[string]any{"from": map[string]any{"connection": "GCP", "field": "credentials"}, "to": map[string]any{"scope": "env/prod/general", "key": "AIM_SPOT"}})
	if set.State != agentapi.StatePending || cp.State != agentapi.StatePending {
		t.Fatalf("%+v %+v", set, cp)
	}
	// while they wait, the place is deleted and made again as a plain one
	r.ok("var-delete", map[string]any{"scope": "env/prod/general", "key": "AIM_SPOT"})
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "AIM_SPOT", "visibility": "plain"})
	for _, id := range []string{set.ID, cp.ID} {
		if d := r.app.AgentDecide(id, true); d.Status == 200 {
			t.Fatalf("a re-aimed request was applied: %+v", d)
		}
		if st := r.status(id); st.State != agentapi.StateFailed || st.Code != "gone" {
			t.Fatalf("%+v", st)
		}
	}
	if got := r.reveal("env/prod/general", "AIM_SPOT"); got != "" {
		t.Fatalf("a value landed in the plain place: %q", got)
	}
	r.noSecrets()
}

func TestAgentEveryWriteIntoASecretNeedsAllow(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	// a plain value into an empty secret place
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "EMPTY_SECRET", "visibility": "secret"})
	r.ok("set-value", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS", "value": "ops@example.net"})
	p := r.call("copy-value", map[string]any{"from": map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"}, "to": map[string]any{"scope": "env/prod/general", "key": "EMPTY_SECRET"}})
	if p.State != agentapi.StatePending || r.reveal("env/prod/general", "EMPTY_SECRET") != "" {
		t.Fatalf("a copy into an empty secret did not wait: %+v", p)
	}
	// a move that empties a secret
	m := r.call("move-value", map[string]any{"from": map[string]any{"connection": "Blob store", "field": "secret_access_key"}, "to": map[string]any{"scope": "env/prod/general", "key": "EMPTY_SECRET"}})
	if m.State != agentapi.StatePending || r.reveal("conn/"+r.connUUID("Blob store"), "secret_access_key") != "blob-secret-1" {
		t.Fatalf("a move out of a secret did not wait: %+v", m)
	}
	r.app.AgentDecide(p.ID, false)
	r.app.AgentDecide(m.ID, false)
	// a copy of an environment that holds secrets waits; an empty one is copied at once
	c := r.call("env-create", map[string]any{"name": "copy1", "from": "prod"})
	if c.State != agentapi.StatePending || r.core.Model().Env("copy1") != nil {
		t.Fatalf("%+v", c)
	}
	r.app.AgentDecide(c.ID, false)
	r.ok("env-create", map[string]any{"name": "bare"})
	r.ok("env-create", map[string]any{"name": "bare2", "from": "bare"})
	r.noSecrets()
}

func TestAgentDeletesWaitForAllow(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	for _, c := range []struct {
		op   string
		args map[string]any
	}{
		{"env-delete", map[string]any{"name": "prod", "confirm": true}},
		{"site-delete", map[string]any{"env": "prod", "name": "main", "confirm": true}},
		{"product-delete", map[string]any{"env": "prod", "name": "portal", "confirm": true}},
		{"connection-delete", map[string]any{"connection": "GCP", "confirm": true}}, // used by a site
	} {
		p := r.call(c.op, c.args)
		if p.State != agentapi.StatePending {
			t.Fatalf("%s did not wait: %+v", c.op, p)
		}
		r.app.AgentDecide(p.ID, false)
	}
	m := r.core.Model()
	if m.Env("prod") == nil || m.Env("prod").Site("main") == nil || m.Env("prod").Product("portal") == nil || m.Connection("GCP") == nil {
		t.Fatal("something was deleted without Allow")
	}
	r.ok("connection-create", map[string]any{"name": "Spare", "kind": "s3"})
	r.ok("connection-delete", map[string]any{"connection": "Spare"}) // nothing uses it: at once
	r.allow("connection-delete", map[string]any{"connection": "Blob store"})
	if r.core.Model().Connection("Blob store") != nil {
		t.Fatal("Allow did not delete")
	}
}

func TestAgentPendingIsCappedAndShowsTheRealPeer(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	for i := 0; i < 4; i++ {
		if p := r.call("set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"}); p.State != agentapi.StatePending {
			t.Fatalf("%d: %+v", i, p)
		}
	}
	r.refused("set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"}, "too_many_pending")
	pend, _ := json.Marshal(r.app.AgentPending())
	if !strings.Contains(string(pend), "pid "+strconv.Itoa(os.Getpid())) || !strings.Contains(string(pend), "\"peer\":\"") || strings.Contains(string(pend), "pid 4242") {
		t.Fatalf("the pending list does not name the real peer: %s", pend)
	}
	r.noSecrets()
}

func TestAgentFolderMustBeExactly0700(t *testing.T) {
	r := newRig(t, 0)
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(r.dir, 0o750); err != nil {
		t.Fatal(err)
	}
	r.unlock()
	if _, err := os.Lstat(agentapi.SocketPath(r.dir)); err == nil {
		t.Fatal("a socket was made in a folder open to the group")
	}
}

func TestAgentLockDropsConnectionsAndPending(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
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
}

func TestAgentDeletesOfFilledSecretsWaitAndConfirmIsNeverForwarded(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	pending := func(op string, args map[string]any) agentapi.Response {
		t.Helper()
		p := r.call(op, args)
		if p.State != agentapi.StatePending {
			t.Fatalf("%s %v did not wait: %+v", op, args, p)
		}
		return p
	}
	// a filled secret: variable, field, other secret, a connection that holds one
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "KEEP_SECRET", "visibility": "secret"})
	r.allow("set-value", map[string]any{"scope": "env/prod/general", "key": "KEEP_SECRET", "value": "new-secret-value-77"})
	r.app.AgentDecide(pending("var-delete", map[string]any{"scope": "env/prod/general", "key": "KEEP_SECRET", "confirm": true}).ID, false)
	if r.reveal("env/prod/general", "KEEP_SECRET") != "new-secret-value-77" {
		t.Fatal("a filled secret variable was deleted without Allow")
	}
	r.app.AgentDecide(pending("field-delete", map[string]any{"connection": "GCP", "field": "credentials"}).ID, false)
	r.app.AgentDecide(pending("other-delete", map[string]any{"other": "wifi"}).ID, false)
	r.ok("connection-create", map[string]any{"name": "Holds one", "kind": "s3"})
	r.ok("field-create", map[string]any{"connection": "Holds one", "field": "secret_access_key", "secret": true})
	r.allow("set-value", map[string]any{"connection": "Holds one", "field": "secret_access_key", "value": "other-secret-value-88"})
	r.app.AgentDecide(pending("connection-delete", map[string]any{"connection": "Holds one"}).ID, false)
	if r.core.Model().Connection("GCP").Field("credentials") == nil || len(r.core.Model().Other) == 0 || r.core.Model().Connection("Holds one") == nil {
		t.Fatal("something was deleted without Allow")
	}
	// the agent's "confirm" opens nothing: what something uses waits for the window
	r.app.AgentDecide(pending("var-delete", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS", "confirm": true}).ID, false)
	r.app.AgentDecide(pending("connection-update", map[string]any{"connection": "GCP", "new_name": "GCP 2", "confirm": true}).ID, false)
	if r.core.Model().Connection("GCP") == nil || len(r.core.Model().Shared) != 1 {
		t.Fatal("a used thing changed on the agent's own confirm")
	}
	r.allow("var-delete", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS"})
	if len(r.core.Model().Shared) != 0 {
		t.Fatal("Allow did not delete the used shared value")
	}
	// plain and unused: at once
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "PLAIN_GONE", "visibility": "plain"})
	r.ok("var-delete", map[string]any{"scope": "env/prod/general", "key": "PLAIN_GONE"})
	r.noSecrets()
}

func TestAgentRelinkAndKindChangesWait(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	for _, c := range []struct {
		op   string
		args map[string]any
	}{
		{"site-update", map[string]any{"env": "prod", "name": "main", "connection": ""}},
		{"site-update", map[string]any{"env": "prod", "name": "main", "kind": "compose"}},
		{"product-update", map[string]any{"env": "prod", "name": "portal", "connections": []any{}}},
		{"product-update", map[string]any{"env": "prod", "name": "portal", "site": ""}},
	} {
		p := r.call(c.op, c.args)
		if p.State != agentapi.StatePending {
			t.Fatalf("%s %v did not wait: %+v", c.op, c.args, p)
		}
		r.app.AgentDecide(p.ID, false)
	}
	m := r.core.Model().Env("prod")
	if m.Site("main").Connection == nil || m.Product("portal").Site == nil || len(m.Product("portal").Connections) != 1 || m.Site("main").Kind != "google-cluster" {
		t.Fatal("a relink went through without Allow")
	}
	r.ok("site-update", map[string]any{"env": "prod", "name": "main", "new_name": "main2", "connection": "GCP"}) // the same connection: a rename only (core may ask: then it waits)
}

func TestAgentPlainVariableNeverShadowsASecretOne(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.refused("var-create", map[string]any{"scope": "env/prod/general", "key": "COOKIE_KEY", "visibility": "plain"}, "no_lowering") // a name the project rule makes secret
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "COOKIE_KEY"})
	var vis string
	for _, v := range r.core.Model().Env("prod").General {
		if v.Key == "COOKIE_KEY" {
			vis = v.Vis
		}
	}
	if vis == "" || vis == "plain" {
		t.Fatalf("the new variable is %q: it must not be plain", vis)
	}
	p := r.call("set-value", map[string]any{"scope": "env/prod/general", "key": "COOKIE_KEY", "value": "other-secret-value-88"})
	if p.State != agentapi.StatePending {
		t.Fatalf("the value of a variable that shares a secret name did not wait: %+v", p)
	}
	r.app.AgentDecide(p.ID, false)
	r.noSecrets()
}

func TestAgentAllowFailsInViewMode(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	p := r.call("set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"})
	r.app.SetMode("view")
	if d := r.app.AgentDecide(p.ID, true); d.Status == 200 {
		t.Fatal("Allow wrote in view mode")
	}
	if st := r.status(p.ID); st.State != agentapi.StateFailed || st.Code != "view_mode" {
		t.Fatalf("%+v", st)
	}
	if r.reveal("other/"+r.core.Model().Other[0].UUID, "") != "wifi-secret-1" {
		t.Fatal("the secret changed")
	}
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
	resp := r.app.AgentJournal()
	raw, _ := json.Marshal(resp)
	if len(raw) > 1500 || strings.Contains(string(raw), "\u001b") || strings.Contains(string(raw), "\u202e") {
		t.Fatalf("the journal panel got the file as it was: %d bytes", len(raw))
	}
}

func TestAgentRenameCannotShadowASecretKey(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "ROOMY", "visibility": "plain"})
	r.refused("var-rename", map[string]any{"scope": "env/prod/general", "key": "ROOMY", "new_key": "COOKIE_KEY"}, "shadows_secret")
	r.ok("var-rename", map[string]any{"scope": "env/prod/general", "key": "ROOMY", "new_key": "ROOMY_TWO"})
	// a secret may take any name; a plain one may take a plain name
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "SECRETIVE", "visibility": "secret"})
	r.ok("var-rename", map[string]any{"scope": "env/prod/general", "key": "SECRETIVE", "new_key": "SECRETIVE_TWO"})
}

func TestAgentRenameOfSecretOrFilledWaitsAndNeverShadows(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "EMPTY_PLAIN", "visibility": "plain"})
	r.ok("var-rename", map[string]any{"scope": "env/prod/general", "key": "EMPTY_PLAIN", "new_key": "EMPTY_PLAIN_2"}) // plain and empty: at once
	r.ok("set-value", map[string]any{"scope": "env/prod/general", "key": "EMPTY_PLAIN_2", "value": "text"})
	p := r.call("var-rename", map[string]any{"scope": "env/prod/general", "key": "EMPTY_PLAIN_2", "new_key": "FILLED_PLAIN"})
	if p.State != agentapi.StatePending {
		t.Fatalf("a filled variable was renamed at once: %+v", p)
	}
	r.app.AgentDecide(p.ID, false)
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "A_SECRET", "visibility": "secret"})
	p = r.call("var-rename", map[string]any{"scope": "env/prod/general", "key": "A_SECRET", "new_key": "B_SECRET"})
	if p.State != agentapi.StatePending {
		t.Fatalf("a secret was renamed at once: %+v", p)
	}
	r.app.AgentDecide(p.ID, true)
	// a plain variable never takes a secret name: a model-level one too (the name rule of the project)
	r.refused("var-rename", map[string]any{"scope": "env/prod/general", "key": "EMPTY_PLAIN_2", "new_key": "DB_PASSWORD"}, "shadows_secret")
	r.refused("var-create", map[string]any{"scope": "env/prod/general", "key": "DB_PASSWORD", "visibility": "plain"}, "no_lowering")
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "DB_PASSWORD"})
	for _, v := range r.core.Model().Env("prod").General {
		if v.Key == "DB_PASSWORD" && v.Vis == "plain" {
			t.Fatal("a variable with a secret name was made plain")
		}
	}
}

func TestAgentSiteCreateThatLinksProductsWaits(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.allow("product-update", map[string]any{"env": "prod", "name": "portal", "site": ""})
	p := r.call("site-create", map[string]any{"env": "prod", "name": "extra", "kind": "google-cluster", "connection": "GCP"})
	if p.State != agentapi.StatePending || r.core.Model().Env("prod").Site("extra") != nil {
		t.Fatalf("a site that would take over a product did not wait: %+v", p)
	}
	r.app.AgentDecide(p.ID, true)
	if r.core.Model().Env("prod").Site("extra") == nil {
		t.Fatal("Allow did not create the site")
	}
	r.ok("site-create", map[string]any{"env": "prod", "name": "extra2", "kind": "google-cluster"}) // nothing to link now: at once
}

func TestAgentEnvCopySeesSecretsInGroupsNoSiteShows(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("env-create", map[string]any{"name": "subby"})
	e := r.core.Model().Env("subby")
	e.Products = append(e.Products, &vmodel.Product{Name: "hidden", Enabled: true, Sub: map[string][]*vmodel.Var{"compose": {{Key: "HID_KEY", Value: "hidden-value", Vis: vmodel.VisSecret}}}})
	p := r.call("env-create", map[string]any{"name": "subby2", "from": "subby"})
	if p.State != agentapi.StatePending {
		t.Fatalf("a copy with a secret in a group no site shows did not wait: %+v", p)
	}
}

func TestAgentOtherRenameOfFilledSecretWaits(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	p := r.call("other-update", map[string]any{"other": "wifi", "new_title": "wifi 2"})
	if p.State != agentapi.StatePending || r.core.Model().Other[0].Title != "wifi" {
		t.Fatalf("%+v", p)
	}
	r.app.AgentDecide(p.ID, false)
	r.ok("other-create", map[string]any{"title": "empty one"})
	r.ok("other-update", map[string]any{"other": "empty one", "new_title": "empty two"}) // nothing filled: at once
}

func TestAgentNewRequestsThatWaitAreRateLimited(t *testing.T) {
	r := newRigGap(t, 0, 400*time.Millisecond)
	r.unlock()
	if p := r.call("set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"}); p.State != agentapi.StatePending {
		t.Fatalf("%+v", p)
	}
	r.refused("set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"}, "rate_limited")
	time.Sleep(500 * time.Millisecond)
	if p := r.call("set-value", map[string]any{"other": "wifi", "value": "other-secret-value-88"}); p.State != agentapi.StatePending {
		t.Fatalf("%+v", p)
	}
	r.noSecrets()
}

func TestAgentPlainNameTakenFromASecretRowIsRefused(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("var-create", map[string]any{"scope": "env/prod/general", "key": "ODDNAME", "visibility": "secret"})
	r.refused("var-create", map[string]any{"scope": "shared", "key": "ODDNAME", "visibility": "plain"}, "shadows_secret")
}

func TestAgentConnectionNameBoundByTheProjectWaits(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	bound := ""
	for _, p := range r.core.d.Products {
		for _, u := range p.Connections {
			if u.Name != "" && r.core.BoundConnectionName(u.Name) && r.core.Model().Connection(u.Name) == nil {
				bound = u.Name
			}
		}
	}
	if bound == "" {
		t.Skip("the example project binds no connection name")
	}
	p := r.call("connection-update", map[string]any{"connection": "Blob store", "new_name": bound})
	if p.State != agentapi.StatePending || r.core.Model().Connection(bound) != nil {
		t.Fatalf("a rename to a bound name did not wait: %+v", p)
	}
	r.app.AgentDecide(p.ID, false)
	c := r.call("connection-create", map[string]any{"name": bound, "kind": "s3"})
	if c.State != agentapi.StatePending || r.core.Model().Connection(bound) != nil {
		t.Fatalf("a connection made under a bound name did not wait: %+v", c)
	}
	r.ok("connection-update", map[string]any{"connection": "Blob store", "new_name": "Blob store 2"}) // an ordinary rename of a used connection goes the usual way (core may ask)
}

func TestAgentBoundNamesAreNormalizedAndKindIdsCount(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	bound, kind := "", ""
	for _, p := range r.core.d.Products {
		for _, u := range p.Connections {
			if u.Name != "" && r.core.BoundConnectionName(u.Name) && r.core.Model().Connection(u.Name) == nil {
				bound = u.Name
			}
			if kind == "" && r.core.Model().Connection(u.Kind) == nil && u.Kind != "" {
				kind = u.Kind
			}
		}
	}
	if bound == "" || kind == "" {
		t.Skip("the example project binds no connection name")
	}
	p := r.call("connection-update", map[string]any{"connection": "Blob store", "new_name": "  " + strings.ToUpper(bound) + "  "})
	if p.State != agentapi.StatePending {
		t.Fatalf("a rename to a bound name in other case and with spaces did not wait: %+v", p)
	}
	r.app.AgentDecide(p.ID, false)
	c := r.call("connection-create", map[string]any{"name": kind, "kind": "s3"})
	if c.State != agentapi.StatePending {
		t.Fatalf("a connection named like a kind id did not wait: %+v", c)
	}
}

func TestAgentFirstAndLastButOneConnectionOfANeededKindWait(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	count := map[string]int{}
	for _, c := range r.core.Model().Connections {
		count[c.Kind]++
	}
	one, none := "", ""
	for _, p := range r.core.d.Products {
		for _, u := range p.Connections {
			if count[u.Kind] == 1 && one == "" {
				one = u.Kind
			}
			if count[u.Kind] == 0 && none == "" {
				none = u.Kind
			}
		}
	}
	if one == "" || none == "" {
		t.Fatalf("the example has no needed kind with one connection (%q) or with none (%q)", one, none)
	}
	// the first connection of a needed kind waits
	if p := r.call("connection-create", map[string]any{"name": "First of its kind", "kind": none}); p.State != agentapi.StatePending {
		t.Fatalf("%+v", p)
	}
	// a second one of a kind is made at once; deleting it would leave exactly one: that waits
	r.ok("connection-create", map[string]any{"name": "Second of its kind", "kind": one})
	p := r.call("connection-delete", map[string]any{"connection": "Second of its kind"})
	if p.State != agentapi.StatePending {
		t.Fatalf("a delete that leaves one connection of a needed kind did not wait: %+v", p)
	}
	r.app.AgentDecide(p.ID, false)
}

func TestAgentOtherWithNotesCountsAsFilled(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("other-create", map[string]any{"title": "only notes"})
	for _, o := range r.core.Model().Other {
		if o.Title == "only notes" {
			o.Notes = "a note"
		}
	}
	if p := r.call("other-delete", map[string]any{"other": "only notes"}); p.State != agentapi.StatePending {
		t.Fatalf("%+v", p)
	}
}

func TestAgentRelinkDialogShowsOldAndNew(t *testing.T) {
	r := newRig(t, 0)
	r.unlock()
	r.ok("connection-create", map[string]any{"name": "Other cloud", "kind": "google"})
	p := r.call("site-update", map[string]any{"env": "prod", "name": "main", "connection": "Other cloud"})
	if p.State != agentapi.StatePending {
		t.Fatalf("%+v", p)
	}
	raw, _ := json.Marshal(r.app.AgentPending())
	for _, want := range []string{"\"field\":\"connection\"", "\"old\":\"GCP\"", "\"new\":\"Other cloud\""} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the pending list lacks %s: %s", want, raw)
		}
	}
}
