package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/pkg/vault"
)

const pw = "Tj7#kQ2!vLxR9mZb" // a throwaway that passes the policy of a new master password

type harness struct {
	t    *testing.T
	dir  string
	env  map[string]string
	pw   []string // what Ask returns, in order
	out  bytes.Buffer
	errb bytes.Buffer
	exec Runner
	tid  bool
	root string
	// asked counts the password prompts: a refusal that needs no vault must leave it at 0
	asked int
	rand  io.Reader // the source of generated passphrases (nil: crypto/rand)
	// notified are the command lines shown to the owner before a touch
	notified []string
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	h := &harness{t: t, dir: dir, env: map[string]string{"ICEVAULT_VAULT": filepath.Join(dir, "vault", "v.kdbx"), configDirVar: filepath.Join(dir, "config")}, pw: []string{pw}, root: filepath.Join(dir, "project")}
	if err := example.Write(h.root); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) run(args ...string) int {
	h.out.Reset()
	h.errb.Reset()
	e := h.newEnv()
	if len(args) >= 2 && args[0] == "session" && (args[1] == "open" || args[1] == "close") {
		return runTestSession(args[1], args[2:], e)
	}
	return Run(args, e)
}

func (h *harness) newEnv() *Env {
	asks := append([]string(nil), h.pw...)
	return &Env{Getenv: func(k string) string { return h.env[k] }, Out: &h.out, Err: &h.errb, Now: time.Now, Exec: h.exec, TouchID: h.tid, Root: h.root, Rand: h.rand,
		Notify: func(s string) { h.notified = append(h.notified, s) },
		Ask: func(string) ([]byte, error) {
			h.asked++
			if len(asks) == 0 {
				return nil, errExit{NeedsOwner}
			}
			p := asks[0]
			asks = asks[1:]
			return []byte(p), nil
		}}
}

func (h *harness) initVault() {
	h.t.Helper()
	h.pw = []string{pw, pw}
	if rc := h.run("init-vault", "--decryption-time", "100"); rc != 0 {
		h.t.Fatalf("init rc=%d %s", rc, h.errb.String())
	}
	h.pw = []string{pw}
}

func (h *harness) seed(entries ...vault.Entry) {
	h.t.Helper()
	v, err := vault.Open(h.env["ICEVAULT_VAULT"], vault.Credentials{Password: []byte(pw), KeyFile: h.env["ICEVAULT_KEYFILE"]})
	if err != nil {
		h.t.Fatal(err)
	}
	for _, e := range entries {
		if err := v.Put(e); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := v.Save(); err != nil {
		h.t.Fatal(err)
	}
}

func TestInitVault(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	p := h.env["ICEVAULT_VAULT"]
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("vault: %v %v", st, err)
	}
	if !strings.Contains(h.out.String(), "") || readInfo(p) == nil {
		t.Fatal("no info file")
	}
	h.pw = []string{pw, pw}
	if rc := h.run("init-vault"); rc != 1 || !strings.Contains(h.errb.String(), "already exists: not overwritten") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
}

func TestInitVaultTable(t *testing.T) {
	cases := []struct {
		name string
		pw   []string
		env  map[string]string
		args []string
		rc   int
		msg  string
	}{
		{"mismatch", []string{"a", "b"}, nil, nil, 1, "do not match"},
		{"no terminal", nil, nil, nil, 1, NeedsOwner},
		{"empty without key file", []string{"", ""}, nil, nil, 1, "needs a key file"},
		{"missing key file", []string{pw, pw}, map[string]string{"ICEVAULT_KEYFILE": "/nonexistent/k"}, nil, 1, "does not exist"},
		{"bad time", []string{pw, pw}, nil, []string{"--decryption-time", "5"}, 1, "100 to 5000"},
		{"bad flag", []string{pw, pw}, nil, []string{"--nope"}, 2, ""},
	}
	for _, c := range cases {
		h := newHarness(t)
		h.pw = c.pw
		for k, v := range c.env {
			h.env[k] = v
		}
		rc := h.run(append([]string{"init-vault"}, c.args...)...)
		if rc != c.rc || !strings.Contains(h.errb.String(), c.msg) {
			t.Errorf("%s: rc=%d %q", c.name, rc, h.errb.String())
		}
		if _, err := os.Stat(h.env["ICEVAULT_VAULT"]); err == nil {
			t.Errorf("%s: a vault was made", c.name)
		}
		if strings.Contains(h.errb.String()+h.out.String(), pw) {
			t.Errorf("%s: password in the output", c.name)
		}
	}
}

func TestKeyFileVault(t *testing.T) {
	h := newHarness(t)
	kf := filepath.Join(h.dir, "k.keyx")
	h.pw = []string{pw, pw}
	if rc := h.run("init-vault", "--new-keyfile", kf, "--decryption-time", "100"); rc != 0 || !strings.Contains(h.out.String(), "made the key file") {
		t.Fatal(h.errb.String())
	}
	if st, err := os.Stat(kf); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	h.pw = []string{pw}
	h.env["ICEVAULT_KEYFILE"] = kf
	if rc := h.importEnv("prod"); rc != 0 {
		t.Fatal(h.errb.String())
	}
	delete(h.env, "ICEVAULT_KEYFILE")
	if rc := h.run("view", "--env", "prod"); rc != 1 || !strings.Contains(h.errb.String(), "wrong password or key file") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
}

// --new-keyfile never overwrites a key file, refuses next to ICEVAULT_KEYFILE, and leaves no key file behind when the vault is not made.
func TestInitVaultNewKeyfileRefusals(t *testing.T) {
	h := newHarness(t)
	kf := filepath.Join(h.dir, "k.keyx")
	if err := os.WriteFile(kf, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.pw = []string{pw, pw}
	if rc := h.run("init-vault", "--new-keyfile", kf); rc != 1 || !strings.Contains(h.errb.String(), "already exists: not overwritten") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	if got, _ := os.ReadFile(kf); string(got) != "mine" {
		t.Fatal("the key file was overwritten")
	}
	h.env["ICEVAULT_KEYFILE"] = kf
	if rc := h.run("init-vault", "--new-keyfile", filepath.Join(h.dir, "other.keyx")); rc != 1 || !strings.Contains(h.errb.String(), "unset ICEVAULT_KEYFILE") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	delete(h.env, "ICEVAULT_KEYFILE")
	fresh := filepath.Join(h.dir, "fresh.keyx")
	h.pw = []string{"a", "b"} // the passwords differ: nothing is made, no key file is left
	if rc := h.run("init-vault", "--new-keyfile", fresh); rc != 1 {
		t.Fatalf("rc=%d", rc)
	}
	if _, err := os.Stat(fresh); err == nil {
		t.Fatal("a key file was left behind")
	}
}

// view --item shows an item of the projection: a connection served to programs (external/<serve-as>), names only.
func TestViewItem(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	if rc, _ := runExternal(h, extOpen, `{"op":"put","group":"monitoring","key":"MONITOR_KEY","value":"never-print-me-1"}`, `{"op":"close"}`); rc != 0 {
		t.Fatal(h.errb.String())
	}
	if rc := h.run("view", "--item", "external/monitor"); rc != 0 {
		t.Fatal(h.errb.String())
	}
	out := h.out.String()
	for _, want := range []string{"item external/monitor:", "MONITOR_KEY"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "never-print-me") {
		t.Errorf("output has a value")
	}
	if rc := h.run("view", "--item", "bad"); rc != 1 || !strings.Contains(h.errb.String(), "SECTION/ITEM") {
		t.Errorf("rc=%d %s", rc, h.errb.String())
	}
	h.pw = nil
	if rc := h.run("view", "--item", "external/monitor"); rc != 1 || !strings.Contains(h.errb.String(), "icevault: "+NeedsOwner) {
		t.Errorf("no terminal: rc=%d %s", rc, h.errb.String())
	}
	h.pw = []string{"wrong"}
	if rc := h.run("view", "--item", "external/monitor"); rc != 1 || strings.Contains(h.errb.String(), "wrong\n") {
		t.Errorf("wrong password: rc=%d %s", rc, h.errb.String())
	}
	h.pw = []string{pw}
	if rc := h.run("view", "--item", "nothing/here"); rc != 0 {
		t.Errorf("unknown item: %s", h.errb.String())
	}
	h.env["ICEVAULT_VAULT"] = filepath.Join(h.dir, "none.kdbx")
	h.pw = []string{pw}
	if rc := h.run("view", "--item", "a/b"); rc != 1 || !strings.Contains(h.errb.String(), "no vault at") {
		t.Errorf("no vault: %s", h.errb.String())
	}
}

// A vault that is not in the vault model is refused with the way to move it.
func TestAVaultOfTheOldLayoutIsRefused(t *testing.T) {
	h := newHarness(t)
	p := h.env["ICEVAULT_VAULT"]
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	v, err := vault.Create(p, vault.Credentials{Password: []byte(pw)}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(vault.Entry{Group: "Old/environments/prod", Title: "X", Password: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	v.Close()
	if rc := h.run("view", "--env", "prod"); rc != 1 || !strings.Contains(h.errb.String(), "holds no vault model") || !strings.Contains(h.errb.String(), "icevault init-vault") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
}

func TestCopyAndCopies(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	dest := filepath.Join(h.dir, "usb")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if rc := h.run("copies", "list"); rc != 0 || !strings.Contains(h.out.String(), "no destination") {
		t.Fatalf("%d %s", rc, h.out.String())
	}
	if rc := h.run("copies", "add", filepath.Dir(h.env["ICEVAULT_VAULT"])); rc != 1 || !strings.Contains(h.errb.String(), "own folder") {
		t.Fatalf("%s", h.errb.String())
	}
	if rc := h.run("copies", "add", filepath.Join(h.dir, "gone")); rc != 1 || !strings.Contains(h.errb.String(), "not reachable") {
		t.Fatalf("%s", h.errb.String())
	}
	if rc := h.run("copies", "add", dest); rc != 0 || !strings.Contains(h.out.String(), "destination added") || !strings.Contains(h.out.String(), "vault copy written to") {
		t.Fatalf("%s %s", h.out.String(), h.errb.String())
	}
	if rc := h.run("copies", "add", dest); rc != 1 || !strings.Contains(h.errb.String(), "already a destination") {
		t.Fatal(h.errb.String())
	}
	a, _ := sha256File(h.env["ICEVAULT_VAULT"])
	b, _ := sha256File(filepath.Join(dest, "v.kdbx"))
	if a != b {
		t.Fatal("copy differs")
	}
	if rc := h.run("copies", "list"); rc != 0 || !strings.Contains(h.out.String(), "same as the vault") {
		t.Fatal(h.out.String())
	}
	if w := copiesWarning(h.env["ICEVAULT_VAULT"], time.Now()); w != "" {
		t.Errorf("warning: %s", w)
	}
	if w := copiesWarning(h.env["ICEVAULT_VAULT"], time.Now().Add(10*24*time.Hour)); !strings.Contains(w, "no destination holds a copy newer than 7 days") {
		t.Errorf("stale warning: %q", w)
	}
	if rc := h.run("copies", "remove", dest); rc != 0 {
		t.Fatal(h.errb.String())
	}
	if rc := h.run("copies", "remove", dest); rc != 1 || !strings.Contains(h.errb.String(), "not a destination") {
		t.Fatal(h.errb.String())
	}
	if w := copiesWarning(h.env["ICEVAULT_VAULT"], time.Now()); !strings.Contains(w, "no destination is configured") {
		t.Errorf("%q", w)
	}
	// copies now keeps the previous copy as .prev
	d2 := filepath.Join(h.dir, "d2")
	_ = os.Mkdir(d2, 0o700)
	if rc := h.run("copies", "now", d2); rc != 0 || !strings.Contains(h.out.String(), a) {
		t.Fatal(h.errb.String())
	}
	h.seed(vault.Entry{Group: "g", Title: "x", Password: []byte("1")})
	if rc := h.run("copies", "now", d2); rc != 0 {
		t.Fatal(h.errb.String())
	}
	if _, err := os.Stat(filepath.Join(d2, "v.kdbx.prev")); err != nil {
		t.Fatal("no previous copy")
	}
	if rc := h.run("copies", "now", filepath.Join(h.dir, "nodir")); rc != 1 || !strings.Contains(h.errb.String(), "is not a directory") {
		t.Fatal(h.errb.String())
	}
	if rc := h.run("copies", "now"); rc != 1 || !strings.Contains(h.errb.String(), "copies now needs a folder") {
		t.Fatalf("rc=%d", rc)
	}
	if rc := h.run("copies", "add"); rc != 1 || !strings.Contains(h.errb.String(), "copies add needs a folder") {
		t.Fatal(h.errb.String())
	}
}

func TestUsageAndUnknownCommands(t *testing.T) {
	h := newHarness(t)
	if rc := h.run(); rc != 2 {
		t.Error("no args")
	}
	if rc := h.run("nonsense"); rc != 2 {
		t.Error("unknown command")
	}
	if rc := h.run("touchid", "status"); rc != 0 || !strings.Contains(h.out.String(), "not available") {
		t.Error("touchid status")
	}
	if rc := h.run("touchid", "enable"); rc != 1 || !strings.Contains(h.errb.String(), "not available") {
		t.Error("touchid enable")
	}
	if rc := h.run("touchid", "bogus"); rc != 2 {
		t.Error("touchid bogus")
	}
	if rc := h.run("view"); rc != 1 {
		t.Error("view without --env")
	}
}

func TestVaultFlagWinsOverTheEnvironment(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	real := h.env["ICEVAULT_VAULT"]
	h.env["ICEVAULT_VAULT"] = filepath.Join(h.dir, "elsewhere.kdbx")
	if rc := h.run("copies", "list"); rc != 0 || strings.Contains(h.out.String(), real) {
		t.Fatal(h.errb.String())
	}
	if rc := h.run("where", "--vault", real); rc != 0 || !strings.Contains(h.out.String(), real) || !strings.Contains(h.out.String(), "\"exists\": true") {
		t.Fatalf("%s %s", h.out.String(), h.errb.String())
	}
	if rc := h.run("where", "--vault="+real); rc != 0 || !strings.Contains(h.out.String(), "\"exists\": true") {
		t.Fatal(h.out.String())
	}
	// what follows -- belongs to the command of a session run
	if args, _, ok := takeFlag([]string{"--env", "prod", "--", "tool", "--vault", "x"}, "vault"); ok || len(args) != 6 {
		t.Fatalf("%v", args)
	}
}

func TestTheRefusalCanGoToAFile(t *testing.T) {
	h := newHarness(t)
	errFile := filepath.Join(h.dir, "err.txt")
	h.env["ICEVAULT_ERROR_FILE"] = errFile
	h.pw = nil
	h.env["ICEVAULT_VAULT"] = filepath.Join(h.dir, "none.kdbx")
	if rc := h.run("copies", "list"); rc != 0 {
		t.Fatal("copies list never refuses")
	}
	if rc := h.run("copies", "now", h.dir); rc != 1 || h.errb.Len() != 0 {
		t.Fatalf("rc=%d stderr=%q", rc, h.errb.String())
	}
	got, err := os.ReadFile(errFile)
	if err != nil || !strings.HasPrefix(string(got), "no vault at ") || strings.HasPrefix(string(got), "icevault: ") {
		t.Fatalf("%q %v", got, err)
	}
	if st, _ := os.Stat(errFile); st.Mode().Perm() != 0o600 {
		t.Fatal("mode")
	}
}
