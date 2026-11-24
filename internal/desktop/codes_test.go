package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/cybericebox/icevault/internal/cliinstall"
	"github.com/cybericebox/icevault/internal/update"
	"github.com/cybericebox/icevault/pkg/vault"
)

const leak = "SECRET-LEAK /private/path/vault.kdbx password=hunter2"

// codePatterns find the codes of the refusals the Go side can emit: a model error Err(status, text, "code"), fail(status, "code"), a Code field, the
// answer maps of the window, the codes of Classify.
var codePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\(\s*(?:\d{3}|http\.Status\w+)\s*,[^\n]*?,\s*"([a-z][a-z0-9_]*)"\s*\)`),
	regexp.MustCompile(`\(\s*\d{3}\s*,\s*"([a-z][a-z0-9_]*)"\s*\)`),
	regexp.MustCompile(`\bCode:\s*"([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`keyCode:\s*"([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`return false, "([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`\brefuse\("([a-z][a-z0-9_]*)"`),
	regexp.MustCompile(`Code: "(cli_[a-z_]+)"`),
	regexp.MustCompile(`\bCode[A-Za-z0-9]*\s*=\s*"([a-z][a-z0-9_]*)"`),
}

func sourceCodes(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}
	for _, root := range []string{"../../internal", "../../cmd", "../../pkg"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			if filepath.ToSlash(p) == "../../internal/migrate/migrate.go" {
				return nil // the codes of the report lines are words of mig.why.* (internal/migrate/codes_test.go), not refusals
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			for _, re := range codePatterns {
				for _, m := range re.FindAllStringSubmatch(string(b), -1) {
					if _, dup := found[m[1]]; !dup {
						found[m[1]] = p
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return found
}

// Every code the Go side can emit has words in every language of the page: the page shows srv.<code>, never a text from Go.
func TestEveryErrorCodeHasMessagesInAllLanguages(t *testing.T) {
	raw, err := fs.ReadFile(frontend(t), "messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var tables map[string]map[string]string
	if err := json.Unmarshal(raw, &tables); err != nil {
		t.Fatal(err)
	}
	codes := sourceCodes(t)
	if len(codes) < 80 {
		t.Fatalf("only %d codes found in the sources: the patterns are wrong", len(codes))
	}
	for _, must := range []string{"vault_kdbx3", "vault_kdf", "vault_not_kdbx", "vault_changed", "vault_busy", "vault_missing", "locked", "not_found", "internal", "keyfile_invalid", "touch_tools_missing", "wrong_password_exit"} {
		if _, ok := codes[must]; !ok {
			t.Errorf("the scan did not find the code %s", must)
		}
	}
	var names []string
	for c := range codes {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		for _, lang := range []string{"en", "uk", "ru"} {
			if strings.TrimSpace(tables[lang]["srv."+c]) == "" {
				t.Errorf("code %q (%s) has no srv.%s in %s", c, codes[c], c, lang)
			}
		}
	}
	// the KDBX 3 text keeps the KeePassXC menu names as they appear in the app, in every language, and tells the person to copy the file first
	for _, lang := range []string{"en", "uk", "ru"} {
		for _, c := range []string{"vault_kdbx3", "vault_kdf"} {
			if s := tables[lang]["srv."+c]; !strings.Contains(s, "Database > Database Settings > Security > Encryption") || !strings.Contains(s, "Argon2d") {
				t.Errorf("%s srv.%s lost the KeePassXC menu path", lang, c)
			}
		}
	}
	for _, lang := range []string{"uk", "ru"} {
		if strings.Contains(tables[lang]["srv.vault_kdbx3"], "this vault is KDBX") {
			t.Errorf("%s srv.vault_kdbx3 is English", lang)
		}
	}
}

func TestClassifyMapsEveryVaultError(t *testing.T) {
	missing := fmt.Errorf("%w: %w", vault.ErrUnreadable, syscall.ENOENT)
	denied := fmt.Errorf("%w: %w", vault.ErrUnreadable, syscall.EACCES)
	kfMissing := fmt.Errorf("%w: %w", vault.ErrKeyFileUnreadable, syscall.ENOENT)
	kfDenied := fmt.Errorf("%w: %w", vault.ErrKeyFileUnreadable, syscall.EACCES)
	cases := []struct {
		err  error
		code string
	}{
		{vault.ErrKDBX3, CodeKDBX3},
		{fmt.Errorf("wrapped: %w", vault.ErrKDBX3), CodeKDBX3},
		{vault.ErrUnsupportedKDF, CodeUnsupportedKDF},
		{vault.ErrNotKDBX, CodeNotKDBX},
		{vault.ErrChangedOnDisk, CodeChangedOnDisk},
		{vault.ErrLocked, CodeVaultBusy},
		{vault.ErrBadCredentials, CodeBadCredentials},
		{vault.ErrNotFound, CodeNotFound},
		{vault.ErrNoCredentials, CodeNoCredentials},
		{missing, CodeVaultMissing},
		{denied, CodeVaultUnreadable},
		{kfMissing, CodeKeyFileMissing},
		{kfDenied, CodeKeyFileUnread},
		{vault.ErrKeyFileInvalid, CodeKeyFileInvalid},
		{errors.New(leak), CodeInternal},
	}
	for _, c := range cases {
		if _, code, _ := Classify(c.err); code != c.code {
			t.Errorf("%v: got %q, want %q", c.err, code, c.code)
		}
	}
}

// a unlocker and a core that fail with an error carrying text that must never reach the page
type failUnlocker struct{ openErr, touchErr error }

func (u failUnlocker) Open([]byte) (Core, error) { return nil, u.openErr }
func (u failUnlocker) Touch() ([]byte, error)    { return nil, u.touchErr }
func (failUnlocker) HasKeyFile() bool            { return false }

// failCLI is an installer that fails with the given error.
type failCLI struct{ err error }

func (failCLI) Status() cliinstall.Status { return cliinstall.Status{State: cliinstall.NotInstalled} }
func (c failCLI) Install(bool) (cliinstall.Status, error) {
	return cliinstall.Status{}, c.err
}

type failCore struct{ err error }

func (c failCore) Read(string, map[string]any) (any, error)  { return nil, c.err }
func (c failCore) Write(string, map[string]any) (any, error) { return nil, c.err }
func (c failCore) Reveal(string, string, string, string) (string, error) {
	return "", c.err
}
func (failCore) Lock() {}

// assertCoded: a failed answer carries a code and no text: no "error" key, nothing of the leaked text.
func assertCoded(t *testing.T, what string, r Response) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRET-LEAK") || strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "/private/") {
		t.Errorf("%s: the text of an error reached the page: %s", what, b)
	}
	data, _ := r.Data.(map[string]any)
	if r.Status >= 400 {
		if _, has := data["error"]; has {
			t.Errorf("%s: an answer carries an error text: %s", what, b)
		}
		if code, _ := data["code"].(string); code == "" {
			t.Errorf("%s: a refusal without a code: %s", what, b)
		}
	}
	for k, v := range data {
		if s, isStr := v.(string); isStr && k != "code" && k != "value" && k != "mode" && k != "password" && k != "file" && k != "folder" && k != "checkout" {
			t.Errorf("%s: unexpected string field %s=%q", what, k, s)
		}
	}
}

// No bound method returns a message string that is not a code, whatever error the unlocker or the core fails with. The list of methods is compared with the
// methods the App really has, so a new bound method cannot be forgotten here.
// failSyncCore is a failCore whose reload of the vault file fails too.
type failSyncCore struct{ failCore }

func (c failSyncCore) Sync(bool) (bool, error) { return false, c.err }

func TestNoBoundMethodReturnsAnErrorText(t *testing.T) {
	bad := []error{errors.New(leak), vault.ErrKDBX3, fmt.Errorf("%s: %w", leak, vault.ErrUnsupportedKDF), fmt.Errorf("%s: %w", leak, vault.ErrChangedOnDisk),
		fmt.Errorf("%s: %w", leak, vault.ErrUnreadable), &cliinstall.Error{Code: "cli_blocked", Params: map[string]any{"link": "/x/icevault"}}, &Error{Status: 409, Message: leak, Code: "section_has_items"}, &Error{Status: 500, Message: leak}}
	covered := map[string]bool{}
	for _, e := range bad {
		a := New(Options{Unlocker: failUnlocker{openErr: e, touchErr: e}, Binding: true})
		assertCoded(t, "Unlock password", a.Unlock("password", "pw"))
		covered["Unlock"] = true
		assertCoded(t, "Unlock touch", a.Unlock("touch", ""))

		// unlocked, with a core that fails every call
		b := New(Options{Unlocker: &MemoryUnlocker{Password: "pw"}})
		if r := b.Unlock("password", "pw"); r.Status != 200 {
			t.Fatal(r)
		}
		b.attach(failCore{err: e})
		if r := b.SetMode("edit"); r.Status != 200 {
			t.Fatal(r)
		}
		covered["SetMode"] = true
		assertCoded(t, "Read", b.Read("nav", nil))
		covered["Read"] = true
		assertCoded(t, "Write", b.Write("set", map[string]any{}))
		covered["Write"] = true
		assertCoded(t, "Write file", b.Write("create-file", map[string]any{"data": "AAAA"}))
		assertCoded(t, "Reveal", b.Reveal(map[string]any{}))
		covered["Reveal"] = true
		assertCoded(t, "CopySecret", b.CopySecret(map[string]any{}))
		covered["CopySecret"] = true
		b.o.CLI = failCLI{err: e}
		assertCoded(t, "CLIInstall", b.CLIInstall(false))
		covered["CLIInstall"] = true
		assertCoded(t, "ChooseProject without a picker", b.ChooseProject("t"))
		b.o.PickDescription = func(string) (string, error) { return "/p/icevault-project.yaml", nil }
		assertCoded(t, "ChooseProject", b.ChooseProject("t"))
		b.o.PickDescription = func(string) (string, error) { return "", e }
		assertCoded(t, "ChooseProject pick fails", b.ChooseProject("t"))
		b.o.PickDescription = nil
		covered["ChooseProject"] = true
		b.attach(failSyncCore{failCore{err: e}})
		assertCoded(t, "Refresh", b.Refresh())
		covered["Refresh"] = true
	}
	// locked
	l := New(Options{})
	assertCoded(t, "Read locked", l.Read("nav", nil))
	assertCoded(t, "Write locked", l.Write("set", nil))
	assertCoded(t, "CopyText locked", l.CopyText("x"))
	covered["CopyText"] = true
	assertCoded(t, "CLIInstall locked", l.CLIInstall(false))
	assertCoded(t, "Refresh locked", l.Refresh())
	if r := l.CLIStatus(); r.Status != 200 { // no installer: the state is "unavailable", with a code, never a text
		t.Errorf("CLIStatus: %+v", r)
	}
	covered["CLIStatus"] = true
	assertCoded(t, "Unlock bad method", l.Unlock("nope", ""))
	assertCoded(t, "Unlock no unlocker", l.Unlock("touch", ""))
	// the choice of the vault: every step fails with each error
	for _, e := range bad {
		fv := &fakeVaults{prepareErr: e, rootErr: e, forgetErr: e}
		v := New(Options{Vaults: fv, Vault: "/v/a.kdbx", Pick: func(string, string) (string, error) { return "/v/b.kdbx", nil }})
		assertCoded(t, "SelectVault", v.SelectVault("/v/a.kdbx"))
		covered["SelectVault"] = true
		assertCoded(t, "ListVaults", v.ListVaults())
		covered["ListVaults"] = true
		assertCoded(t, "Unlock with a problem", v.Unlock("password", "pw"))
		assertCoded(t, "OpenVault", v.OpenVault("t"))
		covered["OpenVault"] = true
		assertCoded(t, "ChooseRoot", v.ChooseRoot("t"))
		covered["ChooseRoot"] = true
		assertCoded(t, "ForgetVault", v.ForgetVault("/v/a.kdbx"))
		covered["ForgetVault"] = true
		w := New(Options{Vaults: fv, Pick: func(string, string) (string, error) { return "", e }})
		assertCoded(t, "OpenVault pick fails", w.OpenVault("t"))
		assertCoded(t, "ChooseRoot without a vault", w.ChooseRoot("t"))
		assertCoded(t, "Unlock without a vault", w.Unlock("password", "pw"))
	}
	// a new vault: every step refuses with a code, whatever the maker, the dialog and the vault list fail with
	for _, e := range bad {
		fv := &fakeVaults{}
		m := &fakeMaker{createErr: e, bindErr: e, touchReady: true}
		n := New(Options{Vaults: fv, Maker: m, Pick: func(string, string) (string, error) { return t.TempDir(), nil }, PickSave: func(string, string, string) (string, error) { return filepath.Join(t.TempDir(), "n.kdbx"), nil }})
		assertCoded(t, "NewVaultPlace without a project", n.NewVaultPlace("t"))
		assertCoded(t, "NewVaultProject", n.NewVaultProject("t"))
		assertCoded(t, "NewVaultPlace", n.NewVaultPlace("t"))
		assertCoded(t, "CreateVault fails", n.CreateVault("k7Qm2xVb9RtZ", "k7Qm2xVb9RtZ", true))
		assertCoded(t, "CreateVault weak", n.CreateVault("Qwerty123!", "Qwerty123!", true))
		assertCoded(t, "SaveRecoveryKit none", n.SaveRecoveryKit("t", "{password}"))
		bad := New(Options{Vaults: fv, Maker: m, Pick: func(string, string) (string, error) { return "", e }, PickSave: func(string, string, string) (string, error) { return "", e }})
		assertCoded(t, "NewVaultPlace pick fails", bad.NewVaultPlace("t"))
		assertCoded(t, "NewVaultProject pick fails", bad.NewVaultProject("t"))
		fv.defaultErr = e
		assertCoded(t, "NewVaultProject refused", n.NewVaultProject("t"))
		covered["NewVaultPlace"], covered["NewVaultProject"], covered["CreateVault"], covered["SaveRecoveryKit"] = true, true, true, true
	}
	assertCoded(t, "NewVaultPlace off", l.NewVaultPlace("t"))
	assertCoded(t, "NewVaultProject off", l.NewVaultProject("t"))
	assertCoded(t, "CreateVault off", l.CreateVault("a", "a", false))
	assertCoded(t, "SaveRecoveryKit off", l.SaveRecoveryKit("t", "{password}"))
	for _, r := range []Response{l.PasswordStrength("x"), l.GeneratePassword(), l.DiscardRecoveryKit()} { // answers without refusals: success shapes only
		if r.Status != 200 {
			t.Errorf("%+v", r)
		}
	}
	for _, name := range []string{"PasswordStrength", "GeneratePassword", "DiscardRecoveryKit"} {
		covered[name] = true
	}
	assertCoded(t, "SelectVault off", l.SelectVault("/v/a.kdbx"))
	assertCoded(t, "OpenVault off", l.OpenVault("t"))
	// updates: without an updater every step is refused with a code; with one, its refusals are codes too
	assertCoded(t, "UpdateCheck off", l.UpdateCheck())
	assertCoded(t, "UpdateFetch off", l.UpdateFetch())
	assertCoded(t, "UpdateApply off", l.UpdateApply())
	assertCoded(t, "UpdateAuto off", l.UpdateAuto(true))
	assertCoded(t, "UpdateRelease off", l.UpdateRelease())
	if r := l.UpdateStatus(); r.Status != 200 {
		t.Errorf("UpdateStatus: %+v", r)
	}
	fu := &fakeUpdater{err: &update.Error{Code: "update_bad_sum"}}
	u := New(Options{Update: fu, OpenURL: func(string) {}})
	assertCoded(t, "UpdateFetch fails", u.UpdateFetch())
	assertCoded(t, "UpdateApply fails", u.UpdateApply())
	assertCoded(t, "UpdateRelease with no release", u.UpdateRelease())
	fu.err = errors.New("/some/path: permission denied")
	assertCoded(t, "UpdateApply other error", u.UpdateApply())
	for _, name := range []string{"UpdateStatus", "UpdateCheck", "UpdateFetch", "UpdateApply", "UpdateAuto", "UpdateRelease"} {
		covered[name] = true
	}
	for _, name := range []string{"Status", "Ping", "Close", "Lock"} { // these answer no refusals: success shapes only
		covered[name] = true
	}

	typ := reflect.TypeOf(&App{})
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		if !covered[name] {
			t.Errorf("the bound method %s is not covered by this test: add it", name)
		}
	}
}
