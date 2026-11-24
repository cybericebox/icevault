package desktop

import (
	"encoding/json"
	"github.com/cybericebox/icevault/internal/project"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

func frontend(t *testing.T) fs.FS {
	t.Helper()
	return os.DirFS("../../cmd/icevault-desktop/frontend")
}

// Every endpoint the page calls must be one the bridge handles: a lifecycle call or a read or a write op of the App.
func TestPageEndpointsAreBound(t *testing.T) {
	src, err := fs.ReadFile(frontend(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := map[string]bool{"status": true, "ping": true, "close": true, "lock": true, "mode": true, "unlock": true, "reveal": true, "cli": true, "cli-install": true, "refresh": true,
		"vaults": true, "vault-select": true, "vault-open": true, "vault-root": true, "vault-forget": true, "project-choose": true,
		"vault-new-project": true, "vault-new-noproject": true, "vault-no-project": true, "vault-new-place": true, "vault-new-strength": true, "vault-new-generate": true, "vault-new-create": true, "vault-change-info": true, "vault-change": true, "kit-save": true, "kit-discard": true, "kit-held": true,
		"update": true, "update-check": true, "update-fetch": true, "update-apply": true, "update-auto": true, "update-release": true}
	reads := map[string]bool{"nav": true, "item": true, "compare": true, "references": true, "pull-candidates": true, "shared": true, "visibility": true, "preview-value": true, "migrate-plan": true}
	found := map[string]bool{}
	for _, m := range regexp.MustCompile(`"/api/([a-z-]+)`).FindAllStringSubmatch(string(src), -1) {
		found[m[1]] = true
	}
	if len(found) < 30 {
		t.Fatalf("the page calls only %d endpoints: the pattern is wrong", len(found))
	}
	for op := range found {
		if !lifecycle[op] && !reads[op] && !writeOps[op] {
			t.Errorf("the page calls /api/%s but the App has no such op", op)
		}
	}
	// dynamic paths (retire-group, retire-entry ... built in retireDialog) are passed as literals too; anything else dynamic is caught by the regexp above
}

func TestPageHasNoNetworkAndNoRemoteContent(t *testing.T) {
	b, err := BuildPage(frontend(t), "N")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, bad := range []string{"fetch(", "XMLHttpRequest", "WebSocket", "navigator.clipboard", "window.open", "eval(", "new Function", "<iframe", "@import"} {
		if strings.Contains(s, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	for _, m := range regexp.MustCompile(`https?://[^"'\s)]+`).FindAllString(s, -1) {
		if m != "http://www.w3.org/2000/svg" && !strings.HasPrefix(m, "https://lucide.dev") && !strings.Contains(m, "scripts.sil.org") && !strings.Contains(m, "openfontlicense") {
			// a link in a comment of a licence is fine; anything else must be looked at
			t.Errorf("page mentions a URL: %s", m)
		}
	}
	if regexp.MustCompile(`(src|href)="https?:`).MatchString(s) {
		t.Error("a remote src or href")
	}
	if !strings.Contains(s, "<title>Cyber\u00a0ICE\u00a0Box</title>") {
		t.Error("the page title must carry the brand with non-breaking spaces")
	}
}

func TestMessageTablesHaveTheSameKeys(t *testing.T) {
	raw, err := fs.ReadFile(frontend(t), "messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var tables map[string]map[string]string
	if err := json.Unmarshal(raw, &tables); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"en", "uk", "ru"} {
		if len(tables[l]) == 0 {
			t.Fatalf("no table for %s", l)
		}
	}
	for k := range tables["en"] {
		for _, l := range []string{"uk", "ru"} {
			if _, found := tables[l][k]; !found {
				t.Errorf("%s lacks %s", l, k)
			}
		}
	}
	for k := range tables["uk"] {
		if _, found := tables["en"][k]; !found {
			t.Errorf("en lacks %s", k)
		}
	}
}

// Locking must not leave decrypted text in a hidden part of the page: renderLocked empties the main area and the navigation (a revealed secret and the plain values
// sit in those nodes; hiding them with a CSS class keeps them in the webview's memory).
func TestLockClearsDecryptedDom(t *testing.T) {
	src, err := fs.ReadFile(frontend(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)function renderLocked\(\) \{(.*?)\n\}`).FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("renderLocked not found")
	}
	for _, want := range []string{`$("main").textContent = ""`, `$("nav").textContent = ""`} {
		if !strings.Contains(m[1], want) {
			t.Errorf("renderLocked does not run %s", want)
		}
	}
}

// Every rule a value can break has a sentence in every language, and the page checks the same rules as the program (the type words it switches on).
func TestEveryTypeRuleHasAMessage(t *testing.T) {
	raw, err := fs.ReadFile(frontend(t), "messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var tables map[string]map[string]string
	if err := json.Unmarshal(raw, &tables); err != nil {
		t.Fatal(err)
	}
	src, _ := fs.ReadFile(frontend(t), "index.html")
	for _, rule := range []string{project.RuleBool, project.RuleInt, project.RuleEmail, project.RuleURL, project.RuleDomain, project.RuleEnum, project.RulePattern, project.RuleRange, project.RuleLength} {
		for _, lang := range []string{"en", "uk", "ru"} {
			if strings.TrimSpace(tables[lang]["m.type."+rule]) == "" {
				t.Errorf("no m.type.%s in %s", rule, lang)
			}
		}
		if rule != project.RulePattern && rule != project.RuleRange && rule != project.RuleLength && !strings.Contains(string(src), "case \""+rule+"\":") {
			t.Errorf("the page does not check %s", rule)
		}
	}
}

// The variable dialog of the model screen (every scope: shared, General, site, product) gives its value field the reference controls and the live
// preview with the scope the server needs, and the header of an environment stays at the top while its sections scroll.
func TestModelScreenWiresReferencesAndStickyHeader(t *testing.T) {
	src, err := fs.ReadFile(frontend(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(src)
	m := regexp.MustCompile(`(?s)function mvarDialog\(scope, r\) \{(.*?)\n\}`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("mvarDialog not found")
	}
	if !strings.Contains(m[1], "ref: refCtx") || !strings.Contains(m[1], "scope,") {
		t.Error("the value field of mvarDialog has no reference controls with its scope")
	}
	d := regexp.MustCompile(`(?s)function dialog\(.*?\n\}\n`).FindString(page)
	for _, want := range []string{"refControls(inp, wrap, f.ref.scope)", "liveRefs(inp,", "scope: f.ref.scope"} {
		if !strings.Contains(d, want) {
			t.Errorf("dialog() does not wire %s", want)
		}
	}
	e := regexp.MustCompile(`(?s)function mEnv\(main\) \{(.*?)\n\}`).FindStringSubmatch(page)
	if e == nil || !strings.Contains(e[1], `classList.add("sticky")`) {
		t.Error("the environment header is not sticky")
	}
	if !strings.Contains(page, ".head.sticky") {
		t.Error("no style for the sticky header")
	}
	for _, op := range []string{"references", "preview-value"} {
		if !strings.Contains(string(mustRead(t, "../mpage/core.go")), `"`+op+`"`) {
			t.Errorf("the model core does not answer %s", op)
		}
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The model screen: one table layout (a framed wrapper, the name cell stays a table cell), folding cards and sections remembered per item, the
// system-set rows hidden behind one remembered toggle, the add buttons at the right end of their header, a success tint for a ready product.
func TestModelScreenLayoutWiring(t *testing.T) {
	src, err := fs.ReadFile(frontend(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(src)
	for _, want := range []string{
		`el("div", "mtwrap")`, `el("td", "mk")`, "function mfold(", `saveCollapsed()`, `mfold(card, h, mscope() + "|site|"`, `mfold(card, h, mscope() + "|product|"`, `mfold(sec, h, mscope()`,
		"(mshowauto || !r.system)", `storeSet("icevault.showauto"`, `" warn" : " ok"`, ".banner.ok {", ".mblock-h .grow, .mcard-h .grow, .msub-h .grow { flex:1; }", ".mtwrap {",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	if mv := regexp.MustCompile(`(?s)function mvars\(.*?\n\}\n`).FindString(page); mv == "" || strings.Contains(mv, `el("td", "kcell")`) {
		t.Error("a name cell of the model tables is a flex box again: its row grows unevenly")
	}
}

// The model screen's dialogs: a secret value is typed masked (and follows the visibility chosen in the dialog), a key file is a masked multi-line
// field that can be read from a file, a bad variable name is an error beside its field, an environment can be created from the view mode, and a
// recovery kit that was not saved is asked about before the step is left.
func TestModelDialogsHideSecretsAndGuardTheKit(t *testing.T) {
	src, err := fs.ReadFile(frontend(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(src)
	for _, want := range []string{
		"maskIf: fresh ?", `classList.add("masked")`, "fromFile: !!r && secret", "textarea.masked {", `bad_key: "key"`, `check: (v) => (v.trim() && !/^[A-Za-z_]`,
		"function leaveKit(", `kit.dataset.saved = "1"`, "leaveKit(() => kitEl, finish)", `if (!editing() && !(await setMode("edit"))) return; menvDialog(null);`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	if ms := regexp.MustCompile(`(?s)function renderMSide\(\) \{(.*?)\n\}\n`).FindStringSubmatch(page); ms == nil || strings.Contains(ms[1], `if (editing()) { const a = el("button", "side-add")`) {
		t.Error("the new environment button is back to edit mode only")
	}
}

// An enum or a bool can take a reference instead of a choice: a stored reference is not a false "not in choices" warning and not an option, the field has a
// "use a reference" link, and a new variable is checked as typed against the type the description gives its name.
func TestTypedFieldsTakeReferences(t *testing.T) {
	src, err := fs.ReadFile(frontend(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(src)
	for _, want := range []string{
		"function withRefAlt(", "f.refAlt = { scope, start: true, value: stored }", "const isRef = (v) => /(^|[^$])\\$\\{\\{/.test(v || \"\")", "const described = (inp) =>", "fields[0].recheck = [\"value\"]",
		"function mrowsOf(scope)", ".sel[hidden]",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
}

// A key file read from a page: at most 64 KiB, checked before it is read, a JSON key compacted to one line, text with line breaks refused with a
// sentence; a secret that is switched to secret is masked again; the kit warning asks the program whether a kit is still held; a product keeps the
// connection it already has in its list.
func TestKeyFilesAndKitGuardsOfTheDialogs(t *testing.T) {
	src, err := fs.ReadFile(frontend(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(src)
	for _, want := range []string{
		"file.size > 65536", "JSON.stringify(JSON.parse(text))", `t("val.file_lines")`, `t("val.file_big")`, `setAttribute("autocapitalize", "off")`, `setAttribute("autocorrect", "off")`,
		`i.dataset.shown = ""`, `api("/api/kit-held")`, `"kit-held"`, "wanted(c) || chosen.has(c.uuid)",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
}

// The audit's last items: the open vault's file name under the sidebar title, an imported value can be taken out from its row, the lock screen heading
// does not wrap against its buttons, the New vault dialog keeps its layout (the Touch ID row keeps its place, the no-project button goes after a
// choice, the passwords have a show toggle), and the Touch ID labels read alike.
func TestAuditLastItems(t *testing.T) {
	src, err := fs.ReadFile(frontend(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(src)
	for _, want := range []string{
		`document.querySelector(".side-head small")`, "onUnimport: (k) =>", `t("m.env.unimport"`, ".vlist-head { display:flex; flex-wrap:wrap;", ".nvtouch.off { visibility:hidden; }",
		"nbtn.hidden = true;", `const cfw = el("div", "valbox")`, `const curw = el("div", "valbox")`, `(nav.envs || []).length ? t("m.env.copy_note") : ""`, "c.title = countTip",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	if strings.Contains(page, "trow.hidden = ") {
		t.Error("the Touch ID row is hidden again instead of kept in place")
	}
}

// A JSON key read from a file stays as it is typed unless it has line breaks; a select inside a dialog opens inside the dialog; the lock screen keeps the
// place of its error line.
func TestKeyTextAsTypedAndListInsideDialog(t *testing.T) {
	src, err := fs.ReadFile(frontend(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(src)
	for _, want := range []string{
		"try { JSON.parse(text); if (/[\\r\\n]/.test(text)) text = JSON.stringify(JSON.parse(text)); }", `trig.closest(".dlgbox")`, "hb.bottom - r.bottom - 8", "#lockedbody .err { min-height:20px;",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	if strings.Contains(page, "text = JSON.stringify(JSON.parse(text)); } catch (e) { text = text.trim(); }") {
		t.Error("a JSON key is re-serialised even when it is one line")
	}
}
