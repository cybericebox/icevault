package desktop

import (
	"encoding/json"
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
		"vault-new-project": true, "vault-new-place": true, "vault-new-strength": true, "vault-new-generate": true, "vault-new-create": true, "vault-change-info": true, "vault-change": true, "kit-save": true, "kit-discard": true,
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
