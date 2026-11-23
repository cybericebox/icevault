package desktop

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

// CSP is the policy of the page: nothing from outside. Scripts and styles only with this load's nonce (and the two scripts of the shell itself: 'self'),
// no network except the bridge of the window, fonts and images only inline.
func CSP(nonce string) string {
	return "default-src 'none'; script-src 'self' 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; connect-src 'self'; font-src data:; img-src data:; " +
		"base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
}

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func readText(fsys fs.FS, name string) (string, error) {
	b, err := fs.ReadFile(fsys, name)
	return string(b), err
}

// BuildPage assembles the page: index.html with the fonts, the lock mark (crest.css), the application icon and the message tables put in (one document, no second request)
// and the nonce set. The files: index.html, fonts.css, crest.css, appicon.css, messages.json.
func BuildPage(fsys fs.FS, nonce string) ([]byte, error) {
	page, err := readText(fsys, "index.html")
	if err != nil {
		return nil, err
	}
	fonts, err := readText(fsys, "fonts.css")
	if err != nil {
		return nil, err
	}
	crest, err := readText(fsys, "crest.css")
	if err != nil {
		return nil, err
	}
	appIcon, err := readText(fsys, "appicon.css")
	if err != nil {
		return nil, err
	}
	raw, err := fs.ReadFile(fsys, "messages.json")
	if err != nil {
		return nil, err
	}
	var tables map[string]any
	if err := json.Unmarshal(raw, &tables); err != nil {
		return nil, err
	}
	msgs, err := json.Marshal(tables)
	if err != nil {
		return nil, err
	}
	// "</" cannot end the script block; json.Marshal already escapes < > & as \u003c ..., this keeps it explicit.
	text := strings.ReplaceAll(string(msgs), "</", "<\\/")
	for _, p := range []string{"/*__FONTS__*/", "/*__CREST__*/", "/*__APPICON__*/", "/*__MESSAGES__*/{}"} {
		if strings.Count(page, p) != 1 {
			return nil, errors.New("page placeholder missing: " + p)
		}
	}
	page = strings.Replace(page, "/*__FONTS__*/", fonts, 1)
	page = strings.Replace(page, "/*__CREST__*/", crest, 1)
	page = strings.Replace(page, "/*__APPICON__*/", appIcon, 1)
	page = strings.Replace(page, "/*__MESSAGES__*/{}", text, 1)
	page = strings.ReplaceAll(page, "__CSP__", strings.ReplaceAll(CSP(nonce), "frame-ancestors 'none'; ", "")) // the meta form does not know frame-ancestors
	page = strings.ReplaceAll(page, "__NONCE__", nonce)
	return []byte(page), nil
}

func secure(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
}

// Handler serves the page at "/" and the adapter script at "/adapter.js" from fsys; everything else is 404 (the shell's own "/wails/..." paths never
// reach it: the Middleware below passes them on).
func Handler(fsys fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure(w.Header())
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/", "/index.html":
			nonce, err := newNonce()
			if err != nil {
				http.Error(w, "error", http.StatusInternalServerError)
				return
			}
			body, err := BuildPage(fsys, nonce)
			if err != nil {
				http.Error(w, "error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", CSP(nonce))
			_, _ = w.Write(body)
		case "/adapter.js":
			body, err := fs.ReadFile(fsys, "adapter.js")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	})
}

// Assets is the asset server option of the window: only Handler, no file system to browse.
func Assets(fsys fs.FS) *assetserver.Options {
	return &assetserver.Options{Handler: Handler(fsys)}
}
