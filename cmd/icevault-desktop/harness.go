//go:build harness && !desktop

// The browser test harness of the window (development only). Built with -tags harness, this package is not the window: it serves the window's page on
// 127.0.0.1 with the window's Content-Security-Policy, and a small script (harnessjs/harness.js) stands in for the Wails bridge: every call of
// window.go.desktop.App goes over HTTP to the REAL internal/desktop App, and the events of the program (vault-changed, vault-selected) come back as
// server-sent events. So the page can be driven by a browser test tool (Chrome DevTools) exactly as the window runs it. A release never has it: the
// release builds use the tags desktop,production, and this file needs harness without desktop.
//
//	mise run ui-harness                      the demo (the example project's vault in a temp folder, password demo)
//	mise run ui-harness -- --mode file       the same vault opened through the real vault list of a temp folder; its password is printed
//
// Flags: --addr (127.0.0.1:0 = a free port), --mode demo|file, --idle (the idle lock, default 10m), --quit-after (end after this time).
// Only 127.0.0.1 is bound; the printed address carries a one-time key that the first page load turns into a cookie, and every other request without
// it (or with another Host) is refused. The file vault and its folder are deleted when the harness ends.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing/fstest"
	"time"

	"github.com/cybericebox/icevault/internal/cli"
	"github.com/cybericebox/icevault/internal/demo"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/example"
)

//go:embed frontend
var frontendFS embed.FS

//go:embed harnessjs/harness.js
var harnessJS []byte

const cookieName = "icevault-harness"

// memClipboard is the clipboard of the harness: in memory, so that a copy in the page never reaches the system clipboard of the machine.
type memClipboard struct {
	mu   sync.Mutex
	text string
}

func (c *memClipboard) Set(s string) error   { c.mu.Lock(); c.text = s; c.mu.Unlock(); return nil }
func (c *memClipboard) Get() (string, error) { c.mu.Lock(); defer c.mu.Unlock(); return c.text, nil }

// events fans the program's events out to the open event streams of the page.
type events struct {
	mu   sync.Mutex
	subs map[chan []byte]bool
}

func (e *events) send(name string, data any) {
	b, err := json.Marshal(map[string]any{"event": name, "data": data})
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for ch := range e.subs {
		select {
		case ch <- b:
		default: // a stream that does not read is not waited for
		}
	}
}

func (e *events) add() chan []byte {
	ch := make(chan []byte, 16)
	e.mu.Lock()
	e.subs[ch] = true
	e.mu.Unlock()
	return ch
}

func (e *events) drop(ch chan []byte) { e.mu.Lock(); delete(e.subs, ch); e.mu.Unlock() }

// pageFS is the window's frontend with one change: index.html loads harness.js (the stand-in of the Wails bridge) before adapter.js.
func pageFS(front fs.FS) (fs.FS, error) {
	out := fstest.MapFS{}
	err := fs.WalkDir(front, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(front, p)
		if err != nil {
			return err
		}
		out[p] = &fstest.MapFile{Data: b, Mode: 0o444}
		return nil
	})
	if err != nil {
		return nil, err
	}
	const tag = `<script src="/adapter.js"></script>`
	page := string(out["index.html"].Data)
	if strings.Count(page, tag) != 1 {
		return nil, errors.New("index.html: the adapter script tag is missing")
	}
	out["index.html"].Data = []byte(strings.Replace(page, tag, `<script src="/harness.js"></script>`+tag, 1))
	return out, nil
}

var responseType = reflect.TypeOf(desktop.Response{})

// call runs one bound method of the App by name with JSON arguments, as the Wails bridge does: only exported methods that answer a Response.
func call(app *desktop.App, method string, args []json.RawMessage) (desktop.Response, int) {
	m := reflect.ValueOf(app).MethodByName(method)
	if method == "" || !m.IsValid() || m.Type().NumOut() != 1 || m.Type().Out(0) != responseType {
		return desktop.Response{}, http.StatusNotFound
	}
	t := m.Type()
	if len(args) != t.NumIn() {
		return desktop.Response{}, http.StatusBadRequest
	}
	in := make([]reflect.Value, len(args))
	for i, raw := range args {
		v := reflect.New(t.In(i))
		if err := json.Unmarshal(raw, v.Interface()); err != nil {
			return desktop.Response{}, http.StatusBadRequest
		}
		in[i] = v.Elem()
	}
	return m.Call(in)[0].Interface().(desktop.Response), http.StatusOK
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "the address to listen on (127.0.0.1 only; port 0 = a free one)")
	mode := flag.String("mode", "demo", "demo: the demo vault of the example project; file: the same vault through the real vault list of a temp folder")
	idle := flag.Duration("idle", desktop.IdleDefault, "lock after this time without activity")
	quitAfter := flag.Duration("quit-after", 0, "end the harness after this time (0: run until stopped)")
	updMode := flag.String("update", "", "play the updates of the application: available, current, manual or failed (\"\": no updater, as the demo)")
	noDesc := flag.Bool("no-description", false, "demo: no project description is found, so the window offers to choose one (the file dialog is answered with a copy of the example's description)")
	flag.Parse()
	demoWithoutDescription = *noDesc
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || host != "127.0.0.1" {
		fmt.Fprintln(os.Stderr, "ui-harness: --addr must be 127.0.0.1:PORT")
		os.Exit(2)
	}

	env := cli.NewWindowEnv()
	cleanup := func() {}
	var vaults desktop.Vaults
	var first, password, vaultFile string
	switch *mode {
	case "demo":
		var derr error
		vaults, first, cleanup, derr = connect(*mode)
		if derr != nil {
			fmt.Fprintln(os.Stderr, "ui-harness: the demo vault:", derr)
			os.Exit(1)
		}
		password = demo.Password
	case "file":
		dir, err := os.MkdirTemp("", "icevault-harness-")
		if err != nil {
			fmt.Fprintln(os.Stderr, "ui-harness:", err)
			os.Exit(1)
		}
		cleanup = func() { _ = os.RemoveAll(dir) }
		password = "harness-" + randomHex(6)
		var root string
		vaultFile, root, err = fileVault(dir, password)
		if err == nil {
			env = demoEnv(dir, root)
		}
		if err != nil {
			cleanup()
			fmt.Fprintln(os.Stderr, "ui-harness: the file vault:", err)
			os.Exit(1)
		}
		cfg := filepath.Join(dir, "config") // the list of recent vaults of the harness, never the user's vaults.json
		orig := env.Getenv
		env.Getenv = func(k string) string {
			switch k {
			case "ICEVAULT_CONFIG_DIR":
				return cfg
			case "ICEVAULT_VAULT":
				return vaultFile
			}
			return orig(k)
		}
		f := newFileVaults(env)
		if err := f.SetRoot(vaultFile, env.Root); err != nil {
			cleanup()
			fmt.Fprintln(os.Stderr, "ui-harness: the project checkout:", err)
			os.Exit(1)
		}
		vaults, first = f, f.first()
	default:
		fmt.Fprintln(os.Stderr, "ui-harness: --mode is demo or file")
		os.Exit(2)
	}

	ev := &events{subs: map[chan []byte]bool{}}
	stop := make(chan string, 1)
	end := func(why string) {
		select {
		case stop <- why:
		default:
		}
	}
	// the stand-in of the system file dialog for the project description: a copy of the demo's description in a folder of the harness
	pickDescription := func(string) (string, error) {
		dir, err := os.MkdirTemp("", "icevault-harness-desc-")
		if err != nil {
			return "", err
		}
		prev := cleanup
		cleanup = func() { prev(); _ = os.RemoveAll(dir) }
		p := filepath.Join(dir, "icevault-project.yaml")
		return p, os.WriteFile(p, example.Description(), 0o600)
	}
	// the stand-in of the save dialog (a new vault, its recovery kit): a fresh name in one temp folder of the harness
	var saveDir string
	pickSave := func(_, _, name string) (string, error) {
		if saveDir == "" {
			d, err := os.MkdirTemp("", "icevault-harness-save-")
			if err != nil {
				return "", err
			}
			saveDir = d
			prev := cleanup
			cleanup = func() { prev(); _ = os.RemoveAll(d) }
		}
		base, ext := strings.TrimSuffix(name, filepath.Ext(name)), filepath.Ext(name)
		for i := 0; ; i++ {
			p := filepath.Join(saveDir, base+ext)
			if i > 0 {
				p = filepath.Join(saveDir, fmt.Sprintf("%s-%d%s", base, i, ext))
			}
			if _, err := os.Lstat(p); err != nil {
				return p, nil
			}
		}
	}
	var upd desktop.Updater
	if *updMode != "" {
		upd = newHarnessUpdater(*updMode)
	}
	app := desktop.New(desktop.Options{Vaults: vaults, Vault: first, Clipboard: &memClipboard{}, Idle: *idle, PickDescription: pickDescription, PickSave: pickSave,
		// the stand-in of the folder dialog: the project checkout of the harness
		Pick: func(kind, _ string) (string, error) {
			if kind == "folder" {
				return env.Root, nil
			}
			return "", nil
		}, Maker: makerFor(vaults),
		Update: upd, OpenURL: func(url string) { fmt.Fprintln(os.Stderr, "ui-harness: open in the browser:", url) },
		Quit:   func() { end("the page ended the program") },
		Say:    func(text string) { fmt.Fprintln(os.Stderr, "ui-harness: settings screen:", text) },
		Notify: ev.send})

	front, err := fs.Sub(frontendFS, "frontend")
	if err == nil {
		front, err = pageFS(front)
	}
	if err != nil {
		cleanup()
		fmt.Fprintln(os.Stderr, "ui-harness: the page:", err)
		os.Exit(1)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		cleanup()
		fmt.Fprintln(os.Stderr, "ui-harness:", err)
		os.Exit(1)
	}
	hostport := ln.Addr().String()
	key := randomHex(16)
	page := desktop.Handler(front)
	mux := http.NewServeMux()
	mux.HandleFunc("/harness.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(harnessJS)
	})
	mux.HandleFunc("/harness/call", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Method string            `json:"method"`
			Args   []json.RawMessage `json:"args"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp, status := call(app, req.Method, req.Args)
		if status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/harness/events", func(w http.ResponseWriter, r *http.Request) {
		fl, can := w.(http.Flusher)
		if !can {
			http.Error(w, "no streaming", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		ch := ev.add()
		defer ev.drop(ch)
		_, _ = io.WriteString(w, ": ok\n\n")
		fl.Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case b := <-ch:
				_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
				fl.Flush()
			}
		}
	})
	mux.Handle("/", page)
	guard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != hostport { // another name for this address (DNS rebinding) is refused
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if k := r.URL.Query().Get("k"); k != "" && subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: key, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(key)) != 1 {
			http.Error(w, "forbidden: open the address the harness printed", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: guard, ReadHeaderTimeout: 10 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	desktop.Watch(ctx, app, 0)
	go desktop.CheckForUpdate(app)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			end("the server stopped: " + err.Error())
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; end("interrupted") }()
	if *quitAfter > 0 {
		time.AfterFunc(*quitAfter, func() { end("--quit-after") })
	}

	fmt.Printf("ui-harness: open http://%s/?k=%s\n", hostport, key)
	fmt.Printf("ui-harness: mode %s, password %s\n", *mode, password)
	if vaultFile != "" {
		fmt.Printf("ui-harness: vault %s\n", vaultFile)
		fmt.Printf("ui-harness: the command on it: ICEVAULT_VAULT=%s ICEVAULT_ROOT=%s icevault ... (the password on the terminal it asks on)\n", vaultFile, env.Root)
	}
	why := <-stop
	fmt.Fprintln(os.Stderr, "ui-harness: ending:", why)
	app.Lock()
	cancel()
	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(sctx)
	scancel()
	cleanup()
}
