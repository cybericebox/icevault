//go:build desktop

// Command icevault-desktop is the desktop window of IceVault, the secrets vault tool (Wails v2: Go backend, system webview). The page is plain HTML/CSS/JS embedded below.
//
// Build the window (cgo and the platform webview are needed): go build -tags desktop,production ./cmd/icevault-desktop
// A start-and-quit check without any real vault: icevault-desktop --demo (throwaway vaults with a sample in a temp folder, password "demo").
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/cybericebox/icevault/internal/agentapi"
	"github.com/cybericebox/icevault/internal/appbundle"
	"github.com/cybericebox/icevault/internal/cliinstall"
	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/update"
	"github.com/cybericebox/icevault/internal/version"
)

//go:embed frontend
var frontendFS embed.FS

// title is the product name, the same as CFBundleName of the application bundle (Dock, menu bar, window title).
const title = "IceVault"

// wailsClipboard is the system clipboard through the Wails runtime.
type wailsClipboard struct{ ctx context.Context }

func (c wailsClipboard) Set(s string) error   { return runtime.ClipboardSetText(c.ctx, s) }
func (c wailsClipboard) Get() (string, error) { return runtime.ClipboardGetText(c.ctx) }

// lateClipboard is the clipboard that exists once the window has started (the App is built before the runtime context is).
type lateClipboard struct {
	mu    sync.Mutex
	inner desktop.Clipboard
}

func (c *lateClipboard) set(in desktop.Clipboard) { c.mu.Lock(); c.inner = in; c.mu.Unlock() }
func (c *lateClipboard) get() (desktop.Clipboard, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner == nil {
		return nil, errors.New("no clipboard yet")
	}
	return c.inner, nil
}
func (c *lateClipboard) Set(s string) error {
	in, err := c.get()
	if err != nil {
		return err
	}
	return in.Set(s)
}
func (c *lateClipboard) Get() (string, error) {
	in, err := c.get()
	if err != nil {
		return "", err
	}
	return in.Get()
}

// quiet drops every log line of the shell: a bound call can carry a password or a value, so nothing is logged at all.
type quiet struct{}

func (quiet) Print(string)   {}
func (quiet) Trace(string)   {}
func (quiet) Debug(string)   {}
func (quiet) Info(string)    {}
func (quiet) Warning(string) {}
func (quiet) Error(string)   {}
func (quiet) Fatal(string)   { os.Exit(1) }

var _ logger.Logger = quiet{}

func main() {
	demo := flag.Bool("demo", false, "use a throwaway vault of the example project (password \"demo\") instead of the real vaults; deleted at the end")
	smoke := flag.Duration("quit-after", 0, "end the program after this time (a start-and-quit check)")
	focus := flag.String("env", "", "the environment to open first")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("icevault-desktop " + version.Version)
		return
	}

	frontend, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		fmt.Fprintln(os.Stderr, "icevault-desktop: embedded page missing")
		os.Exit(1)
	}
	mode := ""
	if *demo {
		mode = "demo"
	}
	vaults, first, cleanup, err := connect(mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, "icevault-desktop: the demo vault could not be made")
		os.Exit(1)
	}
	defer cleanup()
	var cliInst desktop.CLIInstaller
	var upd *update.Updater
	var updater desktop.Updater // stays a nil interface in the demo
	if !*demo {
		cliInst = cliinstall.New()
		settings := ""
		if base, err := os.UserConfigDir(); err == nil {
			settings = filepath.Join(base, appbundle.Identifier, "update.json")
		}
		upd = update.New(version.Version, settings)
		updater = upd
	}

	clip := &lateClipboard{}
	var ctx context.Context
	var pick desktop.Picker
	var pickSave desktop.SavePicker
	if !*demo { // the demo opens no vault file: its list is made up
		pick = func(kind, title string) (string, error) {
			if ctx == nil {
				return "", errors.New("the window has not started")
			}
			if kind == "folder" {
				return runtime.OpenDirectoryDialog(ctx, runtime.OpenDialogOptions{Title: title})
			}
			return runtime.OpenFileDialog(ctx, runtime.OpenDialogOptions{Title: title, Filters: []runtime.FileFilter{{DisplayName: "KeePass (*.kdbx)", Pattern: "*.kdbx"}}})
		}
		// the place of a new vault and of its recovery kit; the dialog itself asks before replacing a file, and nothing is written before the person chose
		pickSave = func(title, dir, name string) (string, error) {
			if ctx == nil {
				return "", errors.New("the window has not started")
			}
			return runtime.SaveFileDialog(ctx, runtime.SaveDialogOptions{Title: title, DefaultDirectory: dir, DefaultFilename: name, CanCreateDirectories: true})
		}
	}
	// the project description (read once, never written): also in the demo
	pickDescription := func(title string) (string, error) {
		if ctx == nil {
			return "", errors.New("the window has not started")
		}
		return runtime.OpenFileDialog(ctx, runtime.OpenDialogOptions{Title: title, Filters: []runtime.FileFilter{{DisplayName: "YAML (*.yaml, *.yml)", Pattern: "*.yaml;*.yml"}}})
	}
	agentDir := ""
	if !*demo { // the demo must not take the socket of a real window
		agentDir = agentapi.Dir(os.Getenv)
	}
	app := desktop.New(desktop.Options{AgentDir: agentDir, Vaults: vaults, Vault: first, Pick: pick, PickSave: pickSave, Maker: makerFor(vaults), PickDescription: pickDescription, Focus: *focus, Clipboard: clip, CLI: cliInst,
		Update: updater, OpenURL: func(url string) {
			if ctx != nil {
				runtime.BrowserOpenURL(ctx, url)
			}
		},
		Quit: func() {
			if ctx != nil {
				runtime.Quit(ctx)
			}
		}, Say: func(text string) { fmt.Fprintln(os.Stderr, "settings screen:", text) },
		// a reload after another writer saved the vault reaches the page at once (the page also sees it in the rev of its ping)
		Notify: func(event string, data any) {
			if ctx != nil {
				runtime.EventsEmit(ctx, event, data)
			}
		}})

	err = wails.Run(&options.App{
		Title: title, Width: 1280, Height: 860, MinWidth: 900, MinHeight: 600,
		AssetServer: desktop.Assets(frontend),
		Bind:        []any{app},
		Logger:      quiet{},
		LogLevel:    logger.ERROR, LogLevelProduction: logger.ERROR,
		EnableDefaultContextMenu:         false, // no inspect element, no reload
		EnableFraudulentWebsiteDetection: false,
		Debug:                            options.Debug{OpenInspectorOnStartup: false},
		Mac: &mac.Options{WebviewIsTransparent: false, WindowIsTranslucent: false,
			// a .kdbx file opened with IceVault in Finder (Open With, or a double click where IceVault is the default): chosen on the lock screen;
			// the vault that is open is locked first. Info.plist declares the type (internal/appbundle).
			OnFileOpen: func(path string) { desktop.OpenFile(app, path) }},
		OnStartup: func(c context.Context) {
			ctx = c
			clip.set(wailsClipboard{c})
			setDockIcon()
			desktop.Watch(c, app, 0)
			go desktop.CheckForUpdate(app) // once a day at most, when it is on; never in the demo
			if *smoke > 0 {
				time.AfterFunc(*smoke, func() { runtime.Quit(c) })
			}
		},
		OnShutdown: func(context.Context) {
			app.Lock()
			if upd != nil {
				upd.Discard() // a new copy that was downloaded but not put in place
			}
		},
	})
	if err != nil {
		cleanup()
		fmt.Fprintln(os.Stderr, "icevault-desktop: could not open the window")
		os.Exit(1)
	}
}
