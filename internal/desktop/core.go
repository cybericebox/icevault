// Package desktop is the backend of the desktop window of IceVault: the rules of the settings screen, as bound methods
// of one App that the Wails window calls, in front of a small Core interface the vault core implements.
//
// The window is a view of the core. While locked, the App holds no core and every data method answers 423. It opens in view mode: every write answers
// 403 until the owner switches to edit mode. A password goes in by one call, is wiped from the byte slice after use and is never logged or put in an error.
package desktop

import "errors"

// Error is a refusal of the model or the vault with an HTTP-like status. It is an answer for the page, not a crash. It mirrors sm.ModelError.
type Error struct {
	Status  int
	Message string
	Code    string
	Params  map[string]any
	Reload  any
	Confirm any
}

// Error is for logs and tests only: Message is never sent to the page, which translates Code.
func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Message
}

// ErrWrongPassword is what Unlocker.Open returns for a password (or key file) that does not open the vault.
var ErrWrongPassword = errors.New("wrong password")

// Core is the unlocked vault as the window needs it. The operations carry the names of the endpoints of the browser screen (without "/api/").
//
// Read ops (no write, allowed in view mode): "nav", "item" {section, name, site}, "compare" {section, name, with}, "references", "pull-candidates" {name},
// "shared", "visibility" {key}, "preview-value" {value, visibility, site}.
//
// Write ops (the App refuses them in view mode, so the core never sees one there): "set", "meta", "seal", "create-section", "update-section",
// "retire-section", "create-item", "update-item", "uses", "create-group", "rename-group", "generate", "generate-seal", "scope", "make-global",
// "move-entry", "create-site", "add-site", "pull-globals", "apply-shared", "group-sites", "item-sites", "site-type", "duplicates", "duplicates-apply",
// "create-entry", "retire-entry", "restore-entry", "retire-group", "create-missing", "retire-item", "retire-file", "create-file", "replace-file",
// "managed" (the owner sets who manages a variable by hand).
// For create-file and replace-file the key "data" holds the decoded bytes ([]byte). A write returns nil (the App answers {"ok": true}) or the payload to answer.
//
// Errors: *Error (with a Code) for a refusal; any other error is classified by Classify into a code. The text of an error never reaches the page.
type Core interface {
	Read(op string, args map[string]any) (any, error)
	Write(op string, args map[string]any) (any, error)
	// Reveal returns one value. The App asks for the extra check (Touch ID) after this call and drops the value when it is refused.
	Reveal(section, name, group, key string) (string, error)
	// Lock drops everything decrypted: the snapshot and the password held inside.
	Lock()
}

// Syncer is a Core that can notice that another writer (the command line, a second window) saved the vault file while the window is unlocked. Sync reads
// the file again when it changed (full: compare the bytes even when the file looks the same) and reports whether the Core now holds what is on disk.
// The window's own writes never count as a change. A Core without it (the demo) is never reloaded.
type Syncer interface {
	Sync(full bool) (changed bool, err error)
}

// Unlocker opens the vault. The key file, when the vault uses one, is the core's business (a path from its own settings), never the page's.
type Unlocker interface {
	// Open opens the vault with the master password (the caller wipes the slice afterwards). ErrWrongPassword for a wrong one.
	Open(password []byte) (Core, error)
	// Touch raises the system Touch ID dialog and returns the master password; (nil, nil) when it was refused, timed out or cancelled.
	Touch() ([]byte, error)
	// HasKeyFile tells the page that a key file is used too.
	HasKeyFile() bool
}

// Corrector is a Core that applied the rule of who manages a variable when it was opened (the stored managed-by that disagreed with the rule was
// rewritten and saved). Corrected answers how many entries changed, once; the App puts the count into the answer of the unlock, and the page says it
// in one line. A Core without it corrects nothing.
type Corrector interface {
	Corrected() int
}

// Clipboard is the system clipboard (Wails runtime in the window, a fake in tests).
type Clipboard interface {
	Set(text string) error
	Get() (string, error)
}

// VisDefaulter is a Core that knows the visibility a new variable of that name gets (the project description, else the name rule): a variable that is
// secret by that rule is never made plain through the agent API.
type VisDefaulter interface {
	DefaultVisibility(key string) string
}

// SecretCounter is a Core that can say whether an environment holds a filled secret or a file anywhere, also in the groups of a site kind that no site
// shows (the answer of "nav" has only the group of the kind in use).
type SecretCounter interface {
	EnvHoldsSecrets(env string) bool
}

// ConnNameBinder is a Core that knows which connection names the project description binds to a use (the name it gives a connection it makes, the name a
// program asks for): a connection made or renamed to such a name is linked by the commands that fill an environment, so it changes where they link.
type ConnNameBinder interface {
	BoundConnectionName(name string) bool
	// ConnectionKindNeeded says whether a use of the project description needs a connection of that kind (the commands that fill an environment link the only one of a kind).
	ConnectionKindNeeded(kind string) bool
}
