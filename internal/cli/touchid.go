package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cybericebox/icevault/pkg/vault"
)

// Touch ID: the master password is encrypted with `age` to a Secure Enclave key made by `age-plugin-se` (access control
// "any biometry"). The key never leaves the chip; decrypting needs a fingerprint at that moment. What is stored on disk, on this Mac only:
//   <dir>/<id>.identity   the enclave key handle (useless on another machine)
//   <dir>/<id>.age        the password encrypted to it
// The password itself is never written to a file: it goes to age on stdin. No cgo: both tools are run as programs.

const (
	touchIDOff      = "ICEVAULT_NO_TOUCHID"
	touchIDDirVar   = "ICEVAULT_TOUCHID_DIR"
	touchIDTimeout  = 60 * time.Second
	oldKeySuffix    = ".touchid.identity"
	oldBlobSuffix   = ".touchid.age"
	touchIDNotHere  = "Touch ID unlock is not available on this platform: the password is asked every time"
	toolInstallHint = "brew install age age-plugin-se"
)

// Runner runs a program. Tests replace it; the real one is execRunner.
type Runner interface {
	// Run starts name with args, feeds stdin, and returns stdout and the exit code. A program that cannot start returns an error.
	Run(name string, args []string, stdin []byte, timeout time.Duration) (out []byte, code int, err error)
	// Has says whether the program is installed.
	Has(name string) bool
}

// execRunner runs programs. With no dirs it starts them by name through PATH (the command line, in the owner's own shell). With dirs it looks only in
// those absolute folders and only takes a program that is a regular executable of this user or root that nobody else can write, in a folder nobody
// else can write into (the window: a program started from Finder has the minimal launchd PATH, and PATH is not a place to trust for a program that
// is handed the master password). The folders are also what the child gets as its PATH, so that `age` finds `age-plugin-se` beside itself.
type execRunner struct{ dirs []string }

// KnownToolDirs are the Homebrew prefixes of Apple silicon and Intel Macs.
var KnownToolDirs = []string{"/opt/homebrew/bin", "/usr/local/bin"}

var errTimeout = errors.New("timeout")

func (r execRunner) find(name string) (string, bool) {
	if len(r.dirs) == 0 {
		p, err := exec.LookPath(name)
		return p, err == nil
	}
	if name != filepath.Base(name) {
		return "", false
	}
	for _, d := range r.dirs {
		p := filepath.Join(d, name)
		if trustedProgram(d, p) {
			return p, true
		}
	}
	return "", false
}

func (r execRunner) Has(name string) bool { _, ok := r.find(name); return ok }

func (r execRunner) Run(name string, args []string, stdin []byte, timeout time.Duration) ([]byte, int, error) {
	path, found := r.find(name)
	if !found {
		return nil, -1, errNoProgram
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- path is a verified absolute path
	if len(r.dirs) > 0 {
		cmd.Env = append(withoutPath(os.Environ()), "PATH="+strings.Join(append(append([]string{}, r.dirs...), "/usr/bin", "/bin"), ":"))
	}
	cmd.Stdin = bytes.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, -1, errTimeout
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.Bytes(), ee.ExitCode(), nil
	}
	if err != nil {
		return nil, -1, err
	}
	return out.Bytes(), 0, nil
}

var errNoProgram = errors.New("the program is not installed")

func withoutPath(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, "PATH=") {
			out = append(out, kv)
		}
	}
	return out
}

// TouchIDMissingTools names the programs Touch ID needs that are not installed (empty when all are).
func (e *Env) TouchIDMissingTools() []string {
	var miss []string
	for _, t := range []string{"age", "age-plugin-se"} {
		if !e.Exec.Has(t) {
			miss = append(miss, t)
		}
	}
	return miss
}

func (e *Env) touchIDDir() string {
	if d := e.Getenv(touchIDDirVar); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "cybericebox", "touchid")
}

// touchIDKey is what the binding is keyed on: the first 16 hex characters of the sha256 of the vault's real path.
func touchIDKey(vaultFile string) string {
	real, err := filepath.EvalSymlinks(vaultFile)
	if err != nil {
		real, _ = filepath.Abs(vaultFile)
	}
	sum := sha256.Sum256([]byte(real))
	return hex.EncodeToString(sum[:])[:16]
}

func (e *Env) touchIDFiles(vaultFile string) (key, blob string) {
	d, id := e.touchIDDir(), touchIDKey(vaultFile)
	return filepath.Join(d, id+".identity"), filepath.Join(d, id+".age")
}

func isFile(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }

func (e *Env) touchIDMakeDir() error {
	d := e.touchIDDir()
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	return os.Chmod(d, 0o700)
}

// touchIDMigrate moves a binding an earlier version put beside the vault into the folder (once; never over an existing binding).
func (e *Env) touchIDMigrate(vaultFile string) {
	oldK, oldB := vaultFile+oldKeySuffix, vaultFile+oldBlobSuffix
	newK, newB := e.touchIDFiles(vaultFile)
	if !isFile(oldK) || !isFile(oldB) {
		return
	}
	for _, f := range []string{newK, newB} {
		if _, err := os.Lstat(f); err == nil {
			return
		}
	}
	if e.touchIDMakeDir() != nil {
		return
	}
	for _, pair := range [][2]string{{oldK, newK}, {oldB, newB}} {
		if os.Rename(pair[0], pair[1]) == nil {
			_ = os.Chmod(pair[1], 0o600)
		}
	}
}

func (e *Env) touchIDEnabled(vaultFile string) bool {
	if !e.TouchID || e.Getenv(touchIDOff) == "1" {
		return false
	}
	e.touchIDMigrate(vaultFile)
	k, b := e.touchIDFiles(vaultFile)
	return isFile(k) && isFile(b)
}

// touchIDPassword is the master password from the binding, or nil: any failure (no touch in time, cancelled, no sensor, no plug-in) ends in nil,
// and the caller asks for the password.
func (e *Env) touchIDPassword(vaultFile string) []byte {
	key, blob := e.touchIDFiles(vaultFile)
	fmt.Fprintln(e.Err, "Touch ID: touch the sensor to unlock the vault (Ctrl+C to type the password instead)")
	out, code, err := e.Exec.Run("age", []string{"--decrypt", "-i", key, blob}, nil, touchIDTimeout)
	if errors.Is(err, errTimeout) {
		fmt.Fprintln(e.Err, "Touch ID: no touch in time; type the password")
		return nil
	}
	if err != nil || code != 0 || len(out) == 0 {
		fmt.Fprintln(e.Err, "Touch ID did not unlock; type the password")
		return nil
	}
	return out
}

func (e *Env) touchIDEnable(vaultFile string) error {
	if !e.TouchID {
		return fail(touchIDNotHere)
	}
	if err := requireVault(vaultFile); err != nil {
		return err
	}
	for _, tool := range []string{"age", "age-plugin-se"} {
		if !e.Exec.Has(tool) {
			return fail("%s is not installed: %s", tool, toolInstallHint)
		}
	}
	pw, err := e.Ask("Vault password (to store behind Touch ID): ")
	if err != nil {
		return err
	}
	defer wipeBytes(pw)
	c := vault.Credentials{Password: append([]byte(nil), pw...), KeyFile: e.Getenv("ICEVAULT_KEYFILE")}
	v, err := vault.Open(vaultFile, c) // a wrong password stops here
	c.Wipe()
	if err != nil {
		return fail("%v", err)
	}
	v.Close()
	if err := e.touchIDStore(vaultFile, pw); err != nil {
		return err
	}
	key, blob := e.touchIDFiles(vaultFile)
	fmt.Fprintf(e.Out, "Touch ID unlock is on: %s (the key is bound to this Mac's chip) and %s. Change the vault password: run `touchid enable` again. Off: `touchid disable`\n", key, blob)
	return nil
}

// touchIDStore makes the Secure Enclave key and keeps the password encrypted to it (the password goes to age on stdin, never to a file). The caller has
// checked that the password opens the vault, and that the tools are there.
func (e *Env) touchIDStore(vaultFile string, pw []byte) error {
	if err := e.touchIDMakeDir(); err != nil {
		return fail("the Touch ID folder cannot be made: %v", err)
	}
	key, blob := e.touchIDFiles(vaultFile)
	if _, code, err := e.Exec.Run("age-plugin-se", []string{"keygen", "--access-control", "any-biometry", "-o", key}, nil, touchIDTimeout); err != nil || code != 0 {
		return fail("age-plugin-se could not make a Secure Enclave key (a Mac with Touch ID and a Secure Enclave is needed)")
	}
	_ = os.Chmod(key, 0o600)
	rec, code, err := e.Exec.Run("age-plugin-se", []string{"recipients", "-i", key}, nil, touchIDTimeout)
	recipient := strings.TrimSpace(string(rec))
	if err != nil || code != 0 || recipient == "" {
		return fail("age-plugin-se gave no recipient for the new key")
	}
	if _, code, err := e.Exec.Run("age", []string{"-r", recipient, "-o", blob}, pw, touchIDTimeout); err != nil || code != 0 {
		return fail("age could not encrypt the password to the Secure Enclave key")
	}
	_ = os.Chmod(blob, 0o600)
	return nil
}

func (e *Env) touchIDStatus(vaultFile string) {
	if !e.TouchID {
		fmt.Fprintln(e.Out, "Touch ID unlock: off ("+touchIDNotHere+")")
		return
	}
	e.touchIDMigrate(vaultFile)
	key, blob := e.touchIDFiles(vaultFile)
	have := [][2]any{{"identity", isFile(key)}, {"encrypted password", isFile(blob)}}
	on := e.touchIDEnabled(vaultFile)
	state := "off"
	if on {
		state = "ON"
	}
	extra := ""
	if e.Getenv(touchIDOff) == "1" && isFile(key) && isFile(blob) {
		extra = " (ignored: " + touchIDOff + "=1)"
	}
	fmt.Fprintf(e.Out, "Touch ID unlock: %s%s\n", state, extra)
	real, err := filepath.EvalSymlinks(vaultFile)
	if err != nil {
		real, _ = filepath.Abs(vaultFile)
	}
	fmt.Fprintf(e.Out, "  place: %s/%s.* (this Mac only; keyed on the vault's real path: %s)\n", e.touchIDDir(), touchIDKey(vaultFile), real)
	for _, h := range have {
		w := "absent"
		if h[1].(bool) {
			w = "present"
		}
		fmt.Fprintf(e.Out, "  %s: %s\n", h[0], w)
	}
	others := map[string]bool{}
	if ents, err := os.ReadDir(e.touchIDDir()); err == nil {
		for _, en := range ents {
			if id, _, ok := strings.Cut(en.Name(), "."); ok && id != touchIDKey(vaultFile) {
				others[id] = true
			}
		}
	}
	if len(others) > 0 {
		fmt.Fprintf(e.Out, "  %d binding(s) for other vault paths in the same folder (a moved or removed vault leaves one: `touchid disable` on that path removes it)\n", len(others))
	}
	for _, t := range []string{"age", "age-plugin-se"} {
		w := "installed"
		if !e.Exec.Has(t) {
			w = "NOT installed (" + toolInstallHint + ")"
		}
		fmt.Fprintf(e.Out, "  %s: %s\n", t, w)
	}
}

func (e *Env) touchIDDisable(vaultFile string) {
	n := 0
	k, b := e.touchIDFiles(vaultFile)
	for _, f := range []string{k, b} {
		if _, err := os.Lstat(f); err == nil && os.Remove(f) == nil {
			n++
		}
	}
	fmt.Fprintf(e.Out, "Touch ID unlock is off (%d file(s) removed)\n", n)
}
