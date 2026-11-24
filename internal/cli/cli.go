// Package cli is the command line of IceVault, the secrets vault tool: argument parsing, the password prompt, and the commands. All terminal I/O of the program is here;
// the vault logic is in pkg/vault.
package cli

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cybericebox/icevault/internal/password"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/version"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
	"golang.org/x/term"
)

// runModel is the single place where the settings-model commands enter.
func runModel(cmd string, args []string, e *Env) int {
	m := e.Model
	if m == nil {
		m = defaultModel{}
	}
	if c, ok := m.(checker); ok { // what the arguments, the files or the info file can refuse or answer is settled before any password is asked
		if rc, done, err := c.Check(e, cmd, args); err != nil {
			return e.fail(cmd, err)
		} else if done {
			return rc
		}
	}
	var v *vault.Vault
	if m.NeedsUnlock(cmd, args) {
		path, err := vaultPath(e)
		if err == nil {
			v, err = unlock(path, e)
		}
		if err != nil {
			e.report(err)
			return 1
		}
		defer v.Close()
	}
	rc, err := m.Run(e, cmd, args, v, e.Out)
	if err != nil {
		var pe *parseErr
		if errors.As(err, &pe) {
			e.reportUsage(cmd, pe)
			return 2
		}
		e.report(err)
		return 1
	}
	return rc
}

// reportUsage prints a command-line error that nobody printed yet, with the way to the usage.
func (e *Env) reportUsage(cmd string, pe *parseErr) {
	if pe.shown {
		return
	}
	fmt.Fprintf(e.Err, "icevault: %s\n", pe.msg)
	if _, ok := specs[cmd]; ok {
		fmt.Fprintf(e.Err, "usage: icevault %s --help\n", cmd)
	}
}

// fail reports an error of a command and returns its exit code: 2 for a wrong command line, else 1.
func (e *Env) fail(cmd string, err error) int {
	var pe *parseErr
	if errors.As(err, &pe) {
		e.reportUsage(cmd, pe)
		return 2
	}
	e.report(err)
	return 1
}

// NeedsOwner is the message of a command that needs the password and has no terminal.
const NeedsOwner = "needs the owner: the vault password (run this in your own terminal)"

// Env is everything the commands take from the outside; tests replace it.
type Env struct {
	// StdioIsTerminal says whether stdin or stdout is a terminal (nil: not asked, tests).
	StdioIsTerminal func() bool
	// In is the standard input (os.Stdin); AskConsole reads a password from the controlling terminal for a program whose stdin is a pipe.
	In         io.Reader
	AskConsole func(prompt string) ([]byte, error)
	Getenv     func(string) string
	Out        io.Writer
	Err        io.Writer
	// Ask returns what the person types without echo; it returns an error with NeedsOwner when there is no terminal.
	Ask func(prompt string) ([]byte, error)
	Now func() time.Time
	// Exec runs age and age-plugin-se for Touch ID. TouchID is true when the platform has it and the password is read from a real terminal.
	Exec    Runner
	TouchID bool
	// Model is the WIRING POINT for the commands that need the settings model (import, export, export-app, status, visibility, recover,
	// purge-plaintext, import-hcp, view --env). The model package implements it.
	Model Model
	// Root is the project checkout (ICEVAULT_ROOT, the folder above the working directory with a project description, or the saved one); ""
	// when it cannot be found.
	Root string
	// the project description, read once (description())
	desc    *project.Description
	descErr error
	// StartWindow starts the window program (tests replace it; nil replaces this process with it).
	StartWindow func(path string, argv, env []string) error
	// Rand is the source of randomness of generated passphrases (nil: crypto/rand; tests give a fixed one).
	Rand io.Reader
}

// DefaultEnv is the real process environment.
func DefaultEnv() *Env {
	return &Env{Getenv: os.Getenv, Out: os.Stdout, Err: os.Stderr, Ask: askTerminal, Now: time.Now, Root: findRoot(os.Getenv), In: os.Stdin, AskConsole: askConsole, Exec: execRunner{}, TouchID: touchIDPlatform && term.IsTerminal(int(os.Stdin.Fd())),
		StdioIsTerminal: func() bool { return term.IsTerminal(int(os.Stdin.Fd())) || term.IsTerminal(int(os.Stdout.Fd())) }}
}

// errExit is a refusal or a failure: one line, printed as "icevault: ...", exit 1.
type errExit struct{ msg string }

func (e errExit) Error() string { return e.msg }

func fail(format string, a ...any) error { return errExit{fmt.Sprintf(format, a...)} }

// notPorted is the exit code of a command the Go program does not have yet.
const notPorted = 2

// Model runs one settings-model command against an open vault. args are the command's arguments after its name. It prints to out and returns
// the exit code; a refusal is an error (printed as "icevault: ...", exit 1). The CLI asks the password and opens the vault before the call.
type Model interface {
	Run(e *Env, cmd string, args []string, v *vault.Vault, out io.Writer) (int, error)
	// NeedsUnlock is false for a command that asks no password (a dry run, a command that is not ported).
	NeedsUnlock(cmd string, args []string) bool
}

// modelCommands need the settings model; the rest of the commands are generic.
// The names of the commands that several files spell.
const (
	cmdImport     = "import"
	cmdStatus     = "status"
	cmdView       = "view"
	cmdExport     = "export"
	cmdExportApp  = "export-app"
	cmdVisibility = "visibility"
	cmdPurge      = "purge-plaintext"
	cmdRecover    = "recover"
	cmdImportHCP  = "import-hcp"
	actClose      = "close" // session close, and the close message of external serve
)

var modelCommands = map[string]bool{cmdImport: true, cmdExport: true, cmdExportApp: true, cmdStatus: true, cmdVisibility: true, cmdPurge: true, cmdRecover: true, cmdImportHCP: true, cmdView: true, cmdEnv: true}

// Run runs one command line (without the program name) and returns the exit code.
func Run(args []string, e *Env) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(e.Out, "icevault "+version.Version)
		return 0
	}
	if len(args) == 2 && args[0] == "help" { // icevault help COMMAND
		if _, ok := specs[args[1]]; ok {
			printCommandUsage(e.Out, args[1])
			return 0
		}
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(e.Out)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, rest := args[0], args[1:]
	// --vault PATH is accepted by every subcommand: the vault file; it wins over ICEVAULT_VAULT, which wins over the default
	if rest, vf, ok := takeFlag(rest, "vault"); ok {
		abs, err := filepath.Abs(vf)
		if err != nil || vf == "" {
			fmt.Fprintln(e.Err, "icevault: --vault needs a path")
			return 2
		}
		orig := e.Getenv
		e.Getenv = func(k string) string {
			if k == "ICEVAULT_VAULT" {
				return abs
			}
			return orig(k)
		}
		return runCommand(cmd, rest, e)
	}
	return runCommand(cmd, rest, e)
}

// takeFlag removes --name VALUE / --name=VALUE from args (the last one wins).
func takeFlag(args []string, name string) ([]string, string, bool) {
	var out []string
	val, found := "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" { // what follows is the command of `session run`
			out = append(out, args[i:]...)
			break
		}
		switch {
		case a == "--"+name || a == "-"+name:
			if i+1 < len(args) {
				val, found = args[i+1], true
				i++
			} else {
				found, val = true, ""
			}
		case strings.HasPrefix(a, "--"+name+"="):
			val, found = strings.TrimPrefix(a, "--"+name+"="), true
		default:
			out = append(out, a)
		}
	}
	return out, val, found
}

func runCommand(cmd string, rest []string, e *Env) int {
	if cmd == "usage-spec" { // hidden: the spec mise reads for completion
		fmt.Fprint(e.Out, UsageSpec())
		return 0
	}
	if rc, done := checkArgs(cmd, rest, e); done {
		return rc
	}
	if modelCommands[cmd] {
		return runModel(cmd, rest, e)
	}
	var err error
	switch cmd {
	case "init-vault":
		err = cmdInit(rest, e)
	case "touchid":
		err = cmdTouchID(rest, e)
	case "copies":
		err = cmdCopies(rest, e)
	case "copy":
		err = cmdCopy(rest, e)
	case "external":
		err = cmdExternal(rest, e)
	case "where":
		err = cmdWhere(rest, e)
	case "project":
		err = cmdProject(rest, e)
	case "trust":
		err = cmdTrust(rest, e)
	case "guard":
		err = cmdGuard(rest, e)
	case "settings":
		err = cmdSettings(rest, e)
	case "session":
		err = cmdSession(rest, e)
	case "keyfile":
		err = cmdKeyfile(rest, e)
	case "ui":
		err = cmdUI(rest, e)
	default:
		fmt.Fprintf(e.Err, "icevault: unknown command %q\n", cmd)
		usage(e.Err)
		return 2
	}
	if err == nil {
		return 0
	}
	var pe *parseErr
	var ec exitCode
	switch {
	case errors.As(err, &pe):
		e.reportUsage(cmd, pe)
		return 2
	case errors.As(err, &ec):
		return int(ec)
	}
	e.report(err)
	return 1
}

func usage(w io.Writer) { printOverview(w) }

// parseErr is a wrong command line (exit 2). shown is true when the message was printed already (by the flag package).
type parseErr struct {
	msg   string
	shown bool
}

func (p *parseErr) Error() string { return p.msg }

// parse reads flags and at most max positional arguments in any order, like argparse.
func parse(name string, args []string, e *Env, max int, setup func(fs *flag.FlagSet)) ([]string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.Err)
	if setup != nil {
		setup(fs)
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, &parseErr{err.Error(), true}
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) > max {
		fmt.Fprintf(e.Err, "icevault: %s: unexpected argument %q\n", name, pos[max])
		return nil, &parseErr{"unexpected argument", true}
	}
	return pos, nil
}

// vaultPath is ICEVAULT_VAULT, or the vault file of the project description (checkout: vault).
func vaultPath(e *Env) (string, error) {
	if v := e.Getenv("ICEVAULT_VAULT"); v != "" {
		return filepath.Abs(v)
	}
	d, err := e.description()
	if err != nil {
		return "", fail("the vault path is unknown: set ICEVAULT_VAULT, or ICEVAULT_ROOT (the project checkout with its description)")
	}
	return filepath.Join(checkoutDir(d), filepath.FromSlash(d.Checkout.Vault)), nil
}

// unlock asks the password once and opens the vault. The password is wiped as soon as the vault is open.
func unlock(path string, e *Env) (*vault.Vault, error) {
	if err := requireVault(path); err != nil {
		return nil, err
	}
	var v *vault.Vault
	if e.touchIDEnabled(path) {
		if pw := e.touchIDPassword(path); pw != nil {
			c := vault.Credentials{Password: pw, KeyFile: e.Getenv("ICEVAULT_KEYFILE")}
			var err error
			v, err = vault.Open(path, c)
			c.Wipe()
			if err != nil {
				v = nil
				fmt.Fprintln(e.Err, "the password behind Touch ID no longer opens the vault (`touchid enable` stores the new one); type it")
			}
		}
	}
	if v == nil {
		pw, err := e.Ask("Vault password: ")
		if err != nil {
			return nil, err
		}
		c := vault.Credentials{Password: pw, KeyFile: e.Getenv("ICEVAULT_KEYFILE")}
		v, err = vault.Open(path, c)
		c.Wipe()
		if err != nil {
			return nil, fail("%v", err)
		}
	}
	if w := copiesWarning(path, e.Now()); w != "" {
		fmt.Fprintln(e.Err, w)
	}
	return v, nil
}

func cmdInit(args []string, e *Env) error {
	var ms int
	var generate bool
	if _, err := parse("init-vault", args, e, 0, func(fs *flag.FlagSet) {
		fs.IntVar(&ms, "decryption-time", 0, "key derivation time in ms, 100 to 5000")
		fs.BoolVar(&generate, "generate", false, "make a random passphrase of six words, show it once and ask for it again")
	}); err != nil {
		return err
	}
	path, err := vaultPath(e)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return fail("%s already exists: not overwritten", path)
	}
	kf := e.Getenv("ICEVAULT_KEYFILE")
	if kf != "" {
		if _, err := os.Stat(kf); err != nil {
			return fail("the key file %s does not exist (`keyfile new PATH` makes one)", kf)
		}
	}
	var pw []byte
	if generate {
		pw, err = e.generatedPassword()
	} else {
		pw, err = e.askNewPassword(kf)
	}
	defer wipeBytes(pw)
	if err != nil {
		return err
	}
	name := "IceVault"
	if d, derr := e.description(); derr == nil {
		name = d.Name
	}
	if err := e.NewVault(path, pw, kf, name, time.Duration(ms)*time.Millisecond); err != nil {
		return err
	}
	fmt.Fprintf(e.Out, "made the vault %s (mode 0600). Next:\n"+
		"  1. write the master password on paper and keep it where the vault file is NOT; a lost password loses everything in the vault\n"+
		"  2. icevault import --env <env>      (an existing plaintext tree of the environment into the vault; asks the password once)\n"+
		"  3. icevault status --env <env>, then purge-plaintext once the vault is verified\n"+
		"  4. icevault copy --to <dir>         to at least two other places (another disk, a synced folder)\n", path)
	return nil
}

// askNewPassword asks the new password twice. Nothing is made before the policy accepted it.
func (e *Env) askNewPassword(kf string) ([]byte, error) {
	pw, err := e.Ask("Enter password to encrypt database: ")
	if err != nil {
		return nil, err
	}
	again, err := e.Ask("Repeat password: ")
	if err != nil {
		return pw, err
	}
	defer wipeBytes(again)
	if string(pw) != string(again) {
		return pw, fail("the passwords do not match; nothing was made")
	}
	if len(pw) == 0 && kf == "" {
		return pw, fail("an empty password needs a key file (ICEVAULT_KEYFILE); nothing was made")
	}
	if err := checkNewPassword(pw, kf); err != nil {
		return pw, err
	}
	return pw, nil
}

const generateTries = 3

// generatedPassword makes the passphrase, shows it once on the terminal (the stream of the prompts, never the output that may be redirected) and asks
// for it to be typed back, so that the person has really got it.
func (e *Env) generatedPassword() ([]byte, error) {
	r := e.Rand
	if r == nil {
		r = rand.Reader
	}
	p, err := password.PassphraseFrom(r)
	if err != nil {
		return nil, fail("%v", err)
	}
	pw := []byte(p) // the string p (shown, compared) cannot be wiped; the byte copies can, and are
	fmt.Fprintf(e.Err, "The new master password (shown once, here only):\n\n    %s\n\n"+
		"Write it down now and keep it away from the vault file. Nothing is saved anywhere for you.\n", p)
	for i := 0; i < generateTries; i++ {
		again, err := e.Ask("Type the password again to confirm you have it: ")
		if err != nil {
			wipeBytes(pw)
			return nil, err
		}
		same := string(again) == p
		wipeBytes(again)
		if same {
			return pw, nil
		}
		fmt.Fprintln(e.Err, "that is not the password shown above")
	}
	wipeBytes(pw)
	return nil, fail("the password was not typed back correctly; nothing was made")
}

// checkNewPassword is the policy of a new master password. An empty one stays possible only with a key file.
func checkNewPassword(pw []byte, keyFile string) error {
	if len(pw) == 0 && keyFile != "" {
		return nil
	}
	if err := password.Check(pw); err != nil {
		return fail("%v; nothing was made", err)
	}
	return nil
}

// NewVault makes the vault file at path: the policy for the password first, then the file (KDBX 4, mode 0600), its empty vault model and its
// info file. The window and init-vault both come here. Nothing is written when the policy refuses or the path is taken.
func (e *Env) NewVault(path string, pw []byte, keyFile, name string, decryption time.Duration) error {
	if _, err := os.Lstat(path); err == nil {
		return fail("%s already exists: not overwritten", path)
	}
	if err := checkNewPassword(pw, keyFile); err != nil {
		return err
	}
	c := vault.Credentials{Password: append([]byte(nil), pw...), KeyFile: keyFile}
	v, err := vault.Create(path, c, vault.CreateOptions{DecryptionTime: decryption, Name: name})
	if err != nil {
		return fail("the vault could not be made: %v", err)
	}
	err = vmodel.Write(v, &vmodel.Vault{}) // an empty vault of the vault model: its format version
	if err == nil {
		err = v.Save()
	}
	v.Close()
	if err != nil {
		return fail("the vault could not be made: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return writeInfo(path, freshInfo())
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func cmdKeyfile(args []string, e *Env) error {
	pos, err := parse("keyfile", args, e, 2, nil)
	if err != nil {
		return err
	}
	if len(pos) != 2 || pos[0] != "new" {
		return fail("usage: keyfile new PATH")
	}
	if err := vault.NewKeyFile(pos[1]); err != nil {
		return fail("the key file was not made: %v", err)
	}
	fmt.Fprintf(e.Out, "made the key file %s (KeePass XML v2, mode 0600). Keep a copy away from the vault; without it the vault cannot be opened. Use it with ICEVAULT_KEYFILE=%s\n", pos[1], pos[1])
	return nil
}

func cmdTouchID(args []string, e *Env) error {
	pos, err := parse("touchid", args, e, 1, nil)
	if err != nil {
		return err
	}
	if len(pos) != 1 || (pos[0] != "enable" && pos[0] != "disable" && pos[0] != "status") {
		return &parseErr{msg: "touchid needs enable, disable or status"}
	}
	path, err := vaultPath(e)
	if err != nil {
		return err
	}
	switch pos[0] {
	case "enable":
		return e.touchIDEnable(path)
	case "disable":
		e.touchIDDisable(path)
	default:
		e.touchIDStatus(path)
	}
	return nil
}

func cmdCopy(args []string, e *Env) error {
	var to string
	if _, err := parse("copy", args, e, 0, func(fs *flag.FlagSet) { fs.StringVar(&to, "to", "", "a directory") }); err != nil {
		return err
	}
	if to == "" {
		return &parseErr{msg: "copy needs --to DIR"}
	}
	path, err := vaultPath(e)
	if err != nil {
		return err
	}
	if err := requireVault(path); err != nil {
		return err
	}
	if st, err := os.Stat(to); err != nil || !st.IsDir() {
		return fail("%s is not a directory", to)
	}
	to, _ = filepath.Abs(to)
	sha, err := sha256File(path)
	if err != nil {
		return err
	}
	if err := copyFileSafely(path, to, filepath.Base(path), sha); err != nil {
		return fail("the copy %s does not match the vault (disk error?): not recorded", copyDest(path, to))
	}
	m := readInfo(path)
	if m == nil {
		m = freshInfo()
	}
	m.setCopy(to, sha, nowStamp())
	if err := writeInfo(path, m); err != nil {
		return err
	}
	if data, err := os.ReadFile(infoPath(path)); err == nil {
		_ = os.WriteFile(filepath.Join(to, filepath.Base(infoPath(path))), data, 0o644)
	}
	fmt.Fprintf(e.Out, "%s  %s\n", sha, copyDest(path, to))
	return nil
}

func cmdCopies(args []string, e *Env) error {
	pos, err := parse("copies", args, e, 2, nil)
	if err != nil {
		return err
	}
	if len(pos) == 0 || (pos[0] != "add" && pos[0] != "remove" && pos[0] != "list") {
		return &parseErr{msg: "copies needs add, remove or list"}
	}
	path, err := vaultPath(e)
	if err != nil {
		return err
	}
	action := pos[0]
	if action == "list" {
		listCopies(path, e.Out)
		return nil
	}
	if len(pos) < 2 {
		return fail("copies %s needs a folder", action)
	}
	dir, _ := filepath.Abs(pos[1])
	m := readInfo(path)
	if action == "add" {
		if err := requireVault(path); err != nil {
			return err
		}
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return fail("%s is not reachable now (not a directory): mount or create it first", dir)
		}
		a, _ := filepath.EvalSymlinks(dir)
		b, _ := filepath.EvalSymlinks(filepath.Dir(path))
		if a == b {
			return fail("that is the vault's own folder: a copy there is not a copy")
		}
		if m == nil {
			m = freshInfo()
		}
		for _, d := range m.destinations() {
			if d == dir {
				return fail("%s is already a destination", dir)
			}
		}
		list := []any{}
		for _, d := range m.destinations() {
			list = append(list, d)
		}
		m["destinations"] = append(list, dir)
		if err := writeInfo(path, m); err != nil {
			return err
		}
		where := "the SAME volume as the vault: purge-plaintext will not count it"
		if !sameVolume(path, dir) {
			where = "another volume"
		}
		fmt.Fprintf(e.Out, "destination added: %s (%s)\n", dir, where)
		if len(makeCopies(path, e.Out)) == 0 {
			fmt.Fprintln(e.Out, "no copy was written (it already has the current one, or it is not writable)")
		}
		return nil
	}
	found := false
	list := []any{}
	for _, d := range m.destinations() {
		if d == dir {
			found = true
			continue
		}
		list = append(list, d)
	}
	if !found {
		return fail("%s is not a destination", dir)
	}
	m["destinations"] = list
	if err := writeInfo(path, m); err != nil {
		return err
	}
	fmt.Fprintf(e.Out, "destination removed: %s (its files are left where they are)\n", dir)
	return nil
}

// errorFileVar names a file that receives the last error line instead of stderr: a calling script reads the refusal from it, so that the prompt and
// the progress lines of the command stay on the terminal and the refusal is not shown twice.
const errorFileVar = "ICEVAULT_ERROR_FILE"

// report prints the one-line refusal of a command: "icevault: <text>" on stderr, or into the file the caller named.
func (e *Env) report(err error) {
	line := fmt.Sprintf("icevault: %s\n", err)
	if p := e.Getenv(errorFileVar); p != "" {
		if f, ferr := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600); ferr == nil {
			_, _ = f.WriteString(strings.TrimPrefix(line, "icevault: "))
			_ = f.Close()
			return
		}
	}
	fmt.Fprint(e.Err, line)
}
