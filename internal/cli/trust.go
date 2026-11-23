package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cybericebox/icevault/internal/project"
)

// A project description can name a script the tool runs (required-check). It runs only while this user trusts that very description and that
// very script: `icevault trust` records, under the path of the description, the resolved path of the script and the SHA-256 of the description
// bytes, a zero byte and the script bytes (trust.json in the user's configuration folder, 0600 in a 0700 folder). Before a run the script is read
// into memory once, the digest is computed again over those bytes and compared, and exactly those bytes run (from a private copy), so a change
// of either file, or a swap of the script between the check and the run, never runs unchecked code.

const trustName = "trust.json"

type trustEntry struct {
	Script string `json:"script,omitempty"` // the resolved path of the script, "" for a description without one
	Digest string `json:"sha256"`
}

func trustFile(getenv func(string) string) string {
	base := configBase(getenv)
	if base == "" {
		return ""
	}
	return filepath.Join(base, appDirName, trustName)
}

func readTrust(getenv func(string) string) map[string]trustEntry {
	out := map[string]trustEntry{}
	f := trustFile(getenv)
	if f == "" {
		return out
	}
	data, err := os.ReadFile(f) // #nosec G304 -- the user's own trust file
	if err == nil && json.Unmarshal(data, &out) != nil {
		return map[string]trustEntry{}
	}
	return out
}

func trustDigest(desc, script []byte) string {
	h := sha256.New()
	h.Write(desc)
	h.Write([]byte{0})
	h.Write(script)
	return hex.EncodeToString(h.Sum(nil))
}

// checked is a description and its script as read once from the disk: the bytes that are compared with the trust record and the bytes that run.
type checked struct {
	descPath string
	script   string // resolved path, "" when the description names no script
	interp   string // the interpreter found on the PATH
	data     []byte // the script bytes
	digest   string
}

// readChecked reads the description and resolves its required-check script: a regular file inside the checkout (links resolved, so a link
// that leads outside is refused), run with an allowed interpreter found on the PATH.
func readChecked(d *project.Description) (*checked, error) {
	p, err := filepath.Abs(d.Path)
	if err != nil {
		return nil, err
	}
	// the digest covers the very bytes d was parsed from: the interpreter, the arguments and the condition the run uses are the trusted ones,
	// whatever the file on the disk says by now
	desc := d.Raw()
	if len(desc) == 0 {
		return nil, fmt.Errorf("%s was not read from a file", p)
	}
	c := &checked{descPath: p}
	if rc := d.RequiredCheck; rc != nil {
		if c.script, c.interp, err = checkScript(d); err != nil {
			return nil, err
		}
		if c.data, err = os.ReadFile(c.script); err != nil { // #nosec G304 -- a script inside the checkout, checked above
			return nil, fmt.Errorf("the script %s cannot be read", rc.Script)
		}
	}
	c.digest = trustDigest(desc, c.data)
	return c, nil
}

// trusted says whether the user trusts the description and its script exactly as they were read.
func trusted(getenv func(string) string, c *checked) bool {
	rec, ok := readTrust(getenv)[c.descPath]
	return ok && rec.Script == c.script && rec.Digest == c.digest
}

// checkScript resolves the script of the required-check: a regular file inside the checkout and the interpreter on the PATH.
func checkScript(d *project.Description) (script, interp string, err error) {
	rc := d.RequiredCheck
	root, err := filepath.EvalSymlinks(checkoutDir(d))
	if err != nil {
		return "", "", errors.New("the checkout cannot be read")
	}
	script, err = filepath.EvalSymlinks(filepath.Join(checkoutDir(d), filepath.FromSlash(rc.Script)))
	if err != nil {
		return "", "", fmt.Errorf("the script %s is not there", rc.Script)
	}
	if !isUnder(script, root) {
		return "", "", fmt.Errorf("the script %s leads outside the checkout", rc.Script)
	}
	if st, err := os.Stat(script); err != nil || !st.Mode().IsRegular() {
		return "", "", fmt.Errorf("the script %s is not a file", rc.Script)
	}
	if !contains(project.Interpreters, rc.Interpreter) {
		return "", "", fmt.Errorf("the interpreter %q is not one of the allowed", rc.Interpreter)
	}
	interp, err = exec.LookPath(rc.Interpreter)
	if err != nil {
		return "", "", fmt.Errorf("%s is not installed", rc.Interpreter)
	}
	return script, interp, nil
}

// runChecked runs the checked script bytes: they are written to a private copy (0600 in a fresh 0700 folder) that the interpreter reads, so
// what runs is what was compared. python3 runs isolated (-I: no environment variables, no user site, no script folder on the path).
func runChecked(dir string, c *checked, interpName string, args []string) ([]byte, int, error) {
	tmp, err := os.MkdirTemp("", "icevault-check-")
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := os.Chmod(tmp, 0o700); err != nil {
		return nil, 0, err
	}
	copyPath := filepath.Join(tmp, filepath.Base(c.script))
	if err := os.WriteFile(copyPath, c.data, 0o600); err != nil {
		return nil, 0, err
	}
	argv := []string{c.interp}
	if interpName == "python3" {
		argv = append(argv, "-I")
	}
	argv = append(argv, copyPath)
	return runHook(dir, append(argv, args...))
}

// cmdTrust: trust [--forget]. Records (or forgets) the description of the checkout and its script as trusted by this user.
func cmdTrust(args []string, e *Env) error {
	forget := false
	for _, a := range args {
		switch a {
		case "--forget", "-forget":
			forget = true
		default:
			return &parseErr{msg: "trust takes only --forget"}
		}
	}
	d, err := e.description()
	if err != nil {
		return err
	}
	f := trustFile(e.Getenv)
	if f == "" {
		return fail("the configuration folder of this user is unknown: nothing was saved")
	}
	list := readTrust(e.Getenv)
	var c *checked
	if forget {
		p, err := filepath.Abs(d.Path)
		if err != nil {
			return fail("%v", err)
		}
		delete(list, p)
	} else {
		if c, err = readChecked(d); err != nil {
			return fail("not trusted: %v", err)
		}
		list[c.descPath] = trustEntry{Script: c.script, Digest: c.digest}
	}
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		return fail("the trust record could not be saved (%v)", pathErrText(err))
	}
	data, _ := json.MarshalIndent(list, "", "  ")
	if err := writeInto(f, 0o600, append(data, '\n')); err != nil {
		return err
	}
	if forget {
		fmt.Fprintf(e.Out, "no longer trusted: %s\n", d.Path)
		return nil
	}
	what := "it names no script"
	if c.script != "" {
		what = "the required-check runs " + d.RequiredCheck.Interpreter + " " + c.script
	}
	fmt.Fprintf(e.Out, "trusted: %s (%s; sha256 %s). A change of the description or the script needs icevault trust again.\n", c.descPath, what, c.digest)
	if c.script != "" {
		fmt.Fprintln(e.Out, "The record covers that one script: it runs alone, from a private copy. A file it sources, includes or runs from the checkout is not covered: read the script before you trust it.")
	}
	return nil
}

func contains(list []string, x string) bool {
	for _, l := range list {
		if l == x {
			return true
		}
	}
	return false
}
