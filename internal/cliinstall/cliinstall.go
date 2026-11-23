// Package cliinstall links the icevault command, which the application bundle carries beside the window program, into a directory of the user's PATH.
//
// It is a symbolic link and nothing else: no copy, no change of a profile file, no privileged helper. The directory is /usr/local/bin when this user can write
// there, else ~/.local/bin (made when needed). It never writes through an existing link and never replaces a file that is not a link.
package cliinstall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Name is the command.
const Name = "icevault"

// The states of the command.
const (
	NotInstalled = "not_installed" // no link in a candidate directory
	Installed    = "installed"     // the link points to the program of this application
	Elsewhere    = "elsewhere"     // a link points to another program (an older copy of the application, a development build)
	Blocked      = "blocked"       // a file that is not a link is in the way
	Unavailable  = "unavailable"   // this window does not run from an application bundle, or from a translocated copy
)

// Error is a refusal with a code the window translates (srv.<code>) and its parameters.
type Error struct {
	Code   string
	Params map[string]any
}

func (e *Error) Error() string { return e.Code }

func refuse(code string, kv ...any) *Error {
	p := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		p[kv[i].(string)] = kv[i+1]
	}
	return &Error{Code: code, Params: p}
}

// Status is what the window shows.
type Status struct {
	State  string `json:"state"`
	Dir    string `json:"dir"`     // where the link is (or would be made)
	Link   string `json:"link"`    // the path of the link
	Target string `json:"target"`  // where an existing link points
	OnPath bool   `json:"on_path"` // Dir is in the PATH of a login shell
	// PathKnown is false when the PATH of a login shell could not be read; the window then does not say it is missing.
	PathKnown bool   `json:"path_known"`
	Code      string `json:"code,omitempty"` // why the state is Unavailable
}

// Installer finds the program and the directories. The fields are replaced in tests.
type Installer struct {
	// Source is the icevault program inside the bundle ("" when the window is not in a bundle).
	Source string
	// Dirs are the candidate directories in order of preference.
	Dirs []string
	// Home is the user's home: only a directory below it is made when it does not exist.
	Home string
	// PathDirs returns the directories of the PATH of a login shell, or nil when they cannot be found.
	PathDirs func() []string
}

// New is the installer of the running window: the program next to the window's own, /usr/local/bin and ~/.local/bin, the PATH of the login shell.
func New() *Installer {
	in := &Installer{PathDirs: LoginShellPath}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			cand := filepath.Join(filepath.Dir(real), Name)
			if st, err := os.Stat(cand); err == nil && st.Mode().IsRegular() {
				in.Source = cand
			}
		}
	}
	in.Dirs = []string{"/usr/local/bin"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		in.Home = home
		in.Dirs = append(in.Dirs, filepath.Join(home, ".local", "bin"))
	}
	return in
}

// source checks the program that would be linked: a regular executable file, not in a translocated copy of the application (macOS runs a downloaded,
// quarantined application from a random read-only path that is gone when the application quits; a link to it would break).
func (in *Installer) source() (string, *Error) {
	if in.Source == "" {
		return "", refuse("cli_unavailable")
	}
	real, err := filepath.EvalSymlinks(in.Source)
	if err != nil || !filepath.IsAbs(real) {
		return "", refuse("cli_unavailable")
	}
	if strings.Contains(real, "/AppTranslocation/") {
		return "", refuse("cli_translocated")
	}
	st, err := os.Stat(real)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return "", refuse("cli_unavailable")
	}
	return real, nil
}

func writable(dir string) bool {
	st, err := os.Stat(dir)
	return err == nil && st.IsDir() && syscall.Access(dir, 2) == nil // W_OK
}

// pickDir is the first candidate this user can write to without any privilege, or a candidate that does not exist yet and whose parent can be written
// (~/.local/bin in a home that has no .local yet).
func (in *Installer) pickDir() (string, bool, *Error) {
	for _, d := range in.Dirs {
		if writable(d) {
			return d, false, nil
		}
	}
	// a directory under the home that does not exist yet (~/.local/bin in a home with no .local) is made, when its nearest existing parent is writable
	for _, d := range in.Dirs {
		if _, err := os.Stat(d); err == nil || in.Home == "" || !strings.HasPrefix(d, in.Home+string(filepath.Separator)) {
			continue
		}
		anc := filepath.Dir(d)
		for anc != in.Home {
			if _, err := os.Stat(anc); err == nil {
				break
			}
			anc = filepath.Dir(anc)
		}
		if writable(anc) {
			return d, true, nil
		}
	}
	return "", false, refuse("cli_no_dir", "dirs", strings.Join(in.Dirs, ", "))
}

// look reports what is at link: "" (nothing), the target of a link, or blocked for something that is not a link.
func look(link string) (target string, state string) {
	st, err := os.Lstat(link)
	if err != nil {
		return "", ""
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return "", Blocked
	}
	t, err := os.Readlink(link)
	if err != nil {
		return "", Elsewhere
	}
	if !filepath.IsAbs(t) {
		t = filepath.Join(filepath.Dir(link), t)
	}
	return filepath.Clean(t), Elsewhere
}

// Status looks at the candidate directories; it changes nothing.
func (in *Installer) Status() Status {
	src, serr := in.source()
	st := Status{State: NotInstalled}
	if serr != nil {
		st.State, st.Code = Unavailable, serr.Code
	}
	for _, d := range in.Dirs {
		link := filepath.Join(d, Name)
		target, state := look(link)
		if state == "" {
			continue
		}
		st.Dir, st.Link, st.Target = d, link, target
		switch {
		case serr != nil:
		case state == Blocked:
			st.State = Blocked
		case sameFile(target, src):
			st.State = Installed
		default:
			st.State = Elsewhere
		}
		break
	}
	if st.Dir == "" && serr == nil {
		if d, _, err := in.pickDir(); err == nil {
			st.Dir, st.Link = d, filepath.Join(d, Name)
		}
	}
	if st.Dir != "" && in.PathDirs != nil {
		if dirs := in.PathDirs(); dirs != nil {
			st.PathKnown = true
			for _, p := range dirs {
				if filepath.Clean(p) == filepath.Clean(st.Dir) {
					st.OnPath = true
				}
			}
		}
	}
	return st
}

func sameFile(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && ra == rb
}

// Install makes the link. A link that points elsewhere is replaced only with replace set; a file that is not a link is never touched.
func (in *Installer) Install(replace bool) (Status, error) {
	src, serr := in.source()
	if serr != nil {
		return Status{}, serr
	}
	dir, create, perr := in.pickDir()
	if perr != nil {
		return Status{}, perr
	}
	link := filepath.Join(dir, Name)
	target, state := look(link)
	switch state {
	case Blocked:
		return Status{}, refuse("cli_blocked", "link", link)
	case Elsewhere:
		if sameFile(target, src) {
			return in.Status(), nil
		}
		if !replace {
			return Status{}, refuse("cli_elsewhere", "link", link, "target", target)
		}
	}
	if create {
		if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- a PATH directory is world-readable
			return Status{}, refuse("cli_failed")
		}
	}
	// a new link under a temporary name, then one rename: the old link (if any) is replaced atomically, and nothing is written through it
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return Status{}, refuse("cli_failed")
	}
	tmp := filepath.Join(dir, "."+Name+".tmp-"+hex.EncodeToString(rnd[:]))
	if err := os.Symlink(src, tmp); err != nil {
		return Status{}, refuse("cli_failed")
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return Status{}, refuse("cli_failed")
	}
	return in.Status(), nil
}

// LoginShellPath is the PATH a terminal would have: the user's login shell started non-interactively (it reads the login profile, as a new terminal
// window does) and asked for $PATH. A shell that is not listed in /etc/shells is not run; zsh is the fallback on macOS. nil when it cannot be read.
func LoginShellPath() []string {
	shell := os.Getenv("SHELL")
	if !listedShell(shell) {
		shell = "/bin/zsh"
		if !listedShell(shell) {
			return nil
		}
	}
	return loginShellPath(shell, shellTimeout)
}

// shellTimeout bounds the whole probe: a slow or hanging login profile only makes the window say nothing about the PATH.
const shellTimeout = 4 * time.Second

// loginShellPath runs shell in a process group of its own and returns what it printed as $PATH. Whatever the profile started in that group is killed
// when the probe ends, and a program the profile left in the background holding the output open cannot keep the probe waiting: the output is closed
// one second after the shell exits or the time is up.
func loginShellPath(shell string, timeout time.Duration) []string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-l", "-c", "printf %s \"$PATH\"") // #nosec G204 -- the shell is one of /etc/shells
	cmd.Env = []string{"HOME=" + os.Getenv("HOME"), "USER=" + os.Getenv("USER"), "TERM=dumb", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // the group of the probe: nothing it started outlives it
	}
	// ErrWaitDelay: the shell itself answered and exited, only a background program of the profile kept the output open
	if (err != nil && !errors.Is(err, exec.ErrWaitDelay)) || len(out) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(out)), ":")
}

func listedShell(p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	data, err := os.ReadFile("/etc/shells")
	if err != nil {
		return false
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(ln) == p {
			return true
		}
	}
	return false
}

// IsRefusal tells a refusal (with a code) from any other error.
func IsRefusal(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
