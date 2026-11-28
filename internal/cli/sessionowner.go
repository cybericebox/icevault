package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// A session directory belongs to the process that opened it. The process is recorded in a small file NEXT TO the directory (<dir>.owner, mode 0600, not
// inside it: the inside is read back into the vault), so a second run of the same environment can tell a live run from the leftover of a killed one.

// ownerInfo is the content of the owner file: the process and when the session was opened. Nothing secret.
type ownerInfo struct {
	PID   int    `json:"pid"`
	Start string `json:"start,omitempty"` // the start time of the process as ps prints it: a recycled PID has another one
	Since string `json:"since"`           // when the session was opened, RFC 3339
}

// ownerState is what the owner file of a session directory says.
type ownerState int

const (
	ownerNone ownerState = iota // no readable owner file: a directory of the old format, or one whose owner file was lost
	ownerDead                   // the recorded process is gone
	ownerLive                   // the recorded process runs
)

// ownerPath is the owner file of a session directory.
func ownerPath(dir string) string { return dir + ".owner" }

// processStart is the start time of a process as `ps` prints it, "" when it cannot be told (then only the PID is compared).
func processStart(pid int) string {
	for _, ps := range []string{"/bin/ps", "/usr/bin/ps"} {
		if _, err := os.Stat(ps); err != nil {
			continue
		}
		cmd := exec.Command(ps, "-o", "lstart=", "-p", strconv.Itoa(pid)) // #nosec G204 -- fixed program, a number
		cmd.Env = []string{"LC_ALL=C", "LANG=C"}
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.Join(strings.Fields(string(out)), " ")
	}
	return ""
}

// writeOwner records this process as the owner of the session directory dir.
func writeOwner(dir string) error {
	body, _ := json.Marshal(ownerInfo{PID: os.Getpid(), Start: processStart(os.Getpid()), Since: time.Now().Format(time.RFC3339)})
	p := ownerPath(dir)
	_ = os.Remove(p)                                                   // an owner file of an earlier, removed directory
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- next to the session directory
	if err != nil {
		return err
	}
	_ = f.Chmod(0o600)
	_, err = f.Write(body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(p)
	}
	return err
}

func removeOwner(dir string) { _ = os.Remove(ownerPath(dir)) }

// readOwner says whether the process that owns the session directory runs. The owner file is written right after the directory is made, so a
// directory without one is looked at again for a moment before it counts as an old-format leftover.
func readOwner(dir string) (ownerInfo, ownerState) {
	var info ownerInfo
	for try := 0; try < 4; try++ {
		data, err := os.ReadFile(ownerPath(dir)) // #nosec G304 -- next to the session directory
		if err == nil && json.Unmarshal(data, &info) == nil && info.PID > 0 {
			break
		}
		info = ownerInfo{}
		if try < 3 && !errors.Is(err, fs.ErrPermission) {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if info.PID == 0 {
		return info, ownerNone
	}
	if !processAlive(info.PID) {
		return info, ownerDead
	}
	if info.Start != "" {
		if now := processStart(info.PID); now != "" && now != info.Start {
			return info, ownerDead // the PID was given to another process
		}
	}
	return info, ownerLive
}

// liveOwnerError is the refusal while a run of the environment is in progress: no word of recover, which would pull the files from under it.
func liveOwnerError(env, site string, info ownerInfo) error {
	since := info.Since
	if t, err := time.Parse(time.RFC3339, info.Since); err == nil {
		since = t.Format("2006-01-02 15:04:05")
	}
	pair := env
	if site != "" {
		pair += " --site " + site
	}
	return fail("a run of '%s' is in progress (PID %d, since %s): wait for it to end, or use a read-only session for commands that only look: "+
		"icevault session run --read-only --env %s -- COMMAND", env, info.PID, since, pair)
}

// liveWriteSession reports a run of env that holds a session for writing (any site) in base and still runs. Such a run writes its directory back
// into the vault when it ends, and that write-back fails when the vault changed under it, so a direct change of the vault waits for it. Read-only
// sessions (their own -ro- directories) never write back and do not count.
func liveWriteSession(e *Env, base, env string) (ownerInfo, bool) {
	base = baseOrTemp(base)
	name := filepath.Base(sessionDir(e, base, env, ""))
	ents, err := os.ReadDir(base)
	if err != nil {
		return ownerInfo{}, false
	}
	for _, en := range ents {
		n := en.Name()
		if !en.IsDir() || (n != name && !strings.HasPrefix(n, name+"-")) {
			continue
		}
		p := filepath.Join(base, n)
		if st, err := os.Lstat(p); err != nil || !ownedByMe(st) {
			continue
		}
		if _, err := os.Lstat(ownerPath(p)); err != nil {
			continue // no owner file: a leftover of an old version or of a killed run, nothing runs
		}
		if info, st := readOwner(p); st == ownerLive {
			return info, true
		}
	}
	return ownerInfo{}, false
}

// openError is why a session directory that already exists cannot be opened.
func (s *session) existsError() error {
	info, st := readOwner(s.Path)
	if st == ownerLive {
		return liveOwnerError(s.Env, s.Site, info)
	}
	return fail("%s is left over from a run that was killed: `icevault recover --env %s%s` writes its files into the vault and removes it "+
		"(or delete the directory if you know it holds nothing new)", s.Path, s.Env, s.siteArg())
}

var _ = fmt.Sprint
