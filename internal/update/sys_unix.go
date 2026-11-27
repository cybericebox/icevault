//go:build !windows

package update

import (
	"os/exec"
	"strconv"
	"syscall"
)

// relaunch starts a shell of its own session that waits until pid has ended and then opens app; it outlives this program. The values are arguments
// of a fixed script, never a part of it. After the process is gone, Launch Services can still count the old copy as running for a moment, and a
// plain `open` then only activates the dying copy, so nothing appears: the script waits a second and opens a new instance (-n), which is safe
// because the old process has ended.
const relaunchScript = "while kill -0 \"$1\" 2>/dev/null; do sleep 0.2; done; sleep 1; exec /usr/bin/open -n \"$2\""

func relaunch(pid int, app string) error {
	cmd := exec.Command("/bin/sh", "-c", relaunchScript, "sh", strconv.Itoa(pid), app) // #nosec G204 -- a fixed script
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

func writable(p string) bool { return syscall.Access(p, 2) == nil } // W_OK
