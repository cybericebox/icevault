//go:build !windows

package cli

import (
	"errors"
	"syscall"
)

// processAlive: a process with this PID exists (a process of another user answers "not permitted" and counts as alive).
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
