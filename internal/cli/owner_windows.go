//go:build windows

package cli

import "os"

// processAlive: on Windows FindProcess fails for a PID that does not exist.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
