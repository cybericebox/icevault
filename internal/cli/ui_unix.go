//go:build !windows

package cli

import "syscall"

// execWindow replaces this process with the window program: the window is the program, not a child of the terminal command.
func execWindow(path string, argv, env []string) error {
	return syscall.Exec(path, argv, env) // #nosec G204 -- path is the window program found next to this one
}
