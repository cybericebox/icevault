//go:build !windows

package desktop

import "syscall"

// noFollow makes opening a symbolic link fail instead of writing through it.
const noFollow = syscall.O_NOFOLLOW
