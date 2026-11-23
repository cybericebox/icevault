//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// sameVolume is true when two paths are on the same filesystem. When that cannot be told, true: a copy is then not counted as being elsewhere.
func sameVolume(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	if err1 != nil || err2 != nil {
		return true
	}
	x, ok1 := sa.Sys().(*syscall.Stat_t)
	y, ok2 := sb.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return true
	}
	return x.Dev == y.Dev
}
