//go:build !windows

package desktop

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe says whether the file or folder belongs to the current user.
func ownedByMe(st fs.FileInfo) bool {
	s, isStat := st.Sys().(*syscall.Stat_t)
	return isStat && int(s.Uid) == os.Getuid()
}
