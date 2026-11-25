//go:build !windows

package agentapi

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"syscall"
)

func ownedByMe(st fs.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Getuid()
}

// CheckDir refuses a socket folder that is not a real directory of this user, or that the group or the others can write into: whoever can write there
// can replace the socket.
func CheckDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || !ownedByMe(st) || st.Mode().Perm()&0o077 != 0 {
		return errors.New("the agent socket folder is not a directory of this user with mode 0700")
	}
	return nil
}

// checkSocketFile is the check before the client connects: a socket made by this user, mode 0600.
func checkSocketFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSocket == 0 || !ownedByMe(st) || st.Mode().Perm()&0o077 != 0 {
		return errors.New("the agent socket is not a socket of this user with mode 0600")
	}
	return nil
}

// MakeDir makes the folder (mode 0700) when missing and checks it.
func MakeDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return CheckDir(dir)
}

// CheckSocketFile is checkSocketFile for the window, after it made the socket.
func CheckSocketFile(path string) error { return checkSocketFile(path) }

// Listen opens the socket with a umask that leaves it no access for the group and the others from the first moment.
func Listen(path string) (net.Listener, error) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}
