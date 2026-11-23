//go:build windows

package vault

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive lock without waiting; the returned function releases it.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, pathErr(err)
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); err != nil {
		_ = f.Close()
		return nil, ErrLocked
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol); _ = f.Close() }, nil
}

// syncDir does nothing on Windows: a directory cannot be opened for fsync there, and the rename is atomic in NTFS.
func syncDir(string) error { return nil }
