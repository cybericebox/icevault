//go:build !windows

package cli

import (
	"io/fs"
	"os"
	"syscall"
)

// trustedProgram: path (in folder dir) is a regular executable file of this user or root that group and others cannot write, and dir is a directory of
// this user or root that others cannot write into. Links are followed (Homebrew links its programs into the prefix), the target is what is checked.
func trustedProgram(dir, path string) bool {
	d, err := os.Stat(dir)
	if err != nil || !d.IsDir() || d.Mode().Perm()&0o002 != 0 || !ownerIsMeOrRoot(d) {
		return false
	}
	f, err := os.Stat(path)
	if err != nil || !f.Mode().IsRegular() || f.Mode().Perm()&0o111 == 0 || f.Mode().Perm()&0o022 != 0 || !ownerIsMeOrRoot(f) {
		return false
	}
	return true
}

func ownerIsMeOrRoot(st fs.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && (int(s.Uid) == os.Getuid() || s.Uid == 0)
}

func ownedByMe(st fs.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Getuid()
}

// ownSessionDir is the check before a left-over session directory is read back into the vault (close, recover): the files in it become secrets of the vault,
// so it must be a real directory (not a link), made by this user, closed to the others. In a shared temp directory another user can create the predictable name
// first; without this check `recover` would take that user's files as the run's.
func ownSessionDir(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fail("no session directory at %s", path)
	}
	if !st.IsDir() || !ownedByMe(st) || st.Mode().Perm()&0o077 != 0 {
		return fail("%s is not a real directory of this user with mode 0700: its files are NOT read into the vault (look at it, then delete it)", path)
	}
	return nil
}

// safeTokenFile is the check before a path is handed to a child as its CLI config: a regular file (not a link) of this user with mode 0600, in a real
// directory of this user with mode 0700.
func safeTokenFile(path string) error {
	f, err := os.Lstat(path)
	if err != nil {
		return fail("the token file %s cannot be checked (%v): it is not used", path, pathErrText(err))
	}
	d, err := os.Lstat(dirOf(path))
	if err != nil {
		return fail("the token file %s cannot be checked (%v): it is not used", path, pathErrText(err))
	}
	if !f.Mode().IsRegular() || !ownedByMe(f) || f.Mode().Perm() != 0o600 {
		return fail("the token file %s is not a regular file of this user with mode 0600: it is not handed to terraform", path)
	}
	if !d.IsDir() || d.Mode()&fs.ModeSymlink != 0 || !ownedByMe(d) || d.Mode().Perm() != 0o700 {
		return fail("the directory of the token file %s is not a real directory of this user with mode 0700: the file is not handed to terraform", path)
	}
	return nil
}
