//go:build windows

package cli

import (
	"io/fs"
	"os"
)

// trustedProgram: no program of the window is trusted on Windows (it has no Touch ID).
func trustedProgram(string, string) bool { return false }

// Windows has no owner and mode bits to compare; the directory of the token file is made by this process with a private name.
func ownedByMe(fs.FileInfo) bool { return true }

// ownSessionDir: a real directory (Windows has no owner and mode bits to compare).
func ownSessionDir(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fail("no session directory at %s", path)
	}
	if !st.IsDir() {
		return fail("%s is not a real directory: its files are NOT read into the vault", path)
	}
	return nil
}

func safeTokenFile(path string) error {
	f, err := os.Lstat(path)
	if err != nil {
		return fail("the token file %s cannot be checked (%v): it is not used", path, pathErrText(err))
	}
	if !f.Mode().IsRegular() {
		return fail("the token file %s is not a regular file: it is not handed to terraform", path)
	}
	return nil
}
