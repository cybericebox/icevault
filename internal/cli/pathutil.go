package cli

import (
	"errors"
	"io/fs"
	"path/filepath"
)

func dirOf(p string) string { return filepath.Dir(p) }

// pathErrText is the operating system's reason without the path.
func pathErrText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
