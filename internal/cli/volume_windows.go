//go:build windows

package cli

import (
	"path/filepath"
	"strings"
)

// sameVolume compares drive letters; a UNC path or an unknown one counts as the same volume (a copy is then not counted as being elsewhere).
func sameVolume(a, b string) bool {
	va, vb := filepath.VolumeName(a), filepath.VolumeName(b)
	if va == "" || vb == "" {
		return true
	}
	return strings.EqualFold(va, vb)
}
