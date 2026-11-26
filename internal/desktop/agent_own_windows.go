//go:build windows

package desktop

import "io/fs"

// ownedByMe: the owner cannot be read here, so nothing is swept (the agent API is not served on this system either).
func ownedByMe(fs.FileInfo) bool { return false }
