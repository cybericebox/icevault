package bridge

import "strings"

// SiteName is the name of the site the writer makes in an environment that has none yet.
const SiteName = "main"

func contains(list []string, x string) bool {
	for _, l := range list {
		if l == x {
			return true
		}
	}
	return false
}

func orText(s, d string) string {
	if s != "" {
		return s
	}
	return d
}

// flat makes a path one title (a slash would be a group in KeePass).
func flat(s string) string { return strings.ReplaceAll(s, "/", "\u2215") }
