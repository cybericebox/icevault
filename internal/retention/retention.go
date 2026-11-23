// Package retention is the release retention policy of the workspace, for the releases (pages and assets) of this repository:
//
//   - the git tag of a final release is kept forever (this package never asks for a tag to be deleted, only for its release);
//   - a release candidate (vX.Y.Z-rc.N) is deleted once the final vX.Y.Z exists: its release, and its tag too (CandidateTags);
//   - the newest minor keeps every patch release;
//   - an older minor keeps only its latest patch, and only for the previous PreviousMinors minors; a minor older than that loses its release too.
package retention

import (
	"regexp"
	"sort"
	"strconv"
)

// PreviousMinors is how many minors older than the current one keep their latest patch.
const PreviousMinors = 10

var tagRE = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(-rc\.\d+)?$`)

type version struct {
	tag                 string
	major, minor, patch int
	rc                  bool
}

func parse(tag string) (version, bool) {
	m := tagRE.FindStringSubmatch(tag)
	if m == nil {
		return version{}, false
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	return version{tag, n(m[1]), n(m[2]), n(m[3]), m[4] != ""}, true
}

// Newest reports whether tag is the newest final release among tags and itself: only that release is marked as the latest one, so a patch of an older
// minor published after a newer minor does not take the place of the newer one.
func Newest(tags []string, tag string) bool {
	v, ok := parse(tag)
	if !ok || v.rc {
		return false
	}
	for _, t := range tags {
		if o, ok := parse(t); ok && !o.rc && newer(o, v) {
			return false
		}
	}
	return true
}

func newer(a, b version) bool {
	if a.major != b.major {
		return a.major > b.major
	}
	if a.minor != b.minor {
		return a.minor > b.minor
	}
	return a.patch > b.patch
}

// CandidateTags returns the release candidate tags (vX.Y.Z-rc.N) whose final vX.Y.Z is among tags, oldest first: the policy deletes those tags,
// while the tags of final releases stay forever.
func CandidateTags(tags []string) []string {
	var out []string
	for _, t := range Delete(tags, len(tags)+1) { // a window wider than the list: only the candidates are left to delete
		if v, _ := parse(t); v.rc {
			out = append(out, t)
		}
	}
	return out
}

// Delete returns the tags whose releases are to be deleted, oldest first. A tag that is not vX.Y.Z or vX.Y.Z-rc.N is left alone.
func Delete(tags []string, previous int) []string {
	var finals []version
	finalOf := map[[3]int]bool{}
	var del []version
	for _, t := range tags {
		v, ok := parse(t)
		if !ok {
			continue
		}
		if v.rc {
			continue
		}
		finals = append(finals, v)
		finalOf[[3]int{v.major, v.minor, v.patch}] = true
	}
	for _, t := range tags { // candidates whose final is out
		if v, ok := parse(t); ok && v.rc && finalOf[[3]int{v.major, v.minor, v.patch}] {
			del = append(del, v)
		}
	}
	// the minors, newest first
	type minor struct{ major, minor int }
	byMinor := map[minor][]version{}
	var minors []minor
	for _, v := range finals {
		k := minor{v.major, v.minor}
		if _, seen := byMinor[k]; !seen {
			minors = append(minors, k)
		}
		byMinor[k] = append(byMinor[k], v)
	}
	sort.Slice(minors, func(i, j int) bool {
		if minors[i].major != minors[j].major {
			return minors[i].major > minors[j].major
		}
		return minors[i].minor > minors[j].minor
	})
	for i, k := range minors {
		vs := byMinor[k]
		sort.Slice(vs, func(a, b int) bool { return vs[a].patch > vs[b].patch })
		switch {
		case i == 0: // the current minor: every patch stays
		case i <= previous: // a previous minor: only its latest patch
			del = append(del, vs[1:]...)
		default: // out of the window
			del = append(del, vs...)
		}
	}
	sort.Slice(del, func(i, j int) bool {
		a, b := del[i], del[j]
		if a.major != b.major {
			return a.major < b.major
		}
		if a.minor != b.minor {
			return a.minor < b.minor
		}
		if a.patch != b.patch {
			return a.patch < b.patch
		}
		return a.tag < b.tag
	})
	out := make([]string, 0, len(del))
	for _, v := range del {
		out = append(out, v.tag)
	}
	return out
}
