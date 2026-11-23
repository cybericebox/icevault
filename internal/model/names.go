// Package model is the generic part of the secrets store that touches no KDBX
// file: the vocabulary (sections, items, groups, entries, files), the notes
// machine lines, paths inside the vault, the in-memory Snapshot, references
// (${{ shared.KEY }}) and the resolution of an environment for a site.
package model

import (
	"regexp"
	"strings"
)

const (
	Group       = "IceVault"
	Attachment  = "content"
	SecEnvs     = "environments"
	SecGlobal   = "global"
	SecExternal = "external"
	SecSites    = "sites"
	GlobalRef   = "shared"
	Files       = "files"
	Retired     = "retired"
	Blobs       = ".blobs"
	ItemMeta    = ".item"
	SectionMeta = ".section"
	GroupMeta   = ".group"
	MaxLabels   = 8
	MaxRefDepth = 8
	OldLayout   = "the vault uses an older layout than this version: move the old file away, run `icevault init-vault`, then `icevault import --env <name>` for each environment"
)

// Values the store reads and writes, shared by every package.
const (
	VisPlain       = "plain"
	VisSecret      = "secret"
	VisSealed      = "sealed"
	ManagedOwner   = "owner"
	ManagedSystem  = "system"
	ManagedRetired = "retired"
	StateActive    = "active"
	StateRetired   = "retired"
)

// Reserved names: a section, an item or a group cannot have them.
var Reserved = []string{Files, Retired, Blobs}

// IsReserved reports whether name is one of the structure names.
func IsReserved(name string) bool {
	for _, r := range Reserved {
		if r == name {
			return true
		}
	}
	return false
}

// Vis is the visibility of a value: plain < secret < sealed.
var Vis = []string{VisPlain, VisSecret, VisSealed}

var visRank = map[string]int{VisPlain: 0, VisSecret: 1, VisSealed: 2}

// VisRank orders visibilities (plain 0, secret 1, sealed 2).
func VisRank(v string) int { return visRank[v] }

// ValidVis reports whether v is a known visibility.
func ValidVis(v string) bool { _, ok := visRank[v]; return ok }

// machineKeys is the ONE list of notes keys that code reads: the writer check
// (DescriptionText), ParseNotes and HintOf all use it. "type" is not written any
// more, but Ingest refuses a vault that carries it (older layout), so a
// description must not be able to produce it.
var machineKeys = []string{"managed-by", "visibility", "labels", "title", "path", "sha256", "mode", "sealed-at", "retired-from", "retired-at", "needed-until", "state",
	"uses", "order", "system", "was-managed", "was-visibility", "was-labels", "was-title", "vis-by", "managed-set", "only-sites", "site-type", "retired-why", "type"}

// IsMachineKey reports whether k is a reserved notes key.
func IsMachineKey(k string) bool {
	for _, m := range machineKeys {
		if m == k {
			return true
		}
	}
	return false
}

// MachineKeyFold is IsMachineKey ignoring case: the writer check also refuses a
// description line that merely looks like a machine line.
func MachineKeyFold(k string) bool {
	for _, m := range machineKeys {
		if strings.EqualFold(m, k) {
			return true
		}
	}
	return false
}

var (
	// NameRE is a section, item, site or system name. (Python's "$" also
	// accepted a trailing newline; Go's does not, which is stricter.)
	NameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	LabelRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._/+-]{0,63}$`)
	KeyRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	PathPart  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	isoTime   = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d`)
	keepRefRE = regexp.MustCompile(`^\{REF:P@I:([0-9A-Fa-f]{32})\}$`)
	// ReferenceRE finds ${{ name.KEY }}; group 1 is the escaping "$" ("$${{" is text).
	ReferenceRE = regexp.MustCompile(`(\$)?\$\{\{\s*([a-z0-9][a-z0-9_-]{0,31})\.([A-Za-z_][A-Za-z0-9_.-]{0,127})\s*\}\}`)
)

const MaxGroupDepth = 8

// StoreError is a refusal or a failure: one line.
type StoreError struct{ Msg string }

func (e *StoreError) Error() string { return e.Msg }

func storeErr(msg string) error { return &StoreError{Msg: msg} }

// ParseNotes returns the key=value lines of a notes text. The FIRST line of a
// key wins: the machine lines are written first, so the free description
// below them cannot override one.
func ParseNotes(text string) map[string]string {
	out := map[string]string{}
	for _, ln := range splitLines(text) {
		k, v, ok := strings.Cut(ln, "=")
		if ok {
			k = strings.TrimSpace(k)
			if !IsMachineKey(k) { // only machine keys are ever read out of notes
				continue
			}
			if _, seen := out[k]; !seen {
				out[k] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// splitLines mimics Python str.splitlines for the separators that matter here.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	parts := strings.Split(text, "\n")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// HintOf is the human part of the notes (the description), without the machine lines.
func HintOf(notes string) string {
	var keep []string
	for _, ln := range splitLines(notes) {
		k, _, ok := strings.Cut(ln, "=")
		if !IsMachineKey(strings.TrimSpace(k)) || !ok {
			keep = append(keep, ln)
		}
	}
	return strings.Join(keep, "\n")
}

// SafeVisibility is the visibility the notes say, else the safe default
// (system: sealed, owner: secret).
func SafeVisibility(notes, managed string) string {
	if v := ParseNotes(notes)["visibility"]; ValidVis(v) {
		return v
	}
	if managed == "system" {
		return "sealed"
	}
	return "secret"
}

// RefText is a reference as written inside a value.
func RefText(system, key string) string { return "${{ " + system + "." + key + " }}" }

// ParseLabels splits a comma list, trimming and dropping empties.
func ParseLabels(text string) []string {
	var out []string
	for _, p := range strings.Split(text, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// CheckLabels returns the labels as a clean (deduplicated) list or an error.
func CheckLabels(labels []string) ([]string, error) {
	if len(labels) > MaxLabels {
		return nil, storeErr("labels are a list of at most 8 short tags")
	}
	out := []string{}
	for _, x := range labels {
		if !LabelRE.MatchString(x) {
			return nil, storeErr("a label is 1-64 characters: letters, digits and : . _ / + -")
		}
		dup := false
		for _, o := range out {
			dup = dup || o == x
		}
		if !dup {
			out = append(out, x)
		}
	}
	return out, nil
}
