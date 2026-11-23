package model

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The builders below are the ONE choke point for everything written into the
// notes of an entry: every field is checked, and one that would make a second
// line, carry a hidden character or parse as a machine line is refused, so no
// caller can inject a machine field whatever the source of the text (a typed
// description, a file name, a comment of an env file, a name in the vault).

func notesErr(what string) error {
	return &StoreError{Msg: "refused: " + what + " cannot be written into the notes of an entry (a line break, a control or invisible character, or a reserved word)"}
}

// plainField: one line with no control, invisible or line-separator character.
func plainField(what, v string) error {
	if !utf8.ValidString(v) || hasLineBreak(v) {
		return notesErr(what)
	}
	for _, r := range v {
		if HiddenRune(r) {
			return notesErr(what)
		}
	}
	return nil
}

// descriptionField: lines separated by "\n" only, no hidden character, and no
// line that parses as a machine line (in any case).
func descriptionField(v string) error {
	if !utf8.ValidString(v) {
		return notesErr("the description")
	}
	for _, r := range v {
		if HiddenRune(r) {
			return notesErr("the description")
		}
	}
	for _, line := range strings.Split(v, "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && MachineKeyFold(strings.TrimSpace(k)) {
			return notesErr("the description")
		}
	}
	return nil
}

var shaRE = regexp.MustCompile(`^([0-9a-f]{64}|pending)$`)

func oneOf(what, v string, allowed ...string) error {
	for _, a := range allowed {
		if a == v {
			return nil
		}
	}
	return notesErr(what)
}

func nameList(what string, l []string) error {
	for _, x := range l {
		if !NameRE.MatchString(x) {
			return notesErr(what)
		}
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// EntryNotes is the notes of a variable: machine lines, then the description.
// visBy ManagedOwner says the owner chose the visibility.
func EntryNotes(managed, vis string, labels []string, description, visBy string) (string, error) {
	return EntryNotesSet(managed, vis, labels, description, visBy, "")
}

// EntryNotesSet is EntryNotes with the managed-set mark: ManagedOwner says the
// owner chose managed-by by hand (the automatic rule then leaves the entry alone).
func EntryNotesSet(managed, vis string, labels []string, description, visBy, managedSet string) (string, error) {
	if err := firstErr(oneOf("managed-by", managed, ManagedOwner, ManagedSystem, StateRetired), oneOf("visibility", vis, Vis...), oneOf("vis-by", visBy, "", ManagedOwner),
		oneOf("managed-set", managedSet, "", ManagedOwner), descriptionField(description)); err != nil {
		return "", err
	}
	for _, l := range labels {
		if !LabelRE.MatchString(l) {
			return "", notesErr("a label")
		}
	}
	lines := []string{"managed-by=" + managed, "visibility=" + vis}
	if visBy != "" {
		lines = append(lines, "vis-by="+visBy)
	}
	if managedSet != "" {
		lines = append(lines, "managed-set="+managedSet)
	}
	if len(labels) > 0 {
		lines = append(lines, "labels="+strings.Join(labels, ","))
	}
	out := strings.Join(lines, "\n")
	if description != "" {
		out += "\n" + description
	}
	return out, nil
}

// WasNotes is the part of the notes of an archived entry that lets it come back
// as it was: was-* lines and its description.
func WasNotes(managed, vis string, labels []string, description string) (string, error) {
	if err := firstErr(oneOf("managed-by", managed, ManagedOwner, ManagedSystem, StateRetired), oneOf("visibility", vis, Vis...), descriptionField(description)); err != nil {
		return "", err
	}
	for _, l := range labels {
		if !LabelRE.MatchString(l) {
			return "", notesErr("a label")
		}
	}
	out := "\nwas-managed=" + managed + "\nwas-visibility=" + vis
	if len(labels) > 0 {
		out += "\nwas-labels=" + strings.Join(labels, ",")
	}
	if description != "" {
		out += "\n" + description
	}
	return out, nil
}

func pathOK(rel string) bool {
	if rel == "" || strings.HasPrefix(rel, "/") || len(rel) > 400 {
		return false
	}
	for _, p := range strings.Split(rel, "/") {
		if !PathPart.MatchString(p) {
			return false
		}
	}
	return true
}

// ValidRel reports whether every segment of a file path is a plain name
// (letters, digits, . _ - and not starting with a dot or dash).
func ValidRel(rel string) bool { return pathOK(rel) }

// FileNotes is the notes of a file entry.
func FileNotes(rel, sha string, mode int, at, managed, vis string) (string, error) {
	if !pathOK(rel) {
		return "", notesErr("a file path")
	}
	if err := firstErr(oneOf("sha256", sha, sha), plainField("a time", at), oneOf("managed-by", managed, ManagedOwner, ManagedSystem, StateRetired), oneOf("visibility", vis, Vis...)); err != nil {
		return "", err
	}
	if !shaRE.MatchString(sha) {
		return "", notesErr("a digest")
	}
	return fmt.Sprintf("managed-by=%s\nvisibility=%s\npath=%s\nsha256=%s\nmode=%04o\nsealed-at=%s", managed, vis, rel, sha, mode, at), nil
}

// PendingFileNotes is the notes of a file entry made before its content is attached.
func PendingFileNotes(rel, managed string) (string, error) {
	if !pathOK(rel) {
		return "", notesErr("a file path")
	}
	if err := oneOf("managed-by", managed, ManagedOwner, ManagedSystem, StateRetired); err != nil {
		return "", err
	}
	return "managed-by=" + managed + "\npath=" + rel + "\nsha256=pending", nil
}

// RetiredNotes is the notes of a retired entry or file. rel is what it was
// before ("group/KEY" or a file path).
func RetiredNotes(rel, sha string, mode int, at, needed string) (string, error) {
	if err := firstErr(plainField("the old path", rel), plainField("a time", at), plainField("needed-until", needed)); err != nil {
		return "", err
	}
	if rel == "" || !shaRE.MatchString(sha) {
		return "", notesErr("a retired path or digest")
	}
	return fmt.Sprintf("managed-by=retired\nretired-from=%s\nretired-at=%s\nneeded-until=%s\nsha256=%s\nmode=%04o", rel, at, needed, sha, mode), nil
}

// ItemNotes is the notes of an `.item` entry.
func ItemNotes(it *Item) (string, error) {
	if err := firstErr(plainField("a title", it.Title), oneOf("state", it.State, StateActive, StateRetired), descriptionField(it.Description),
		nameList("a site name", it.OnlySites)); err != nil {
		return "", err
	}
	if it.SiteType != "" && !NameRE.MatchString(it.SiteType) {
		return "", notesErr("a site type")
	}
	var lines []string
	if it.Title != "" {
		lines = append(lines, "title="+it.Title)
	}
	if len(it.Uses) > 0 {
		parts := make([]string, len(it.Uses))
		for i, u := range it.Uses {
			if !NameRE.MatchString(u.Section) || !NameRE.MatchString(u.Name) {
				return "", notesErr("a link")
			}
			parts[i] = u.Section + "/" + u.Name
		}
		lines = append(lines, "uses="+strings.Join(parts, ","))
	}
	if len(it.OnlySites) > 0 {
		lines = append(lines, "only-sites="+strings.Join(it.OnlySites, ","))
	}
	if it.SiteType != "" {
		lines = append(lines, "site-type="+it.SiteType)
	}
	lines = append(lines, "state="+it.State)
	out := strings.Join(lines, "\n")
	if it.Description != "" {
		out += "\n" + it.Description
	}
	return out, nil
}

// GroupNotes is the notes of a `.group` entry.
func GroupNotes(state, title, description string, onlySites []string) (string, error) {
	if err := firstErr(oneOf("state", state, StateActive, StateRetired), plainField("a title", title), descriptionField(description), nameList("a site name", onlySites)); err != nil {
		return "", err
	}
	lines := []string{"state=" + state}
	if title != "" {
		lines = append(lines, "title="+title)
	}
	if len(onlySites) > 0 {
		lines = append(lines, "only-sites="+strings.Join(onlySites, ","))
	}
	out := strings.Join(lines, "\n")
	if description != "" {
		out += "\n" + description
	}
	return out, nil
}

// SectionNotes is the notes of a `.section` entry; order < 0 means none.
func SectionNotes(title string, order int, system bool, state string) (string, error) {
	if err := firstErr(plainField("a title", title), oneOf("state", state, StateActive, StateRetired)); err != nil {
		return "", err
	}
	lines := []string{"state=" + state}
	if title != "" {
		lines = append(lines, "title="+title)
	}
	if order >= 0 {
		lines = append(lines, fmt.Sprintf("order=%d", order))
	}
	if system {
		lines = append(lines, "system=yes")
	}
	return strings.Join(lines, "\n"), nil
}

// ---- paths inside the vault

func ItemRoot(section, item string) string { return Group + "/" + section + "/" + item }
func VarEntry(section, item, group, key string) string {
	return ItemRoot(section, item) + "/" + group + "/" + key
}
func BlobEntry(section, item, name string) string {
	return ItemRoot(section, item) + "/" + Blobs + "/" + name
}
func FileEntryPath(section, item, rel string) string {
	return ItemRoot(section, item) + "/" + Files + "/" + rel
}
func ItemEntry(section, item string) string { return ItemRoot(section, item) + "/" + ItemMeta }
func SectionEntry(section string) string    { return Group + "/" + section + "/" + SectionMeta }
func GroupEntry(section, item, group string) string {
	return ItemRoot(section, item) + "/" + group + "/" + GroupMeta
}

// SplitRef splits "section/item"; ok is false when either part is empty.
func SplitRef(text string) (ref ItemKey, ok bool) {
	s, i, _ := strings.Cut(text, "/")
	if s == "" || i == "" {
		return ItemKey{}, false
	}
	return ItemKey{s, i}, true
}
