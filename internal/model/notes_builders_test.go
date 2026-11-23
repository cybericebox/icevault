package model

import (
	"strings"
	"testing"
)

var sha64 = strings.Repeat("a", 64)

// The builders of the notes are the one choke point: a field that would make a
// second line (or carry a hidden character) is refused, whatever the caller.
func TestNotesBuildersRefuseAnyFieldThatWouldInject(t *testing.T) {
	bad := []string{"x\ntype=aws", "x\rstate=retired", "x\u2028uses=a/b", "x\u0085labels=a", "x\u200bstate=y", "\ufeffx", "x\x00y", "x\vy"}
	for _, b := range bad {
		if _, err := EntryNotes("owner", "plain", []string{b}, "", ""); err == nil {
			t.Errorf("entry label %q", b)
		}
		if _, err := EntryNotes("owner", "plain", nil, b, ""); err == nil {
			t.Errorf("entry description %q", b)
		}
		if _, err := EntryNotes(b, "plain", nil, "", ""); err == nil {
			t.Errorf("entry managed %q", b)
		}
		if _, err := EntryNotes("owner", b, nil, "", ""); err == nil {
			t.Errorf("entry visibility %q", b)
		}
		if _, err := EntryNotes("owner", "plain", nil, "", b); err == nil {
			t.Errorf("entry vis-by %q", b)
		}
		it := NewItem("external", "cf")
		it.Title = b
		if _, err := ItemNotes(it); err == nil {
			t.Errorf("item title %q", b)
		}
		it = NewItem("external", "cf")
		it.SiteType = b
		if _, err := ItemNotes(it); err == nil {
			t.Errorf("item site type %q", b)
		}
		it = NewItem("external", "cf")
		it.OnlySites = []string{b}
		if _, err := ItemNotes(it); err == nil {
			t.Errorf("item only-sites %q", b)
		}
		it = NewItem("environments", "e")
		it.Uses = []ItemKey{{"mine", b}}
		if _, err := ItemNotes(it); err == nil {
			t.Errorf("item uses %q", b)
		}
		it = NewItem("external", "cf")
		it.Description = b
		if _, err := ItemNotes(it); err == nil {
			t.Errorf("item description %q", b)
		}
		it = NewItem("external", "cf")
		it.State = b
		if _, err := ItemNotes(it); err == nil {
			t.Errorf("item state %q", b)
		}
		if _, err := GroupNotes("active", b, "", nil); err == nil {
			t.Errorf("group title %q", b)
		}
		if _, err := GroupNotes("active", "", b, nil); err == nil {
			t.Errorf("group description %q", b)
		}
		if _, err := GroupNotes("active", "", "", []string{b}); err == nil {
			t.Errorf("group sites %q", b)
		}
		if _, err := SectionNotes(b, 1, false, "active"); err == nil {
			t.Errorf("section title %q", b)
		}
		if _, err := FileNotes(b, sha64, 0o600, "now", "owner", "sealed"); err == nil {
			t.Errorf("file path %q", b)
		}
		if _, err := FileNotes("a/b", b, 0o600, "now", "owner", "sealed"); err == nil {
			t.Errorf("file sha %q", b)
		}
		if _, err := RetiredNotes(b, sha64, 0o600, "now", "x"); err == nil {
			t.Errorf("retired-from %q", b)
		}
		if _, err := RetiredNotes("a/b", sha64, 0o600, "now", b); err == nil {
			t.Errorf("needed-until %q", b)
		}
	}
	// a path segment that is not a plain name is refused in a file path
	for _, p := range []string{"a b", "a/ b", "a\"b", "../x"} {
		if _, err := FileNotes(p, sha64, 0o600, "now", "owner", "sealed"); err == nil {
			t.Errorf("file path %q", p)
		}
	}
	// and what is fine still works, byte for byte as before
	n, err := EntryNotes("owner", "plain", []string{"a", "file:x/y.env"}, "line one\nline two", "owner")
	if err != nil || n != "managed-by=owner\nvisibility=plain\nvis-by=owner\nlabels=a,file:x/y.env\nline one\nline two" {
		t.Errorf("%q %v", n, err)
	}
	if n, err := RetiredNotes("shop/OLD", sha64, 0o400, "2026-01-01T00:00:00Z", "later, or never"); err != nil || !strings.Contains(n, "needed-until=later, or never") {
		t.Errorf("%q %v", n, err)
	}
}
