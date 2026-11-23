package model

import "testing"

// injections are descriptions a user may type. Every one of them must be
// refused by DescriptionText, because the parsers would otherwise read a
// machine line out of the description.
var injections = []string{
	"type=aws",
	"ok\ntype=aws",
	" visibility = plain",
	"x\n\tstate=retired",
	"x\r\nstate=retired",
	"x\rtitle=evil",
	"x\u2028state=retired",
	"x\u2029uses=environments/a",
	"x\vlabels=a",
	"x\fvis-by=owner",
	"x\u0085only-sites=a",
	"x\x85only-sites=a", /* invalid UTF-8 byte */
	"x\x1cmanaged-by=system",
	"\ufeffstate=retired",
	"x\n\u200bstate=retired",
	"x\n\u2060visibility=plain",
	"Visibility=plain",
	"MANAGED-BY=system",
	"site-type=aws",
	"x\nwas-managed=owner",
	"retired-why=entry",
	"x\x00state=retired",
}

func TestDescriptionInjectionIsRefused(t *testing.T) {
	for _, d := range injections {
		if got, err := DescriptionText(d); err == nil {
			t.Errorf("accepted %q (as %q)", d, got)
		}
	}
}

func TestRoundTripOfAcceptedDescriptions(t *testing.T) {
	accepted := []string{"", "plain text", "two\nlines", "a = b is not a machine line", "has=equals\nand more", "tabs\tinside", "ünïcode — ok", "blank\n\nline in the middle", "  trimmed  ",
		"typed=1", "types = x", "title2=x", "= leading equals"}
	for _, d := range accepted {
		desc, err := DescriptionText(d)
		if err != nil {
			t.Errorf("refused %q: %v", d, err)
			continue
		}
		it := NewItem("external", "cf")
		it.Title, it.OnlySites, it.SiteType, it.Description = "CF", []string{"a", "b"}, "aws", desc
		notes := nn(ItemNotes(it))
		n := ParseNotes(notes)
		want := map[string]string{"title": "CF", "only-sites": "a,b", "site-type": "aws", "state": "active"}
		for k, v := range want {
			if n[k] != v {
				t.Errorf("item %q: %s = %q, want %q", d, k, n[k], v)
			}
		}
		if len(n) != len(want) {
			t.Errorf("item %q: extra machine fields %v", d, n)
		}
		if got := HintOf(notes); got != desc {
			t.Errorf("item %q: description %q came back as %q", d, desc, got)
		}
		en := nn(EntryNotes("owner", "plain", []string{"x", "y"}, desc, "owner"))
		m := ParseNotes(en)
		wantE := map[string]string{"managed-by": "owner", "visibility": "plain", "vis-by": "owner", "labels": "x,y"}
		for k, v := range wantE {
			if m[k] != v {
				t.Errorf("entry %q: %s = %q, want %q", d, k, m[k], v)
			}
		}
		if len(m) != len(wantE) || HintOf(en) != desc {
			t.Errorf("entry %q: fields %v hint %q", d, m, HintOf(en))
		}
		s := NewSnapshot()
		if err := s.Ingest(RawEntry{Path: []string{"external", "cf"}, Title: ".item", Notes: notes}); err != nil {
			t.Errorf("ingest %q: %v", d, err)
			continue
		}
		if s.Item("external", "cf").Description != desc || s.Item("external", "cf").Title != "CF" {
			t.Errorf("ingest %q changed the item", d)
		}
	}
}

func TestParseNotesReadsOnlyMachineKeys(t *testing.T) {
	n := ParseNotes("managed-by=owner\nfree=text\nanything = else\nstate=active")
	if len(n) != 2 || n["managed-by"] != "owner" || n["state"] != "active" {
		t.Errorf("got %v", n)
	}
}

func TestOneLineRefusesEveryLineSeparator(t *testing.T) {
	for _, sep := range []string{"\n", "\r", "\u2028", "\u2029", "\v", "\f", "\x85", "\x1c", "\x00"} {
		if _, err := OneLine("a"+sep+"state=retired", "a title", 120); err == nil {
			t.Errorf("one_line accepted %q", sep)
		}
	}
	if _, err := OneLine("fine title", "a title", 120); err != nil {
		t.Error("a normal title is fine")
	}
}
