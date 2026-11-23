package main

import (
	"bytes"
	"strings"
	"testing"
)

func relprune(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(args, strings.NewReader(stdin), &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

const releases = `[{"tagName":"v1.0.0","isDraft":false},{"tagName":"v1.0.1","isDraft":false},{"tagName":"v1.1.0","isDraft":false},{"tagName":"v1.2.0","isDraft":true}]`

func TestPrunesTheReleasesButNeverADraft(t *testing.T) {
	if got := relprune(t, releases); got != "v1.0.0\n" {
		t.Fatalf("got %q", got)
	}
}

func TestOnlyTheNewestFinalIsTheLatest(t *testing.T) {
	for tag, want := range map[string]string{"v1.2.0": "true\n", "v1.0.2": "false\n", "v1.1.0": "true\n", "v1.3.0-rc.1": "false\n"} {
		if got := relprune(t, releases, "-newest", tag); got != want {
			t.Errorf("%s: got %q, want %q", tag, got, want)
		}
	}
}

func TestReleaseCandidateTagsGoOnceTheirFinalExists(t *testing.T) {
	tags := "v1.0.0\nv1.1.0-rc.1\nv1.1.0-rc.2\nv1.1.0\nv1.2.0-rc.1\nnightly\n"
	if got := relprune(t, tags, "-rc-tags"); got != "v1.1.0-rc.1\nv1.1.0-rc.2\n" {
		t.Fatalf("got %q", got)
	}
}

func TestRefusesWhatIsNotTheReleaseList(t *testing.T) {
	if err := run(nil, strings.NewReader("not json"), &bytes.Buffer{}); err == nil {
		t.Fatal("no error")
	}
}
