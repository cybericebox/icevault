package retention

import (
	"fmt"
	"reflect"
	"testing"
)

func TestCurrentMinorKeepsEveryPatchOlderMinorsOnlyTheLatest(t *testing.T) {
	tags := []string{"v1.0.0", "v1.0.1", "v1.0.2", "v1.1.0", "v1.1.1", "v1.2.0", "v1.2.1", "v1.2.2"}
	want := []string{"v1.0.0", "v1.0.1", "v1.1.0"}
	if got := Delete(tags, 10); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOnlyThePreviousTenMinorsKeepTheirLatestPatch(t *testing.T) {
	var tags []string
	for m := 0; m <= 12; m++ {
		tags = append(tags, fmt.Sprintf("v1.%d.0", m), fmt.Sprintf("v1.%d.1", m))
	}
	got := Delete(tags, 10)
	// minors 12 (current, all kept), 11..2 (the previous ten, latest patch kept), 1 and 0 (out of the window: both patches deleted)
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for m := 2; m <= 11; m++ {
		if !set[fmt.Sprintf("v1.%d.0", m)] || set[fmt.Sprintf("v1.%d.1", m)] {
			t.Errorf("minor %d: %v", m, got)
		}
	}
	for m := 0; m <= 1; m++ {
		if !set[fmt.Sprintf("v1.%d.0", m)] || !set[fmt.Sprintf("v1.%d.1", m)] {
			t.Errorf("minor %d is out of the window but kept: %v", m, got)
		}
	}
	if set["v1.12.0"] || set["v1.12.1"] {
		t.Errorf("the current minor lost a patch: %v", got)
	}
}

func TestMajorsOrderBeforeMinors(t *testing.T) {
	tags := []string{"v1.9.0", "v1.9.1", "v2.0.0", "v2.0.1"}
	want := []string{"v1.9.0"} // v2.0 is current (all kept); v1.9 is the previous minor (latest patch kept)
	if got := Delete(tags, 10); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestReleaseCandidatesGoOnceTheFinalExists(t *testing.T) {
	tags := []string{"v1.3.0-rc.1", "v1.3.0-rc.2", "v1.3.0", "v1.4.0-rc.1"}
	want := []string{"v1.3.0-rc.1", "v1.3.0-rc.2"} // the candidate of 1.4.0 has no final yet
	if got := Delete(tags, 10); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOtherTagsAndAnEmptyListAreLeftAlone(t *testing.T) {
	if got := Delete([]string{"nightly", "v1.2", "release-1", "v1.0.0"}, 10); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if got := Delete(nil, 10); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestNewestIsOnlyTheHighestFinal(t *testing.T) {
	tags := []string{"v1.0.0", "v1.1.0", "v1.1.1", "v2.0.0-rc.1"}
	for tag, want := range map[string]bool{"v1.1.2": true, "v1.0.1": false, "v1.1.1": true, "v2.0.0-rc.2": false, "v2.0.0": true, "nightly": false} {
		if got := Newest(tags, tag); got != want {
			t.Errorf("%s: got %v, want %v", tag, got, want)
		}
	}
}

func TestCandidateTagsAreOnlyCandidatesWithAFinal(t *testing.T) {
	tags := []string{"v1.0.0", "v1.0.1", "v1.1.0", "v1.2.0-rc.1", "v1.2.0", "v1.3.0-rc.1"}
	if got := CandidateTags(tags); !reflect.DeepEqual(got, []string{"v1.2.0-rc.1"}) {
		t.Fatalf("got %v", got)
	}
}

func TestOrderOfTheInputDoesNotMatter(t *testing.T) {
	a := Delete([]string{"v1.0.1", "v1.1.0", "v1.0.0", "v1.1.1", "v1.2.0"}, 10)
	b := Delete([]string{"v1.2.0", "v1.1.1", "v1.1.0", "v1.0.1", "v1.0.0"}, 10)
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a, []string{"v1.0.0", "v1.1.0"}) {
		t.Fatalf("%v %v", a, b)
	}
}
