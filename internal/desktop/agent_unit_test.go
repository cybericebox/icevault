package desktop

import "testing"

func TestAnyFileOfAnEnvironmentCountsAsASecretForTheCopyGate(t *testing.T) {
	plain := map[string]any{"general": []any{map[string]any{"state": "set", "visibility": "plain"}}}
	if hasSecrets(plain) {
		t.Fatal("a plain environment counts as secret")
	}
	withFile := map[string]any{"file_list": []any{map[string]any{"rel": "a", "sealed": false}}}
	if !hasSecrets(withFile) {
		t.Fatal("a file of the environment is not counted")
	}
	siteFile := map[string]any{"sites": []any{map[string]any{"file_list": []any{map[string]any{"rel": "k"}}}}}
	if !hasSecrets(siteFile) {
		t.Fatal("a file of a site is not counted")
	}
}

func TestCleanHidesInvisibleCharacters(t *testing.T) {
	if got := clean("a\u202eb\u200bc\x1b", 20); got != "a?b?c " {
		t.Fatalf("%q", got)
	}
	if got := clean("abcdef", 3); got != "abc…" {
		t.Fatalf("%q", got)
	}
}

func TestADraftBelongsToTheHolderOfItsToken(t *testing.T) {
	h := newAgentHub(nil, "", 0, -1)
	h.drafts["x"] = &agentBatch{id: "x", token: "abcdef"}
	if h.draftWith("x", "abcdef") == nil {
		t.Fatal("the holder does not get its draft")
	}
	for _, other := range []string{"", "abcdeg", "abcde", "abcdefg"} {
		if h.draftWith("x", other) != nil {
			t.Fatalf("the token %q opened the draft", other)
		}
	}
	h.drafts["y"] = &agentBatch{id: "y"} // a draft without a token is never open
	if h.draftWith("y", "") != nil {
		t.Fatal("an empty token opened a draft")
	}
}

func TestAReplayStopsWhenTheVaultWasLocked(t *testing.T) {
	h := newAgentHub(nil, "", 0, -1)
	items := []*agentItem{{op: "var-create", target: "a"}, {op: "var-create", target: "b"}}
	results, failed, code := h.replay(nil, items, func() bool { return true })
	if failed != 0 || code != "locked" || len(results) != 2 || results[0].Result != "failed: locked" || results[1].Result != "skipped" {
		t.Fatalf("%d %q %+v", failed, code, results)
	}
}
