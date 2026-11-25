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
}
