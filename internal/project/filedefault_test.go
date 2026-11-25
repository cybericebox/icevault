package project

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/example"
)

func TestFileDefaultIsValidated(t *testing.T) {
	const old = "{name: GCP_KEY_PATH, field: credentials}"
	base := string(example.Description())
	if !strings.Contains(base, old) {
		t.Fatal("the example changed")
	}
	for name, tc := range map[string]struct{ pat, want string }{
		"ok":        {"generated/*/account/credentials.json", ""},
		"absolute":  {"/etc/key", "file-default"},
		"parent":    {"../key", "file-default"},
		"unclean":   {"a//b", "file-default"},
		"bad glob":  {"a[", "file-default"},
		"dot-parts": {"a/../b", "file-default"},
	} {
		d := strings.Replace(base, old, "{name: GCP_KEY_PATH, field: credentials, file-default: '"+tc.pat+"'}", 1)
		_, err := Parse([]byte(d))
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v", name, err)
		}
	}
	// outside a connection
	d := strings.Replace(base, "{name: GKE_POOL", "{file-default: x, name: GKE_POOL", 1)
	if d != base {
		if _, err := Parse([]byte(d)); err == nil || !strings.Contains(err.Error(), "file-default") {
			t.Errorf("file-default outside a connection: %v", err)
		}
	}
}
