package mpage

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/vmodel"
)

func TestFileListHasNoContent(t *testing.T) {
	c, _ := newCore(t)
	m := c.Model()
	e := m.Envs[0]
	e.Files = []*vmodel.File{{Rel: "b.txt", Data: []byte("TOPSECRET-env"), Vis: vmodel.VisSealed, Changed: "2030-01-02T03:04:05Z"}}
	e.Sites[0].Files = []*vmodel.File{{Rel: "generated/x/account/credentials.json", Data: []byte("TOPSECRET-site"), Vis: vmodel.VisSealed}}
	list := envFileViews(e)
	if len(list) != 2 || list[0]["rel"] != "b.txt" || list[0]["site"] != "" || list[1]["site"] != e.Sites[0].Name || list[0]["sealed"] != true {
		t.Fatalf("list: %v", list)
	}
	for _, f := range list {
		for k, x := range f {
			if s, ok := x.(string); ok && strings.Contains(s, "TOPSECRET") {
				t.Fatalf("content in %s", k)
			}
			if k == "size" || k == "mode" || k == "data" {
				t.Fatalf("unexpected key %s", k)
			}
		}
	}
}
