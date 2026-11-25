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
	list := fileViews(e.Files, "")
	if len(list) != 1 || list[0]["rel"] != "b.txt" || list[0]["site"] != "" || list[0]["sealed"] != true {
		t.Fatalf("list: %v", list)
	}
	site := fileViews(e.Sites[0].Files, e.Sites[0].Name)
	if len(site) != 1 || site[0]["site"] != e.Sites[0].Name {
		t.Fatalf("site list: %v", site)
	}
	for _, f := range append(list, site...) {
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
