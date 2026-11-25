package mpage

import (
	"testing"

	"github.com/cybericebox/icevault/internal/vmodel"
)

func TestAnEmptyFieldNamesTheFileOfTheSiteThatCoversIt(t *testing.T) {
	c, _ := newCore(t)
	e := c.Model().Envs[0]
	gcp := e.Sites[0].Connection
	x := c.connView(gcp, nil)
	for _, f := range x["fields"].([]map[string]any) {
		if f["file_used"] != nil {
			t.Fatalf("no file-default in the description, yet %v", f)
		}
	}
	e.Sites[0].Files = []*vmodel.File{{Rel: "generated/x/account/credentials.json", Vis: vmodel.VisSealed}}
	if got := c.fileDefaultUsed(gcp, "credentials"); got != "" {
		t.Fatalf("without file-default: %q", got)
	}
}
