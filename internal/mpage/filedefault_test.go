package mpage

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/vmodel"
)

func TestAnEmptyFieldNamesTheFileOfTheSiteThatCoversIt(t *testing.T) {
	desc := strings.Replace(string(example.Description()), "{name: GCP_KEY_PATH, field: credentials}", "{name: GCP_KEY_PATH, field: credentials, file-default: 'creds/*.json'}", 1)
	c, _ := newCoreWith(t, []byte(desc))
	e := c.Model().Envs[0]
	gcp := e.Sites[0].Connection
	field := func() map[string]any {
		for _, f := range c.connView(gcp, nil)["fields"].([]map[string]any) {
			if f[jName] == "credentials" {
				return f
			}
		}
		t.Fatal("no credentials field")
		return nil
	}
	gcp.Field("credentials").Value = ""
	if field()["file_used"] != nil {
		t.Fatal("no file yet")
	}
	e.Sites[0].Files = []*vmodel.File{{Rel: "creds/gcp.json", Data: []byte("TOPSECRET"), Vis: vmodel.VisSealed}}
	if got := field()["file_used"]; got != "creds/gcp.json" {
		t.Fatalf("file_used: %v", got)
	}
	gcp.Field("credentials").Value = "filled"
	if field()["file_used"] != nil {
		t.Fatal("a filled field names no file")
	}
}
