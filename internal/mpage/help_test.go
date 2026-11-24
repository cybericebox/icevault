package mpage

import (
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/example"
)

func TestConnectionFieldsCarryHelp(t *testing.T) {
	c, _ := newCore(t)
	var blob map[string]any
	for _, x := range c.Nav()["connections"].([]map[string]any) {
		if x["name"] == "Blob store" {
			blob = x
		}
	}
	for _, f := range blob["fields"].([]map[string]any) {
		h, _ := f["help"].(map[string]string)
		if h["en"] == "" || h["uk"] == "" || h["ru"] == "" {
			t.Errorf("field %v has no general help", f["name"])
		}
	}
	// the project's own help of the variable that carries the field comes with it
	c2, _ := newCoreWith(t, []byte(strings.Replace(string(example.Description()), "- {name: BLOB_BUCKET, field: bucket}", "- {name: BLOB_BUCKET, field: bucket, help: {en: The blob bucket of the portal.}}", 1)))
	for _, x := range c2.Nav()["connections"].([]map[string]any) {
		if x["name"] != "Blob store" {
			continue
		}
		for _, f := range x["fields"].([]map[string]any) {
			if f["name"] == "bucket" {
				if ph, _ := f["project_help"].(map[string]string); ph["en"] != "The blob bucket of the portal." {
					t.Fatalf("%v", f["project_help"])
				}
				return
			}
		}
	}
	t.Fatal("no bucket field")
}
