package mpage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// infraDescription finds the project description of the infrastructure checkout (CIB_INFRA_ROOT, else a sibling "infrastructure" folder above this
// one) and reads it as it is, in place: nothing of it is copied into this repository (a public one), and nothing below private/ is ever read.
func infraDescription(t *testing.T) *project.Description {
	t.Helper()
	root := os.Getenv("CIB_INFRA_ROOT")
	if root == "" {
		dir, _ := os.Getwd()
		for d := dir; d != filepath.Dir(d); d = filepath.Dir(d) {
			if _, err := os.Stat(filepath.Join(d, "infrastructure", project.FileName)); err == nil {
				root = filepath.Join(d, "infrastructure")
				break
			}
		}
	}
	if root == "" {
		t.Skip("no infrastructure checkout next to this one (CIB_INFRA_ROOT)")
	}
	d, err := project.Load(filepath.Join(root, project.FileName))
	if err != nil {
		t.Skipf("the description of the checkout is not one this version reads: %v", err)
	}
	return d
}

// The real description: a staging environment whose Brain is on the cluster lists the empty values of Brain as needed; with BRAIN=none it needs none.
func TestRealDescriptionBrainOnTheClusterNeedsItsValues(t *testing.T) {
	d := infraDescription(t)
	p := filepath.Join(t.TempDir(), "v.kdbx")
	v, err := vault.Create(p, vault.Credentials{Password: []byte("pw-throwaway-1")}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	brain := &vmodel.Product{Name: "brain", Enabled: true, Place: "cluster", Sub: map[string][]*vmodel.Var{}}
	m := &vmodel.Vault{Format: vmodel.Format, Envs: []*vmodel.Environment{{Name: "staging", Layouts: map[string][]byte{}, Products: []*vmodel.Product{brain}}}}
	if err := vmodel.Write(v, m); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	c, err := New(v, d)
	if err != nil {
		t.Fatal(err)
	}
	e := c.Model().Env("staging")
	missing := func() map[string]bool {
		out := map[string]bool{}
		for _, p := range c.envView(e)["products"].([]map[string]any) {
			if p["name"] == "brain" {
				for _, x := range p["missing"].([]map[string]any) {
					if k, _ := x["key"].(string); k != "" {
						out[k] = true
					}
				}
			}
		}
		return out
	}
	want := []string{"BRAIN_TAG", "BRAIN_INFERENCE_URL", "BRAIN_INFERENCE_API_KEY", "BRAIN_REGISTRY_USERNAME", "BRAIN_REGISTRY_TOKEN", "BRAIN_TOKEN"}
	got := missing()
	for _, k := range want {
		if !got[k] {
			t.Errorf("%s is not listed as needed for BRAIN=cluster (listed: %v)", k, got)
		}
	}
	e.Product("brain").Place = "none" // the model the core holds, not the one the vault was written from
	for _, k := range want {
		if missing()[k] {
			t.Errorf("%s is needed with BRAIN=none", k)
		}
	}
}
