package cli

import (
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

func (h *harness) model() *vmodel.Vault {
	h.t.Helper()
	v, err := vault.Open(h.env["ICEVAULT_VAULT"], vault.Credentials{Password: []byte(pw)})
	if err != nil {
		h.t.Fatal(err)
	}
	defer v.Close()
	m, err := vmodel.Load(v)
	if err != nil {
		h.t.Fatal(err)
	}
	return m
}

func hasKey(vs []*vmodel.Var, k string) *vmodel.Var {
	for _, x := range vs {
		if x.Key == k {
			return x
		}
	}
	return nil
}
