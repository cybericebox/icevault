package vmodel

import "testing"

func TestSiteBackendFollowsTheStateConnection(t *testing.T) {
	hcp := &Connection{Name: "HCP", Kind: "hcp"}
	cases := []struct {
		s    *Site
		want string
	}{
		{nil, ""},
		{&Site{}, ""},
		{&Site{State: hcp}, "hcp"},
		{&Site{State: hcp, StateBackend: "legacy"}, "legacy"},
		{&Site{StateBackend: "hcp"}, "hcp"},
	}
	for i, c := range cases {
		if got := c.s.Backend(); got != c.want {
			t.Fatalf("case %d: %q, want %q", i, got, c.want)
		}
	}
}
