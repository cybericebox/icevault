package vmodel

import (
	"fmt"
	"testing"

	"github.com/cybericebox/icevault/internal/model"
)

// The depth limit of the picker counts the referrers of the edited key: a value above it makes the chain longer.
func TestUnusableCountsTheReferrersOfTheEditedKey(t *testing.T) {
	// own is referred to by top, top by top2; target t0 starts a chain of MaxRefDepth links
	g := &refGraph{edges: map[string][]string{"shared.top2": {"shared.top"}, "shared.top": {"shared.own"}}}
	prev := "shared.t0"
	for i := 1; i < model.MaxRefDepth; i++ {
		next := fmt.Sprintf("shared.t%d", i)
		g.edges[prev] = append(g.edges[prev], next)
		prev = next
	}
	// t0 alone: MaxRefDepth links from t0 (t0 -> ... -> t7 as nodes = 8 nodes, 7 hops + the link own -> t0 = 8): allowed with no referrers
	free := (&refGraph{edges: map[string][]string{"shared.t0": g.edges["shared.t0"]}})
	for n, to := range g.edges {
		if len(n) > 8 && n[:8] == "shared.t" && n != "shared.top" && n != "shared.top2" {
			free.edges[n] = to
		}
	}
	if free.unusable("shared.own")["shared.t0"] {
		t.Fatal("t0 is usable when nothing refers to own")
	}
	if !g.unusable("shared.own")["shared.t0"] {
		t.Fatal("t0 is refused when own is two links below other values")
	}
}
