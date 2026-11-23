package vmodel

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cybericebox/icevault/pkg/vault"
)

func TestSyncKeepsEntriesAndFollowsRenames(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.kdbx")
	v, err := vault.Create(p, vault.Credentials{Password: []byte(pw)}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	m := sample()
	if err := Write(v, m); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	m, err = Load(v)
	if err != nil {
		t.Fatal(err)
	}
	cf := m.Connection("Blob store")
	id := cf.UUID
	site := m.Env("prod").Site("main")
	siteID := site.UUID
	// rename a connection and a site, swap two variable names, drop a field, change a value, remove an Other entry, add a product variable
	cf.Name = "Blobs"
	cf.Fields = cf.Fields[:1]
	site.Name = "eu"
	g := m.Env("prod").General
	g = append(g, &Var{Key: "B", Value: "b", Vis: VisPlain})
	m.Env("prod").General = g
	m.Shared[0].Value = "new@example.org"
	m.Other = m.Other[1:]
	m.Env("prod").Product("portal").Vars = append(m.Env("prod").Product("portal").Vars, &Var{Key: "X", Value: "x", Vis: VisSecret})
	if err := Sync(v, m); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	back, err := Load(v)
	if err != nil || len(back.Problems) > 0 {
		t.Fatalf("%v %v", err, back.Problems)
	}
	c := back.Connection("Blobs")
	if c == nil || c.UUID != id || len(c.Fields) != 1 || back.Connection("Blob store") != nil {
		t.Fatalf("connection %+v", c)
	}
	e := back.Env("prod")
	if s := e.Site("eu"); s == nil || s.UUID != siteID || e.Site("main") != nil || e.Product("portal").Site != s {
		t.Fatal("site rename")
	}
	if e.Product("portal").Connections[0] != c {
		t.Fatal("the product lost its connection")
	}
	if back.SharedVar("CONTACT_ADDRESS").Value != "new@example.org" || e.Imports[0] != back.SharedVar("CONTACT_ADDRESS") {
		t.Fatal("shared")
	}
	if len(back.Other) != 1 || len(e.General) != 2 || len(e.Product("portal").Vars) != 2 || string(e.Layouts["services-portal"]) == "" {
		t.Fatalf("%d %d", len(back.Other), len(e.General))
	}
	if v.HasGroup(GroupEnvs+"/prod/Sites/main") || v.HasGroup(GroupOther+"/.icevault-moving") {
		t.Fatal("an empty group stayed")
	}
	// a second sync of the same model changes nothing
	before, _ := v.Entries(GroupConnections)
	if err := Sync(v, back); err != nil {
		t.Fatal(err)
	}
	after, _ := v.Entries(GroupConnections)
	if before[0].Modified != after[0].Modified || before[0].History != after[0].History {
		t.Fatal("a sync without a change touched an entry")
	}
}
