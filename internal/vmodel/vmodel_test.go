package vmodel

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/pkg/vault"
)

const pw = "pw-throwaway-1"

func desc(t *testing.T) *project.Description {
	t.Helper()
	d, err := project.Parse(example.Description())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func sample() *Vault {
	aws := &Connection{Name: "GCP main", Kind: "google", Fields: []*Field{{Name: "credentials", Value: "creds/gcp.json"}, {Name: "project", Value: "lumen-1"}}}
	second := &Connection{Name: "GCP second", Kind: "google", Fields: []*Field{{Name: "project", Value: "lumen-2"}}}
	cf := &Connection{Name: "Blob store", Kind: "s3", Fields: []*Field{{Name: "secret_access_key", Value: "blob-sec", Secret: true}, {Name: "bucket", Value: ""}}}
	hcp := &Connection{Name: "TFC", Kind: "hcp", Fields: []*Field{{Name: "organization", Value: "org1"}}}
	admin := &Var{Key: "CONTACT_ADDRESS", Value: "help@example.org", Vis: VisPlain}
	main := &Site{Name: "main", Kind: "google-cluster", Connection: aws, State: hcp, StateBackend: "tfc", Vars: []*Var{{Key: "GKE_POOL", Value: "c1", Vis: VisPlain}},
		Files: []*File{{Rel: "creds/gcp.kubeconfig", Data: []byte("kc\x00\x01"), Mode: 0o600}}}
	other := &Site{Name: "indexer-host", Kind: "google-cluster", Connection: second}
	prod := &Environment{Name: "prod", Title: "Production", General: []*Var{{Key: "PUBLIC_HOST", Value: "example.org", Vis: VisPlain}}, Imports: []*Var{admin},
		Sites: []*Site{main, other}, Layouts: map[string][]byte{"services-portal": []byte(`{"lines": [], "v": 1}`)},
		Products: []*Product{
			{Name: "portal", Enabled: true, Place: "cluster", Site: main, Connections: []*Connection{cf}, Vars: []*Var{{Key: "COOKIE_KEY", Value: "sig", Managed: ManagedSystem, Vis: VisSealed}},
				Sub: map[string][]*Var{"google-cluster": {{Key: "EXPORT_BUCKET", Value: "b1", Vis: VisPlain}}}},
			{Name: "indexer", Enabled: false, Place: "none", Site: other},
		}}
	return &Vault{Format: Format, Shared: []*Var{admin}, Connections: []*Connection{aws, second, cf, hcp}, Envs: []*Environment{prod},
		Other: []*Other{{Title: "a note", Value: "v", Notes: "n"}, {Title: "dump", Data: []byte("sql"), Extra: "dumps/x.sql"}}}
}

func TestWriteLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.kdbx")
	v, err := vault.Create(p, vault.Credentials{Password: []byte(pw)}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if FormatOf(v) != 0 {
		t.Fatal("a new vault has a format")
	}
	if _, err := Load(v); err == nil || !strings.Contains(err.Error(), "holds no vault model") {
		t.Fatalf("load of a vault before the model: %v", err)
	}
	if err := Write(v, sample()); err != nil {
		t.Fatal(err)
	}
	if err := Write(v, sample()); err == nil {
		t.Fatal("a second write into a vault with a model")
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	v.Close()
	v, err = vault.Open(p, vault.Credentials{Password: []byte(pw)})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	m, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Problems) > 0 || m.ReadOnly || m.Format != Format {
		t.Fatalf("%v %v", m.Problems, m.ReadOnly)
	}
	e := m.Env("prod")
	if e == nil || e.Title != "Production" || len(e.Imports) != 1 || e.Imports[0] != m.SharedVar("CONTACT_ADDRESS") {
		t.Fatalf("env %+v", e)
	}
	s := e.Site("main")
	if s.Kind != "google-cluster" || s.Connection != m.Connection("GCP main") || s.State != m.Connection("TFC") || s.StateBackend != "tfc" || len(s.Files) != 1 || string(s.Files[0].Data) != "kc\x00\x01" {
		t.Fatalf("site %+v", s)
	}
	pl := e.Product("portal")
	if !pl.Enabled || pl.Site != s || pl.Place != "cluster" || len(pl.Connections) != 1 || pl.Connections[0].Name != "Blob store" || pl.Sub["google-cluster"][0].Value != "b1" || pl.Vars[0].Vis != VisSealed {
		t.Fatalf("portal %+v", pl)
	}
	if br := e.Product("indexer"); br.Enabled || br.Site != e.Site("indexer-host") {
		t.Fatalf("indexer %+v", br)
	}
	if c := m.Connection("Blob store"); c.Field("secret_access_key").Value != "blob-sec" || !c.Field("secret_access_key").Secret || c.Field("bucket") == nil {
		t.Fatalf("blobs %+v", c)
	}
	if len(m.Other) != 2 || string(e.Layouts["services-portal"]) == "" {
		t.Fatalf("other %+v", m.Other)
	}
	// a newer format is read only
	v.SetMetaValue(FormatKey, "7")
	if err := CheckWritable(v); err != ErrNewerFormat {
		t.Fatal("a newer format is writable")
	}
	if m2, err := Load(v); err != nil || !m2.ReadOnly {
		t.Fatalf("newer: %v", err)
	}
}

func TestCheckRefusesBrokenModels(t *testing.T) {
	m := sample()
	m.Envs[0].Sites[0].Connection = m.Connections[2] // the blob store on a Google Cloud site
	m.Envs[0].Products[0].Site = &Site{Name: "elsewhere", Kind: "compose"}
	m.Connections = append(m.Connections, &Connection{Name: "a/b", Kind: "FTP"})
	errs := strings.Join(m.Check(), "\n")
	for _, w := range []string{"needs a connection of kind \"google\"", "its site is not a site of prod", "not a name", "not a kind id"} {
		if !strings.Contains(errs, w) {
			t.Errorf("no %q in %s", w, errs)
		}
	}
}

func TestBatches(t *testing.T) {
	m, d := sample(), desc(t)
	bs, err := Batches(m, d, "prod", Selection{Product: "portal"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range bs {
		got = append(got, b.Name+"("+strings.Join(b.Variables, ",")+")")
	}
	want := "general(PUBLIC_HOST,CONTACT_ADDRESS) product-portal(COOKIE_KEY,EXPORT_BUCKET) site-main(GKE_POOL) connection-gcp-main(GCP_PROJECT_ID,GCP_KEY_PATH) connection-tfc(TFC_ORG) connection-blob-store(BLOB_KEY_SECRET,BLOB_BUCKET)"
	if strings.Join(got, " ") != want {
		t.Fatalf("got  %s\nwant %s", strings.Join(got, " "), want)
	}
	if bs[1].Site != "site-main" || bs[1].Connections[0] != "connection-blob-store" || bs[2].Connections[0] != "connection-gcp-main" || bs[2].State != "connection-tfc" {
		t.Fatalf("references %+v %+v", bs[1], bs[2])
	}
	// two sites on two Google Cloud projects: each site has its own connection batch, nothing collides
	all, err := Batches(m, d, "prod", Selection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, b := range all {
		if b.ConnectionKind == "google" {
			n++
		}
		if b.Name == "product-indexer" {
			t.Fatal("a product that is off is in --all")
		}
	}
	if n != 2 {
		t.Fatalf("google batches: %d", n)
	}
	if _, err := Batches(m, d, "prod", Selection{Site: "nope"}); err == nil || !strings.Contains(err.Error(), "it has: main, indexer-host") {
		t.Fatalf("%v", err)
	}
	if _, err := Batches(m, d, "nope", Selection{All: true}); err == nil {
		t.Fatal("unknown environment")
	}
}

func TestCompatSkipsTwoSites(t *testing.T) {
	m := sample()
	c := Compat(m, desc(t), nil)
	if c.Skipped["prod"] == "" || c.Snap.Extras["dumps/x.sql"] == nil {
		t.Fatalf("%+v", c.Skipped)
	}
	m.Envs[0].Sites = m.Envs[0].Sites[:1]
	m.Envs[0].Products = m.Envs[0].Products[:1]
	c = Compat(m, desc(t), nil)
	it := c.Snap.Item("environments", "prod")
	if it == nil || it.Files["creds/gcp.kubeconfig"] == nil {
		t.Fatal("no item")
	}
	var keys []string
	for _, e := range it.Entries {
		keys = append(keys, e.Key+"="+e.Value)
	}
	want := "PUBLIC_HOST=example.org CONTACT_ADDRESS=help@example.org HOSTING=gcp STATE_STORE=tfc GKE_POOL=c1 GCP_PROJECT_ID=lumen-1 GCP_KEY_PATH=creds/gcp.json TFC_ORG=org1 PORTAL=cluster COOKIE_KEY=sig EXPORT_BUCKET=b1 BLOB_KEY_SECRET=blob-sec BLOB_BUCKET="
	if strings.Join(keys, " ") != want {
		t.Fatalf("got  %s\nwant %s", strings.Join(keys, " "), want)
	}
}
