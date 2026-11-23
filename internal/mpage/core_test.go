package mpage

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/internal/desktop"
	"github.com/cybericebox/icevault/internal/example"
	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

func newCore(t *testing.T) (*Core, *vault.Vault) {
	t.Helper()
	d, err := project.Parse(example.Description())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "v.kdbx")
	v, err := vault.Create(p, vault.Credentials{Password: []byte("pw-throwaway-1")}, vault.CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	gcp := &vmodel.Connection{Name: "GCP", Kind: "google", Fields: []*vmodel.Field{{Name: "credentials", Value: "gkey-secret-1", Secret: true}, {Name: "project", Value: "lumen-prod"}}}
	cf := &vmodel.Connection{Name: "Blob store", Kind: "s3", Fields: []*vmodel.Field{{Name: "secret_access_key", Value: "blob-secret-1", Secret: true}}}
	admin := &vmodel.Var{Key: "CONTACT_ADDRESS", Value: "hello@example.net", Vis: vmodel.VisPlain}
	site := &vmodel.Site{Name: "main", Kind: "google-cluster", Connection: gcp, Vars: []*vmodel.Var{{Key: "GKE_POOL", Value: "c1", Vis: vmodel.VisPlain}}}
	m := &vmodel.Vault{Format: vmodel.Format, Shared: []*vmodel.Var{admin}, Connections: []*vmodel.Connection{gcp, cf},
		Envs: []*vmodel.Environment{{Name: "prod", General: []*vmodel.Var{{Key: "PUBLIC_HOST", Value: "example.org", Vis: vmodel.VisPlain}}, Imports: []*vmodel.Var{admin}, Sites: []*vmodel.Site{site},
			Layouts: map[string][]byte{}, Products: []*vmodel.Product{{Name: "portal", Enabled: true, Site: site, Connections: []*vmodel.Connection{cf},
				Vars: []*vmodel.Var{{Key: "COOKIE_KEY", Value: "sig-secret-1", Vis: vmodel.VisSealed, Managed: vmodel.ManagedSystem}}, Sub: map[string][]*vmodel.Var{}}}}},
		Other: []*vmodel.Other{{Title: "wifi", Value: "wifi-secret-1"}}}
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
	return c, v
}

func code(err error) string {
	var de *desktop.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

func TestNavShowsTheModelAndNoSecret(t *testing.T) {
	c, _ := newCore(t)
	b, err := json.Marshal(c.Nav())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, secret := range []string{"gkey-secret-1", "blob-secret-1", "sig-secret-1", "wifi-secret-1"} {
		if strings.Contains(s, secret) {
			t.Fatalf("the answer holds %s", secret)
		}
	}
	for _, want := range []string{"example.org", "lumen-prod", "\"imported\":true", "\"kind\":\"google-cluster\"", "Публічний хост", "\"missing\":["} {
		if !strings.Contains(s, want) {
			t.Errorf("the answer lacks %s", want)
		}
	}
	if v, err := c.Reveal("m", "conn/"+c.Model().Connection("GCP").UUID, "", "credentials"); err != nil || v != "gkey-secret-1" {
		t.Fatalf("reveal %q %v", v, err)
	}
	if _, err := c.Reveal("m", "env/prod/product/portal", "", "COOKIE_KEY"); code(err) != "sealed" {
		t.Fatalf("a sealed value is revealed: %v", err)
	}
}

func TestWritesAskBeforeTouchingWhatIsUsed(t *testing.T) {
	c, v := newCore(t)
	gcp := c.Model().Connection("GCP").UUID
	if _, err := c.Write("m-connection", map[string]any{"action": "update", "uuid": gcp, "name": "GCP main"}); code(err) != "confirm_rename_used" {
		t.Fatalf("rename of a used connection: %v", err)
	}
	if _, err := c.Write("m-connection", map[string]any{"action": "update", "uuid": gcp, "name": "GCP main", "confirm": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-connection", map[string]any{"action": "create", "name": "GCP second", "kind": "google"}); err != nil {
		t.Fatal(err)
	}
	second := c.Model().Connection("GCP second")
	if _, err := c.Write("m-site", map[string]any{"env": "prod", "action": "update", "name": "main", "connection": second.UUID}); code(err) != "confirm_site_connection" {
		t.Fatalf("a new connection of a site that runs: %v", err)
	}
	if _, err := c.Write("m-site", map[string]any{"env": "prod", "action": "update", "name": "main", "connection": c.Model().Connection("Blob store").UUID, "confirm": true}); code(err) != "wrong_connection_kind" {
		t.Fatalf("a connection of another kind: %v", err)
	}
	if _, err := c.Write("m-site", map[string]any{"env": "prod", "action": "update", "name": "main", "connection": second.UUID, "confirm": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-var", map[string]any{"scope": "env/prod/product/portal", "key": "COOKIE_KEY", "value": "x"}); code(err) != "system_managed" {
		t.Fatalf("a system value is edited by hand: %v", err)
	}
	for _, w := range []map[string]any{
		{"scope": "env/prod/general", "key": "NOTES_LABEL", "value": "the production"},
		{"scope": "env/prod/product/portal/google-cluster", "key": "EXPORT_BUCKET", "value": "b1"},
		{"scope": "shared", "key": "SHARED_NOTE", "value": "age1x"},
	} {
		if _, err := c.Write("m-var", w); err != nil {
			t.Fatalf("%v: %v", w, err)
		}
	}
	if _, err := c.Write("m-import", map[string]any{"env": "prod", "keys": []any{"CONTACT_ADDRESS", "SHARED_NOTE"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-var", map[string]any{"scope": "shared", "key": "SHARED_NOTE", "delete": true}); code(err) != "confirm_shared_used" {
		t.Fatalf("a shared value in use: %v", err)
	}
	if _, err := c.Write("m-env", map[string]any{"action": "copy", "name": "staging", "from": "prod", "title": "Staging"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-product", map[string]any{"env": "staging", "action": "update", "name": "portal", "enabled": false}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-other", map[string]any{"action": "create", "title": "router", "value": "r-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write("m-site", map[string]any{"env": "prod", "action": "delete", "name": "main"}); code(err) != "confirm_delete_site" {
		t.Fatalf("delete a used site: %v", err)
	}
	// what was written is in the file
	back, err := vmodel.Load(v)
	if err != nil || len(back.Problems) > 0 {
		t.Fatalf("%v %v", err, back.Problems)
	}
	st := back.Env("staging")
	if st == nil || st.Title != "Staging" || st.Product("portal").Enabled || st.Site("main").Connection != back.Connection("GCP second") || len(st.Imports) != 2 {
		t.Fatalf("the copy %+v", st)
	}
	if back.Env("prod").Product("portal").Sub["google-cluster"][0].Value != "b1" || back.Connection("GCP main") == nil || len(back.Other) != 2 {
		t.Fatal("the writes are not in the vault")
	}
	if back.Env("prod").Site("main").Connection.Name != "GCP second" {
		t.Fatal("the site connection")
	}
}

// m-env-fill: the window's "create missing entries" is vmodel.FillMissing: empty entries only, nothing that exists is changed, an imported
// key is not made again.
func TestEnvFill(t *testing.T) {
	c, _ := newCore(t)
	res, err := c.Write("m-env-fill", map[string]any{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := res.(map[string]any)
	if n, _ := r["added"].(int); n == 0 {
		t.Fatalf("nothing added: %v", res)
	}
	e := c.Model().Env("prod")
	web := e.Product("portal")
	for _, x := range web.Vars {
		if x.Key == "COOKIE_KEY" && x.Value != "sig-secret-1" {
			t.Fatal("an existing value changed")
		}
		if x.Key == "CONTACT_ADDRESS" {
			t.Fatal("an imported key was made again")
		}
		if x.Key == "SIGNUP_MODE" && x.Value != "" {
			t.Fatal("a value was written")
		}
	}
	if e.Sites[0].Connection.Field("credentials").Value != "gkey-secret-1" {
		t.Fatal("a connection field changed")
	}
	again, err := c.Write("m-env-fill", map[string]any{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := again.(map[string]any)["added"].(int); n != 0 {
		t.Fatalf("second fill added %d", n)
	}
	if _, err := c.Write("m-env-fill", map[string]any{"env": "nothing"}); code(err) != "no_env" {
		t.Fatalf("unknown environment: %v", err)
	}
}
