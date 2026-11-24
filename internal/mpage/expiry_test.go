package mpage

import (
	"testing"
	"time"
)

func TestExpiryIsSetListedAndNeverCarriesValues(t *testing.T) {
	c, v := newCore(t)
	c.Now = func() time.Time { return time.Date(2030, 1, 10, 12, 0, 0, 0, time.UTC) }
	gcp := c.Model().Connections[0]
	steps := []struct {
		op string
		a  map[string]any
	}{
		{"m-var", map[string]any{"scope": "env/prod/general", "key": "PUBLIC_HOST", "expires": "2030-01-09"}},
		{"m-var", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS", "expires": "2030-01-20"}},
		{"m-field", map[string]any{"uuid": gcp.UUID, "field": "credentials", "expires": "2030-01-12"}},
		{"m-other", map[string]any{"action": "create", "title": "token-note", "value": "x", "expires": "2031-01-01"}},
	}
	for _, s := range steps {
		if _, err := c.Write(s.op, s.a); err != nil {
			t.Fatalf("%s: %v", s.op, err)
		}
	}
	if _, err := c.Write("m-var", map[string]any{"scope": "shared", "key": "CONTACT_ADDRESS", "expires": "12.01"}); code(err) != "bad_date" {
		t.Fatalf("a date in a wrong form: %v", err)
	}
	nav := c.Nav()
	if nav["expired_count"] != 1 || nav["soon_count"] != 2 {
		t.Fatalf("counts: %v %v", nav["expired_count"], nav["soon_count"])
	}
	list := nav["expiring"].([]map[string]any)
	if len(list) != 3 || list[0]["name"] != "PUBLIC_HOST" || list[0]["state"] != "expired" || list[0]["date"] != "2030-01-09" {
		t.Fatalf("list: %v", list)
	}
	for _, it := range list {
		for k, x := range it {
			if s, _ := x.(string); s == "gkey-secret-1" || s == "example.org" || s == "hello@example.net" {
				t.Fatalf("a value in the list: %s=%s", k, s)
			}
		}
	}
	// never: an empty date clears it, and the change reaches the file
	if _, err := c.Write("m-var", map[string]any{"scope": "env/prod/general", "key": "PUBLIC_HOST", "expires": ""}); err != nil {
		t.Fatal(err)
	}
	if n := c.Nav()["expired_count"]; n != 0 {
		t.Fatalf("never: %v", n)
	}
	if _, ok, _ := v.Expiry("Environments/prod/General/PUBLIC_HOST"); ok {
		t.Fatal("the vault entry still expires")
	}
	if _, ok, _ := v.Expiry("Connections/GCP"); !ok {
		t.Fatal("the connection entry has no native expiry")
	}
}
