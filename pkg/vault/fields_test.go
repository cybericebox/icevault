package vault

import (
	"errors"
	"testing"
)

func TestFieldsMetaUUIDRecycle(t *testing.T) {
	v, p := newVault(t, creds())
	if err := v.Put(Entry{Group: "A/B", Title: "e", Password: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := v.SetFields("A/B/e", map[string]Field{"IceVault.Kind": {Value: "aws"}, "token": {Value: "t-1", Protected: true}}); err != nil {
		t.Fatal(err)
	}
	if err := v.SetFields("A/B/e", map[string]Field{"Title": {Value: "x"}}); !errors.Is(err, ErrStandardField) {
		t.Fatalf("standard field: %v", err)
	}
	u, err := v.UUIDOf("A/B/e")
	if err != nil || len(u) != 32 {
		t.Fatalf("uuid %q %v", u, err)
	}
	v.SetMetaValue("IceVault.Format", "1")
	if err := v.Put(Entry{Group: "Old/x", Title: "f"}); err != nil {
		t.Fatal(err)
	}
	if err := v.RecycleGroup("Old"); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	v.Close()
	v = mustOpen(t, p, creds())
	defer v.Close()
	f, err := v.Fields("A/B/e")
	if err != nil || f["IceVault.Kind"].Value != "aws" || f["token"].Value != "t-1" || !f["token"].Protected || len(f) != 2 {
		t.Fatalf("fields %v %v", f, err)
	}
	if u2, _ := v.UUIDOf("A/B/e"); u2 != u {
		t.Fatal("uuid changed on save")
	}
	if v.MetaValue("IceVault.Format") != "1" {
		t.Fatal("meta value lost")
	}
	if v.HasGroup("Old") || !v.HasGroup(RecycleBinName+"/Old/x") {
		t.Fatal("group not in the recycle bin")
	}
	// removing a field, and a change that alters nothing
	if err := v.SetFields("A/B/e", map[string]Field{"IceVault.Kind": {}}); err != nil {
		t.Fatal(err)
	}
	if f, _ := v.Fields("A/B/e"); len(f) != 2 || f["IceVault.Kind"].Value != "" {
		t.Fatalf("an empty field is a field: %v", f)
	}
	if err := v.RemoveField("A/B/e", "IceVault.Kind"); err != nil {
		t.Fatal(err)
	}
	if f, _ := v.Fields("A/B/e"); len(f) != 1 {
		t.Fatalf("not removed: %v", f)
	}
	v.SetMetaValue("IceVault.Format", "")
	if v.MetaValue("IceVault.Format") != "" {
		t.Fatal("meta value not removed")
	}
}
