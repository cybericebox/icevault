package vault

import (
	"path/filepath"
	"testing"
	"time"
)

func TestExpiryIsTheNativeKeePassOne(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.kdbx")
	cred := Credentials{Password: []byte("pw-throwaway-1")}
	v, err := Create(p, cred, CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(Entry{Group: "G", Title: "TOKEN", Password: []byte("s3cret")}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := v.Expiry("G/TOKEN"); ok {
		t.Fatal("a new entry expires")
	}
	day := time.Date(2030, 1, 12, 5, 0, 0, 0, time.UTC)
	if err := v.SetExpiry("G/TOKEN", day); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	v.Close()
	v, err = Open(p, cred)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	got, ok, err := v.Expiry("G/TOKEN")
	if err != nil || !ok || !got.Equal(ExpiryEnd(day)) {
		t.Fatalf("expiry %v %v %v", got, ok, err)
	}
	infos, _ := v.Entries("G")
	if len(infos) != 1 || !infos[0].Expires.Equal(ExpiryEnd(day)) {
		t.Fatalf("EntryInfo.Expires: %+v", infos)
	}
	if n := infos[0].History; n != 1 {
		t.Fatalf("history after a change of the expiry: %d", n)
	}
	if err := v.SetExpiry("G/TOKEN", day); err != nil {
		t.Fatal(err)
	}
	if infos, _ = v.Entries("G"); infos[0].History != 1 {
		t.Fatal("the same date wrote a version")
	}
	if err := v.SetExpiry("G/TOKEN", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := v.Expiry("G/TOKEN"); ok {
		t.Fatal("never did not clear the expiry")
	}
	if err := v.SetExpiry("G/NOPE", day); err == nil {
		t.Fatal("a missing entry")
	}
}
