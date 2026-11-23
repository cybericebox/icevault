package vault

import (
	"errors"
	"os"
	"testing"
	"time"
)

// Another writer (the command line, a second window) saves the file: Changed notices it, the vault's own saves and a mere touch do not count, and Reopen
// reads the new file with the key already derived, without the password.
func TestChangedOnDiskAndReopen(t *testing.T) {
	v, p := newVault(t, creds())
	for _, full := range []bool{false, true} {
		if ch, err := v.Changed(full); err != nil || ch {
			t.Fatalf("a fresh vault changed (full=%v): %v %v", full, ch, err)
		}
	}
	must(t, v.Put(Entry{Group: "IceVault/prod", Title: "OWN", Password: []byte("own-value")}))
	must(t, v.Save())
	if ch, err := v.Changed(false); err != nil || ch {
		t.Fatalf("its own save counted as a change: %v %v", ch, err)
	}
	later := time.Now().Add(time.Hour)
	must(t, os.Chtimes(p, later, later))
	if ch, err := v.Changed(false); err != nil || ch {
		t.Fatalf("a touched file with the same bytes counted as a change: %v %v", ch, err)
	}

	other := mustOpen(t, p, creds())
	must(t, other.Put(Entry{Group: "IceVault/prod", Title: "THEIRS", Password: []byte("their-value")}))
	must(t, other.Save())
	other.Close()
	if ch, err := v.Changed(false); err != nil || !ch {
		t.Fatalf("a save by another writer was not noticed: %v %v", ch, err)
	}
	if err := v.Save(); !errors.Is(err, ErrChangedOnDisk) {
		t.Fatalf("the stale vault saved over the other writer: %v", err)
	}

	k := v.Key()
	nv, err := Reopen(p, k)
	k.Wipe()
	must(t, err)
	v.Close() // the reopened vault owns its own copy of the key: closing the old one does not break it
	e, err := nv.Get("IceVault/prod/THEIRS")
	if err != nil || string(e.Password) != "their-value" {
		t.Fatalf("the reopened vault does not see the other writer's entry: %v", err)
	}
	if _, err := nv.Get("IceVault/prod/OWN"); err != nil {
		t.Fatalf("the reopened vault lost the earlier entry: %v", err)
	}
	if ch, err := nv.Changed(false); err != nil || ch {
		t.Fatalf("a reopened vault is already changed: %v %v", ch, err)
	}
	must(t, nv.Put(Entry{Group: "IceVault/prod", Title: "AFTER", Password: []byte("x")}))
	must(t, nv.Save())
	if ch, err := nv.Changed(true); err != nil || ch {
		t.Fatalf("its own save counted as a change (full): %v %v", ch, err)
	}
	nv.Close()

	if _, err := Reopen(p, nil); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("reopen without a key: %v", err)
	}
	if _, err := nv.Changed(false); err == nil {
		t.Fatal("a closed vault answered Changed")
	}
}
