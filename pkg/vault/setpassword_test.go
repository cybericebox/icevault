package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const newPw = "another-throwaway-2"

// The password of an open vault is replaced and the file re-encrypted: only the new one opens it, the entries and the key derivation settings stay.
func TestSetPasswordReplacesThePassword(t *testing.T) {
	v, p := newVault(t, creds())
	must(t, v.Put(Entry{Group: "G", Title: "T", Password: []byte("secret")}))
	must(t, v.Save())
	before := mustOpen(t, p, creds()).db.Header.FileHeaders.KdfParameters.Iterations
	must(t, v.SetPassword([]byte(newPw)))
	if _, err := Open(p, creds()); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("the old password still opens the vault: %v", err)
	}
	n := mustOpen(t, p, Credentials{Password: []byte(newPw)})
	e, err := n.Get("G/T")
	must(t, err)
	if string(e.Password) != "secret" {
		t.Fatal("an entry changed")
	}
	if got := n.db.Header.FileHeaders.KdfParameters.Iterations; got != before {
		t.Fatalf("the key derivation iterations changed: %d to %d", before, got)
	}
	// the open vault goes on working with the new password: a further save is accepted
	must(t, v.Put(Entry{Group: "G", Title: "T2", Password: []byte("x")}))
	must(t, v.Save())
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}

// The previous copy (<vault>.prev) holds the old password: it is gone after a change, and a failed change leaves it alone.
func TestSetPasswordRemovesThePreviousCopy(t *testing.T) {
	v, p := newVault(t, creds())
	must(t, v.Put(Entry{Group: "G", Title: "T", Password: []byte("x")}))
	must(t, v.Save())
	if _, err := os.Stat(p + ".prev"); err != nil {
		t.Fatalf("no previous copy to start with: %v", err)
	}
	real := writeFile
	writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	_ = v.SetPassword([]byte(newPw))
	writeFile = real
	if _, err := os.Stat(p + ".prev"); err != nil {
		t.Fatal("a failed change removed the previous copy")
	}
	must(t, v.SetPassword([]byte(newPw)))
	if _, err := os.Stat(p + ".prev"); err == nil {
		t.Fatal("the previous copy still opens with the old password")
	}
}

// A key file stays the same: the composite key keeps it, and the old password with it still fails.
func TestSetPasswordKeepsTheKeyFile(t *testing.T) {
	kf := filepath.Join(t.TempDir(), "k.key")
	must(t, NewKeyFile(kf))
	c := Credentials{Password: []byte(pw), KeyFile: kf}
	v, p := newVault(t, c)
	must(t, v.SetPassword([]byte(newPw)))
	if _, err := Open(p, Credentials{Password: []byte(newPw)}); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("without the key file: %v", err)
	}
	mustOpen(t, p, Credentials{Password: []byte(newPw), KeyFile: kf})
	// an empty password is fine when a key file holds the key, and refused when none does
	must(t, v.SetPassword(nil))
	mustOpen(t, p, Credentials{KeyFile: kf})
	w, _ := newVault(t, creds())
	if err := w.SetPassword(nil); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("an empty password with no key file: %v", err)
	}
}

// A failed save leaves the old file, and the open vault keeps the old password (it can be saved again).
func TestSetPasswordFailureLeavesTheOldFile(t *testing.T) {
	v, p := newVault(t, creds())
	old, err := os.ReadFile(p)
	must(t, err)
	real := writeFile
	writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	err = v.SetPassword([]byte(newPw))
	writeFile = real
	if err == nil {
		t.Fatal("the failure was swallowed")
	}
	now, _ := os.ReadFile(p)
	if string(now) != string(old) {
		t.Fatal("the old file changed")
	}
	mustOpen(t, p, creds())
	for _, n := range dirNames(t, filepath.Dir(p)) {
		if n != "v.kdbx" && n != "v.kdbx.lock" {
			t.Fatalf("a stray file is left: %s", n)
		}
	}
	must(t, v.Put(Entry{Group: "G", Title: "T", Password: []byte("x")}))
	must(t, v.Save()) // still the old password
	mustOpen(t, p, creds())
}

// A file that another writer replaced since it was read is not overwritten with a new password.
func TestSetPasswordRefusesAChangedFile(t *testing.T) {
	v, p := newVault(t, creds())
	other := mustOpen(t, p, creds())
	must(t, other.Put(Entry{Group: "G", Title: "T", Password: []byte("x")}))
	must(t, other.Save())
	time.Sleep(10 * time.Millisecond)
	if err := v.SetPassword([]byte(newPw)); !errors.Is(err, ErrChangedOnDisk) {
		t.Fatalf("got %v", err)
	}
	mustOpen(t, p, creds())
}

func TestSetPasswordOnAClosedVault(t *testing.T) {
	v, _ := newVault(t, creds())
	v.Close()
	if err := v.SetPassword([]byte(newPw)); err == nil {
		t.Fatal("a closed vault took a password")
	}
}
