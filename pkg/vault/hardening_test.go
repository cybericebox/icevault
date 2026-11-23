package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// A vault that is a symbolic link must stay a link and the real file must be the one that changes.
func TestSaveThroughSymlink(t *testing.T) {
	v, p := newVault(t, creds())
	v.Close()
	realDir := filepath.Join(t.TempDir(), "real")
	must(t, os.MkdirAll(realDir, 0o700))
	realFile := filepath.Join(realDir, "real.kdbx")
	must(t, os.Rename(p, realFile))
	link := filepath.Join(filepath.Dir(p), "link.kdbx")
	must(t, os.Symlink(realFile, link))
	v = mustOpen(t, link, creds())
	must(t, v.Put(Entry{Group: "G", Title: "T", Password: []byte("x")}))
	must(t, v.Save())
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced by a file: %v %v", st, err)
	}
	if _, err := mustOpen(t, realFile, creds()).Get("G/T"); err != nil {
		t.Fatalf("the real file was not written: %v", err)
	}
	if _, err := os.Stat(realFile + ".prev"); err != nil {
		t.Fatal("the previous copy is not beside the real file")
	}
	// a second save through the same link still works (the hash of the open file is the real file's)
	must(t, v.Put(Entry{Group: "G", Title: "T2", Password: []byte("y")}))
	must(t, v.Save())
}

// The check after the write must read the FILE back: a disk that stores other bytes than it was given must be caught, and the old file stays.
func TestSaveCatchesCorruptionOnDisk(t *testing.T) {
	v, p := newVault(t, creds())
	must(t, v.Put(Entry{Group: "G", Title: "T", Password: []byte("x")}))
	must(t, v.Save())
	before, _ := os.ReadFile(p)
	orig := writeFile
	defer func() { writeFile = orig }()
	writeFile = func(path string, data []byte, mode os.FileMode) error {
		bad := bytes.Clone(data)
		bad[len(bad)/2] ^= 0xff // the disk flips one byte; the buffer in memory is still fine
		return orig(path, bad, mode)
	}
	must(t, v.Put(Entry{Group: "G", Title: "T2", Password: []byte("y")}))
	if err := v.Save(); err == nil || !strings.Contains(err.Error(), "did not verify") {
		t.Fatalf("a corrupt write was accepted: %v", err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("the old file changed")
	}
	for _, n := range dirNames(t, filepath.Dir(p)) {
		if strings.Contains(n, ".tmp") {
			t.Fatalf("a temp file is left: %s", n)
		}
	}
}

// A failure while the previous copy is written leaves the vault file and no temp files.
func TestSaveFailureWritingPrevLeavesVault(t *testing.T) {
	v, p := newVault(t, creds())
	must(t, v.Put(Entry{Group: "G", Title: "T", Password: []byte("x")}))
	must(t, v.Save())
	before, _ := os.ReadFile(p)
	orig := writeFile
	defer func() { writeFile = orig }()
	writeFile = func(path string, data []byte, mode os.FileMode) error {
		if strings.HasSuffix(path, ".prev.tmp") {
			return errors.New("disk full")
		}
		return orig(path, data, mode)
	}
	must(t, v.Put(Entry{Group: "G", Title: "T2", Password: []byte("y")}))
	if err := v.Save(); err == nil {
		t.Fatal("no error")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("the vault changed")
	}
	for _, n := range dirNames(t, filepath.Dir(p)) {
		if strings.Contains(n, ".tmp") {
			t.Fatalf("a temp file is left: %s", n)
		}
	}
}

// A second writer is refused while the lock is held; the lock is free again after the first save.
func TestSaveLockedByAnotherWriter(t *testing.T) {
	v, p := newVault(t, creds())
	unlock, err := lockFile(p + ".lock")
	must(t, err)
	if err := v.Save(); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	unlock()
	must(t, v.Save())
	st, err := os.Stat(p + ".lock")
	must(t, err)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode %v", st.Mode())
	}
}

// The file changed after it was opened: refuse, write nothing.
func TestSaveRefusesWhenChangedOnDisk(t *testing.T) {
	v, p := newVault(t, creds())
	v.Close()
	a := mustOpen(t, p, creds())
	b := mustOpen(t, p, creds())
	must(t, a.Put(Entry{Group: "G", Title: "A", Password: []byte("1")}))
	must(t, a.Save())
	must(t, b.Put(Entry{Group: "G", Title: "B", Password: []byte("2")}))
	if err := b.Save(); !errors.Is(err, ErrChangedOnDisk) {
		t.Fatalf("want ErrChangedOnDisk, got %v", err)
	}
	if _, err := mustOpen(t, p, creds()).Get("G/A"); err != nil {
		t.Fatal("A lost")
	}
}

// An attachment whose bytes are valid base64 (a key of 64 hex characters, the base64 of 32 bytes) must come back byte for byte: the library decoded it.
func TestAttachmentThatLooksLikeBase64RoundTrips(t *testing.T) {
	v, p := newVault(t, creds())
	vals := map[string][]byte{
		"hex64":  []byte(strings.Repeat("0123456789abcdef", 4)),
		"b64key": []byte("q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA="),
		"mmmm":   bytes.Repeat([]byte("M"), 32),
		"short":  []byte("abcd"),
	}
	must(t, v.Put(Entry{Group: "G", Title: "T", Password: []byte("x")}))
	for name, data := range vals {
		must(t, v.SetAttachment("G/T", name, data))
	}
	check := func(v *Vault, when string) {
		for name, data := range vals {
			got, err := v.Attachment("G/T", name)
			if err != nil || !bytes.Equal(got, data) {
				t.Errorf("%s: %s came back as %d bytes, want %d", when, name, len(got), len(data))
			}
		}
	}
	check(v, "in memory")
	must(t, v.Save())
	check(mustOpen(t, p, creds()), "after reopen")
}
