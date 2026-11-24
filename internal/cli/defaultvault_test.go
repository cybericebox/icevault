package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The vault file the description names stays inside the project folder once symbolic links are resolved.
func TestDefaultVaultPathStaysInsideTheProjectFolder(t *testing.T) {
	h := newHarness(t)
	want, err := DefaultVaultPath(h.root)
	if err != nil {
		t.Fatal(err)
	}
	// a link inside the folder that leads elsewhere inside it is fine
	plain := filepath.Join(h.root, "plain")
	inside := filepath.Join(h.root, "real-plain")
	if err := os.Rename(plain, inside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inside, plain); err != nil {
		t.Skip("no symbolic links here")
	}
	if got, err := DefaultVaultPath(h.root); err != nil || got != want {
		t.Fatalf("a link that stays inside: %q %v, want %q", got, err, want)
	}
	// a link that leaves the folder is refused, and nothing is made through it
	outside := t.TempDir()
	if err := os.Remove(plain); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, plain); err != nil {
		t.Fatal(err)
	}
	if got, err := DefaultVaultPath(h.root); !errors.Is(err, ErrOutsideRoot) || got != "" {
		t.Fatalf("a link out of the folder: %q %v", got, err)
	}
	// the same when the folder behind the link is not made yet (the parent that exists is the link's target)
	if err := os.Remove(plain); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "not", "yet"), plain); err != nil {
		t.Fatal(err)
	}
	if _, err := DefaultVaultPath(h.root); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("a dangling link out of the folder: %v", err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("something was made outside the project folder")
	}
}
