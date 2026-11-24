package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

// Credentials unlock a vault: a master password, a key file, or both (the KeePass composite key, so KeePassXC opens the same file with the same pair).
// The slices belong to the caller; Open and Create read them and the caller wipes them with Wipe.
type Credentials struct {
	Password []byte // may be empty when a key file is given
	KeyFile  string // path of a KeePass key file: XML v2 (with hash), XML v1, raw 32 bytes, 64 hex characters, or any other file (hashed)
}

// Wipe overwrites the password bytes.
func (c *Credentials) Wipe() {
	for i := range c.Password {
		c.Password[i] = 0
	}
}

// build makes the library's credentials. The password is hashed here, so no Go string of it exists.
func (c Credentials) build() (*gokeepasslib.DBCredentials, error) {
	if len(c.Password) == 0 && c.KeyFile == "" {
		return nil, ErrNoCredentials
	}
	cred := &gokeepasslib.DBCredentials{}
	if len(c.Password) > 0 {
		cred.Passphrase = passwordKey(c.Password)
	}
	if c.KeyFile != "" {
		data, err := os.ReadFile(c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrKeyFileUnreadable, pathErr(err))
		}
		key, err := gokeepasslib.ParseKeyData(data)
		wipe(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrKeyFileInvalid, err)
		}
		cred.Key = key
	}
	return cred, nil
}

// passwordKey is the password part of the KDBX composite key, the one place that makes it (Open, Create and SetPassword come here). Not password
// storage: KDBX builds its composite key from SHA-256(password) (the format requires it, KeePassXC does the same), and the slow key derivation
// (Argon2d, 64 MiB, see Create) runs on that composite key. The caller wipes the result.
func passwordKey(pw []byte) []byte {
	h := sha256.Sum256(pw)
	out := append([]byte(nil), h[:]...)
	wipe(h[:])
	return out
}

func wipeCreds(c *gokeepasslib.DBCredentials) {
	if c == nil {
		return
	}
	wipe(c.Passphrase)
	wipe(c.Key)
	wipe(c.Windows)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func pathErr(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

// NewKeyFile writes a new KeePass XML v2 key file (32 random bytes with the 4-byte check hash, the format KeePassXC makes) at path with mode 0600.
// It refuses to overwrite.
func NewKeyFile(path string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	defer wipe(key)
	sum := sha256.Sum256(key)
	hexKey := []byte(hex.EncodeToString(key))
	// the KeePass layout: 4 groups of 8 hex digits, upper case
	up := []byte(fmt.Sprintf("%X", key))
	defer wipe(hexKey)
	defer wipe(up)
	doc := fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n\t<Key>\n\t\t<Data Hash=\"%X\">\n"+
		"\t\t\t%s %s %s %s\n\t\t\t%s %s %s %s\n\t\t</Data>\n\t</Key>\n</KeyFile>\n", sum[:4],
		up[0:8], up[8:16], up[16:24], up[24:32], up[32:40], up[40:48], up[48:56], up[56:64])
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(doc); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
