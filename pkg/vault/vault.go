// Package vault reads and writes KeePass KDBX 4.x databases for IceVault, the secrets vault tool. It has no terminal I/O: callers pass credentials in and get data and errors out.
package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tobischo/argon2"
	"github.com/tobischo/gokeepasslib/v3"
)

// Vault is an open database. It is not safe for use from several goroutines.
type Vault struct {
	path    string
	db      *gokeepasslib.Database
	creds   Credentials
	diskSum [32]byte // hash of the file as read: Save refuses when the file is not that any more
	hasDisk bool
	format  Format
	stamp   os.FileInfo // the file as last seen (Open, Save, Changed): a cheap first test of whether another writer replaced it
}

// CreateOptions tune a new vault.
type CreateOptions struct {
	// DecryptionTime is the target time of one key derivation (default 1s, 100ms to 5s). Argon2d iterations are calibrated to it on this machine.
	DecryptionTime time.Duration
	// Name is the database name shown in KeePass clients (default "IceVault").
	Name string
}

const (
	argonMemory      = 64 * 1024 * 1024 // bytes, as KeePassXC
	argonParallelism = 2
)

// Create makes a new KDBX 4.1 vault (Argon2d, AES-256) at path and returns it open. It refuses to overwrite and creates the folder with mode 0700.
func Create(path string, c Credentials, o CreateOptions) (*Vault, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("%s already exists: not overwritten", path)
	}
	cred, err := c.build()
	if err != nil {
		return nil, err
	}
	if o.DecryptionTime == 0 {
		o.DecryptionTime = time.Second
	}
	if o.DecryptionTime < 100*time.Millisecond || o.DecryptionTime > 5*time.Second {
		return nil, errors.New("the decryption time is 100 to 5000 ms")
	}
	if o.Name == "" {
		o.Name = "IceVault"
	}
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion41())
	db.Credentials = cred
	fh := db.Header.FileHeaders
	fh.CipherID = gokeepasslib.CipherAES
	fh.EncryptionIV = randBytes(16)
	fh.KdfParameters.Memory = argonMemory
	fh.KdfParameters.Parallelism = argonParallelism
	fh.KdfParameters.Iterations = calibrate(o.DecryptionTime)
	db.Content.Meta.DatabaseName = o.Name
	db.Content.Meta.Generator = "IceVault"
	db.Content.Meta.RecycleBinEnabled = boolW(true)
	root := gokeepasslib.NewGroup()
	root.Name = "Passwords" // as KeePassXC names the root group; the database name is o.Name
	root.IconID = 49
	db.Content.Root.Groups = []gokeepasslib.Group{root}
	v := &Vault{path: path, db: db, creds: Credentials{}, format: Format{Major: 4, Minor: 1, KDF: "argon2d"}}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := v.Save(); err != nil {
		return nil, err
	}
	return v, nil
}

// calibrate finds the Argon2d iteration count that takes about d for 64 MiB and 2 lanes on this machine.
func calibrate(d time.Duration) uint64 {
	salt := randBytes(32)
	start := time.Now()
	argon2.DKey(salt, salt, 1, argonMemory/1024, argonParallelism, 32)
	one := time.Since(start)
	n := uint64(d / max(one, time.Millisecond))
	return min(max(n, 2), 1000)
}

// Open reads and decrypts the vault. A KDBX 3.x file and an Argon2id file are refused with a message that says what to do in KeePassXC.
func Open(path string, c Credentials) (*Vault, error) {
	cred, err := c.build()
	if err != nil {
		return nil, err
	}
	return openWith(path, cred)
}

// openWith reads and decrypts path with key material the new Vault then owns (Close wipes it).
func openWith(path string, cred *gokeepasslib.DBCredentials) (*Vault, error) {
	stamp, _ := os.Stat(path) // before the read: a file replaced between the two is seen as changed by the next Changed, never missed
	data, err := os.ReadFile(path)
	if err != nil {
		wipeCreds(cred)
		return nil, fmt.Errorf("%w: %w", ErrUnreadable, pathErr(err))
	}
	db, f, err := decode(data, cred)
	if err != nil {
		wipeCreds(cred)
		return nil, err
	}
	return &Vault{path: path, db: db, diskSum: sha256.Sum256(data), hasDisk: true, format: f, stamp: stamp}, nil
}

// sameFile says whether two looks at the file show the same file: the same inode (a save renames a new file into place), size and modification time.
func sameFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// Changed says whether the file on disk is no longer the one this vault read or last saved, for instance because the command line or another window
// saved it. It looks at the file's inode, size and time first and reads and hashes it only when one of them moved (always when full is set). Its own
// saves never count: Save records what it wrote. It reads no key material and decrypts nothing.
func (v *Vault) Changed(full bool) (bool, error) {
	if v.db == nil {
		return false, errors.New("the vault is closed")
	}
	st, err := os.Stat(v.path)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrUnreadable, pathErr(err))
	}
	if !full && sameFile(v.stamp, st) {
		return false, nil
	}
	data, err := os.ReadFile(v.path)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrUnreadable, pathErr(err))
	}
	if v.hasDisk && sha256.Sum256(data) == v.diskSum {
		v.stamp = st // the same bytes (touched, or copied back): nothing to read again
		return false, nil
	}
	return true, nil
}

// SkipChange makes Changed (not full) quiet about the file as it was at st, a look taken before a read of it that failed (another writer changed the
// password, a damaged file): the window does not derive the key again every few seconds for a file it cannot open. A later save by anyone is a change
// again; Save still refuses to write over that file.
func (v *Vault) SkipChange(st os.FileInfo) {
	if st != nil {
		v.stamp = st
	}
}

// Key is a copy of the key material of an open vault (the hashed password and the key file's key, never the password itself): what Reopen needs to read
// the file again without asking for the password. Wipe it after use.
type Key struct{ c *gokeepasslib.DBCredentials }

func copyCreds(c *gokeepasslib.DBCredentials) *gokeepasslib.DBCredentials {
	if c == nil {
		return nil
	}
	dup := func(b []byte) []byte {
		if b == nil {
			return nil
		}
		return append([]byte(nil), b...)
	}
	return &gokeepasslib.DBCredentials{Passphrase: dup(c.Passphrase), Key: dup(c.Key), Windows: dup(c.Windows)}
}

// Key copies the key material of the open vault; nil when it is closed.
func (v *Vault) Key() *Key {
	if v.db == nil {
		return nil
	}
	return &Key{c: copyCreds(v.db.Credentials)}
}

// Wipe overwrites the copy.
func (k *Key) Wipe() {
	if k != nil {
		wipeCreds(k.c)
	}
}

// Reopen reads the vault file at path again with k, as another process may have saved it, and returns it as a new open Vault with its own copy of the
// key (k stays the caller's to wipe). A wrong key (the password was changed elsewhere) is ErrBadCredentials.
func Reopen(path string, k *Key) (*Vault, error) {
	if k == nil || k.c == nil {
		return nil, ErrNoCredentials
	}
	return openWith(path, copyCreds(k.c))
}

func decode(data []byte, cred *gokeepasslib.DBCredentials) (*gokeepasslib.Database, Format, error) {
	f, err := PeekFormat(data)
	if err != nil {
		return nil, f, err
	}
	db := gokeepasslib.NewDatabase()
	db.Credentials = cred
	if err := gokeepasslib.NewDecoder(bytes.NewReader(data)).Decode(db); err != nil {
		if errors.Is(err, gokeepasslib.ErrCorruptedDatabase) {
			return nil, f, err
		}
		return nil, f, ErrBadCredentials
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, f, ErrBadCredentials
	}
	return db, f, nil
}

// Path is the vault file.
func (v *Vault) Path() string { return v.path }

// Format tells the KDBX version and the key derivation function of the file as it was read (or made).
func (v *Vault) Format() Format { return v.format }

// Close forgets the database and overwrites the key material it can reach. Go cannot promise more: the garbage collector may have copied it.
func (v *Vault) Close() {
	if v.db == nil {
		return
	}
	wipeCreds(v.db.Credentials)
	v.db = nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("no random source: " + err.Error())
	}
	return b
}

// rotate gives the file fresh seeds before every save, as KeePass does, so no two saved versions share a keystream.
func (v *Vault) rotate() {
	fh := v.db.Header.FileHeaders
	fh.MasterSeed = randBytes(32)
	fh.EncryptionIV = randBytes(len(fh.EncryptionIV))
	copy(fh.KdfParameters.Salt[:], randBytes(32))
	v.db.Content.InnerHeader.InnerRandomStreamKey = randBytes(len(v.db.Content.InnerHeader.InnerRandomStreamKey))
}

func (v *Vault) encode() ([]byte, error) {
	v.rotate()
	if err := v.db.LockProtectedEntries(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err := gokeepasslib.NewEncoder(&buf).Encode(v.db)
	if uerr := v.db.UnlockProtectedEntries(); err == nil {
		err = uerr
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Save writes the vault atomically: a lock file against a second writer, a temp file in the same folder, fsync, a re-open that must match what is in memory,
// one previous copy (<vault>.prev), then a rename. A failure leaves the old file as it was.
func (v *Vault) Save() error {
	if v.db == nil {
		return errors.New("the vault is closed")
	}
	// A vault that is a symbolic link is written THROUGH the link: the temp file, the previous copy and the rename all work on the real file, so the link
	// stays a link and the real file is the one that changes (a rename onto the link itself would replace the link and leave the real file stale).
	path := v.path
	if real, err := filepath.EvalSymlinks(v.path); err == nil {
		path = real
	}
	unlock, err := lockFile(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	var old []byte
	if v.hasDisk {
		old, err = os.ReadFile(path)
		if err != nil || sha256.Sum256(old) != v.diskSum {
			return ErrChangedOnDisk
		}
	} else if _, err := os.Lstat(path); err == nil {
		return ErrChangedOnDisk
	}
	want := fingerprint(v.db)
	out, err := v.encode()
	if err != nil {
		return fmt.Errorf("the vault could not be encoded: %w", err)
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(randBytes(4)))
	if err := writeFile(tmp, out, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	cleanup := func() { _ = os.Remove(tmp) }
	// verify: the file as it is on DISK (read back, not the buffer that was written) must be what was written, open with the same credentials and hold
	// what is in memory
	written, err := os.ReadFile(tmp)
	if err != nil || !bytes.Equal(written, out) {
		cleanup()
		return errors.New("the written vault did not verify: the old file is untouched")
	}
	vdb, _, err := decode(written, v.db.Credentials)
	if err != nil || fingerprint(vdb) != want {
		cleanup()
		return errors.New("the written vault did not verify: the old file is untouched")
	}
	if old != nil {
		prev := path + ".prev"
		ptmp := prev + ".tmp"
		if err := writeFile(ptmp, old, 0o600); err != nil {
			cleanup()
			_ = os.Remove(ptmp)
			return err
		}
		if err := os.Rename(ptmp, prev); err != nil {
			cleanup()
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return fmt.Errorf("the vault could not be replaced: %w", pathErr(err))
	}
	_ = syncDir(dir)
	v.diskSum, v.hasDisk = sha256.Sum256(out), true
	v.stamp, _ = os.Stat(path) // still under the lock: no other writer can have replaced it since the rename
	return nil
}

// writeFile is writeSynced; a variable so a test can make the disk misbehave.
var writeFile = writeSynced

func writeSynced(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("a file cannot be written: %w", pathErr(err))
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
