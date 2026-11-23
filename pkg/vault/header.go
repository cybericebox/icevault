package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Errors a caller can test with errors.Is.
var (
	// ErrNotKDBX means the file is not a KeePass database at all.
	ErrNotKDBX = errors.New("not a KeePass (KDBX) database")
	// ErrKDBX3 means a KDBX 3.x database. It is refused, never converted: the library this tool uses corrupts attachments of 3.1 files.
	ErrKDBX3 = errors.New("this vault is KDBX 3.x, an older KeePass format that this program does not write: open it in KeePassXC and " +
		"choose Database > Database Settings > Security > Encryption, set the key derivation function to Argon2d (this upgrades the file to KDBX 4), save, then try again")
	// ErrUnsupportedKDF means a key derivation function that this program cannot compute (Argon2id).
	ErrUnsupportedKDF = errors.New("this vault uses a key derivation function that this program does not support (Argon2id): " +
		"in KeePassXC choose Database > Database Settings > Security > Encryption and set the key derivation function to Argon2d, save, then try again")
	// ErrBadCredentials means the password or the key file is wrong (or the file is damaged: the format cannot tell them apart).
	ErrBadCredentials = errors.New("wrong password or key file, or the vault file is damaged")
	// ErrChangedOnDisk means the vault file changed after it was opened: saving would overwrite someone else's change.
	ErrChangedOnDisk = errors.New("the vault file changed on disk since it was opened: open it again, nothing was written")
	// ErrUnreadable means the vault file could not be read (it is missing, or not readable by this user); the cause is wrapped too.
	ErrUnreadable = errors.New("the vault cannot be read")
	// ErrKeyFileUnreadable means the key file named in the credentials could not be read; the cause is wrapped too.
	ErrKeyFileUnreadable = errors.New("the key file cannot be read")
	// ErrKeyFileInvalid means the key file is not a usable KeePass key file.
	ErrKeyFileInvalid = errors.New("the key file is not a valid KeePass key file")
	// ErrNoCredentials means neither a password nor a key file was given.
	ErrNoCredentials = errors.New("a password or a key file is needed")
	// ErrLocked means another process is writing the vault.
	ErrLocked = errors.New("another process is writing this vault: try again in a moment")
)

const (
	sig1 = 0x9AA2D903
	sig2 = 0xB54BFB67

	fieldEnd           = 0
	fieldKdfParameters = 11
	maxHeaderField     = 1 << 20
)

var (
	kdfArgon2d  = []byte{0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c}
	kdfArgon2id = []byte{0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6}
	kdfAES      = []byte{0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea}
)

// Format is what the plain part of a KDBX header says, read before any key is derived.
type Format struct {
	Major, Minor uint16
	KDF          string // "argon2d", "aes" or "argon2id"
}

// PeekFormat reads the version and the key derivation function from the start of a KDBX file. It computes nothing secret.
func PeekFormat(data []byte) (Format, error) {
	var f Format
	if len(data) < 12 || binary.LittleEndian.Uint32(data[0:4]) != sig1 || binary.LittleEndian.Uint32(data[4:8]) != sig2 {
		return f, ErrNotKDBX
	}
	f.Minor = binary.LittleEndian.Uint16(data[8:10])
	f.Major = binary.LittleEndian.Uint16(data[10:12])
	if f.Major < 4 {
		return f, ErrKDBX3
	}
	if f.Major > 4 {
		return f, fmt.Errorf("KDBX %d.%d is newer than this program understands", f.Major, f.Minor)
	}
	pos := 12
	for {
		if pos+5 > len(data) {
			return f, errors.New("the vault header is truncated")
		}
		id := data[pos]
		n := int(binary.LittleEndian.Uint32(data[pos+1 : pos+5]))
		pos += 5
		if n < 0 || n > maxHeaderField || pos+n > len(data) {
			return f, errors.New("the vault header is damaged")
		}
		field := data[pos : pos+n]
		pos += n
		if id == fieldKdfParameters {
			uuid, err := variantUUID(field)
			if err != nil {
				return f, err
			}
			switch {
			case bytes.Equal(uuid, kdfArgon2d):
				f.KDF = "argon2d"
			case bytes.Equal(uuid, kdfArgon2id):
				f.KDF = "argon2id"
				return f, ErrUnsupportedKDF
			case bytes.Equal(uuid, kdfAES):
				f.KDF = "aes"
			default:
				return f, errors.New("this vault uses an unknown key derivation function")
			}
		}
		if id == fieldEnd {
			break
		}
	}
	if f.KDF == "" {
		return f, errors.New("the vault header has no key derivation parameters")
	}
	return f, nil
}

// variantUUID finds "$UUID" in a KeePass variant dictionary.
func variantUUID(d []byte) ([]byte, error) {
	if len(d) < 3 {
		return nil, errors.New("the key derivation parameters are damaged")
	}
	pos := 2 // the dictionary version
	for pos < len(d) {
		t := d[pos]
		pos++
		if t == 0 {
			break
		}
		if pos+4 > len(d) {
			break
		}
		kl := int(binary.LittleEndian.Uint32(d[pos : pos+4]))
		pos += 4
		if kl < 0 || pos+kl+4 > len(d) {
			break
		}
		key := string(d[pos : pos+kl])
		pos += kl
		vl := int(binary.LittleEndian.Uint32(d[pos : pos+4]))
		pos += 4
		if vl < 0 || pos+vl > len(d) {
			break
		}
		if key == "$UUID" && vl == 16 {
			return d[pos : pos+vl], nil
		}
		pos += vl
	}
	return nil, errors.New("the key derivation parameters are damaged")
}
