package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
)

const pw = "pw-throwaway-1"

func creds() Credentials { return Credentials{Password: []byte(pw)} }

func newVault(t *testing.T, c Credentials) (*Vault, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sub", "v.kdbx")
	v, err := Create(p, c, CreateOptions{DecryptionTime: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return v, p
}

func mustOpen(t *testing.T, p string, c Credentials) *Vault {
	t.Helper()
	v, err := Open(p, c)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCreateOpenRoundTrip(t *testing.T) {
	v, p := newVault(t, creds())
	f := v.Format()
	if f.Major != 4 || f.KDF != "argon2d" {
		t.Fatalf("format %+v", f)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	must(t, v.Put(Entry{Group: "IceVault/prod/gcp", Title: "API_KEY", Notes: "managed-by=owner\n\u0432\u0435\u043b\u0438\u043a\u0438\u0439 \u0441\u0435\u043a\u0440\u0435\u0442", Password: []byte("s3cr\u00e9t-\u0443\u043a\u0440")}))
	must(t, v.Put(Entry{Group: "IceVault/prod/aws", Title: "EMPTY"}))
	must(t, v.MakeGroup("IceVault/empty/deep"))
	must(t, v.SetAttachment("IceVault/prod/gcp/API_KEY", "content", bytes.Repeat([]byte{0, 1, 2, 255}, 50000)))
	must(t, v.Save())
	v2 := mustOpen(t, p, creds())
	e, err := v2.Get("IceVault/prod/gcp/API_KEY")
	must(t, err)
	if string(e.Password) != "s3cr\u00e9t-\u0443\u043a\u0440" || !strings.Contains(e.Notes, "\u0432\u0435\u043b\u0438\u043a\u0438\u0439") {
		t.Fatal("entry changed")
	}
	a, err := v2.Attachment("IceVault/prod/gcp/API_KEY", "content")
	must(t, err)
	if !bytes.Equal(a, bytes.Repeat([]byte{0, 1, 2, 255}, 50000)) {
		t.Fatal("attachment changed")
	}
	if g, _ := v2.Groups("IceVault/empty"); len(g) != 1 || g[0] != "deep" {
		t.Fatalf("empty group lost: %v", g)
	}
	if _, err := os.Stat(p + ".lock"); err != nil {
		t.Fatal("lock file")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestWrongPasswordAndKeyFile(t *testing.T) {
	_, p := newVault(t, creds())
	if _, err := Open(p, Credentials{Password: []byte("nope")}); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("got %v", err)
	}
	kf := filepath.Join(t.TempDir(), "k.keyx")
	must(t, NewKeyFile(kf))
	if _, err := Open(p, Credentials{Password: []byte(pw), KeyFile: kf}); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("an unneeded key file must not open it: %v", err)
	}
	if err := NewKeyFile(kf); err == nil {
		t.Fatal("overwrote a key file")
	}
}

func TestKeyFileFormats(t *testing.T) {
	dir := t.TempDir()
	xmlKey := filepath.Join(dir, "x.keyx")
	must(t, NewKeyFile(xmlKey))
	raw := filepath.Join(dir, "raw.key")
	must(t, os.WriteFile(raw, bytes.Repeat([]byte{7}, 32), 0o600))
	hexf := filepath.Join(dir, "hex.key")
	must(t, os.WriteFile(hexf, []byte(strings.Repeat("0a", 32)), 0o600))
	other := filepath.Join(dir, "other.txt")
	must(t, os.WriteFile(other, []byte("any file content"), 0o600))
	for name, kf := range map[string]string{"xml2": xmlKey, "raw32": raw, "hex64": hexf, "any": other} {
		for _, withPw := range []bool{true, false} {
			c := Credentials{KeyFile: kf}
			if withPw {
				c.Password = []byte(pw)
			}
			p := filepath.Join(t.TempDir(), "v.kdbx")
			v, err := Create(p, c, CreateOptions{DecryptionTime: 100 * time.Millisecond})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			must(t, v.Put(Entry{Group: "g", Title: "e", Password: []byte("x")}))
			must(t, v.Save())
			if _, err := Open(p, c); err != nil {
				t.Fatalf("%s pw=%v: %v", name, withPw, err)
			}
			if withPw {
				if _, err := Open(p, Credentials{Password: []byte(pw)}); !errors.Is(err, ErrBadCredentials) {
					t.Fatalf("%s: opened without its key file", name)
				}
			}
		}
	}
	if _, err := Create(filepath.Join(dir, "n.kdbx"), Credentials{Password: []byte(pw), KeyFile: filepath.Join(dir, "missing")}, CreateOptions{}); err == nil {
		t.Fatal("missing key file accepted")
	}
}

// header builds the start of a KDBX 4 file with one KDF parameters field, enough for PeekFormat.
func header(major uint16, kdf []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, []uint32{sig1, sig2})
	_ = binary.Write(&b, binary.LittleEndian, []uint16{1, major})
	var d bytes.Buffer
	_ = binary.Write(&d, binary.LittleEndian, uint16(0x100))
	d.WriteByte(0x42)
	_ = binary.Write(&d, binary.LittleEndian, uint32(5))
	d.WriteString("$UUID")
	_ = binary.Write(&d, binary.LittleEndian, uint32(16))
	d.Write(kdf)
	d.WriteByte(0)
	b.WriteByte(11)
	_ = binary.Write(&b, binary.LittleEndian, uint32(d.Len()))
	b.Write(d.Bytes())
	b.WriteByte(0)
	_ = binary.Write(&b, binary.LittleEndian, uint32(4))
	b.Write([]byte{13, 10, 13, 10})
	return b.Bytes()
}

func TestPeekFormat(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		kdf  string
		err  error
	}{
		{"argon2d", header(4, kdfArgon2d), "argon2d", nil},
		{"aes", header(4, kdfAES), "aes", nil},
		{"argon2id", header(4, kdfArgon2id), "argon2id", ErrUnsupportedKDF},
		{"kdbx3", header(3, kdfAES), "", ErrKDBX3},
		{"garbage", []byte("not a database at all"), "", ErrNotKDBX},
		{"empty", nil, "", ErrNotKDBX},
	}
	for _, c := range cases {
		f, err := PeekFormat(c.data)
		if !errors.Is(err, c.err) || f.KDF != c.kdf {
			t.Errorf("%s: %+v %v", c.name, f, err)
		}
	}
	if _, err := PeekFormat(header(4, kdfAES)[:30]); err == nil {
		t.Error("truncated header accepted")
	}
	p := filepath.Join(t.TempDir(), "id.kdbx")
	must(t, os.WriteFile(p, header(4, kdfArgon2id), 0o600))
	if _, err := Open(p, creds()); !errors.Is(err, ErrUnsupportedKDF) {
		t.Fatalf("got %v", err)
	}
	for _, msg := range []string{ErrKDBX3.Error(), ErrUnsupportedKDF.Error()} {
		if !strings.Contains(msg, "KeePassXC") || !strings.Contains(msg, "Argon2d") {
			t.Errorf("message does not say how to upgrade: %s", msg)
		}
	}
}

func TestSaveSafety(t *testing.T) {
	v, p := newVault(t, creds())
	must(t, v.Put(Entry{Group: "g", Title: "a", Password: []byte("1")}))
	must(t, v.Save())
	first, _ := os.ReadFile(p)
	// a second opener changes the file; the first must refuse to overwrite it
	other := mustOpen(t, p, creds())
	must(t, other.Put(Entry{Group: "g", Title: "b", Password: []byte("2")}))
	must(t, other.Save())
	must(t, v.Put(Entry{Group: "g", Title: "c", Password: []byte("3")}))
	if err := v.Save(); !errors.Is(err, ErrChangedOnDisk) {
		t.Fatalf("got %v", err)
	}
	after := mustOpen(t, p, creds())
	if _, err := after.Get("g/b"); err != nil {
		t.Fatal("the other writer's change was lost")
	}
	if _, err := after.Get("g/c"); err == nil {
		t.Fatal("a refused save wrote")
	}
	prev, err := os.ReadFile(p + ".prev")
	must(t, err)
	if bytes.Equal(prev, first) == false {
		// .prev is the file before the LAST save: it must open and hold a but not b
		pv := mustOpen(t, p+".prev", creds())
		if _, err := pv.Get("g/b"); err == nil {
			t.Fatal("prev holds the new entry")
		}
	}
	// a held lock stops a writer
	unlock, err := lockFile(p + ".lock")
	must(t, err)
	if err := after.Save(); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v", err)
	}
	unlock()
	must(t, after.Save())
	entries, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("temp file left: %s", e.Name())
		}
	}
}

func TestEditHistoryRemoveMove(t *testing.T) {
	v, p := newVault(t, creds())
	must(t, v.Put(Entry{Group: "a/b", Title: "K", Password: []byte("v1")}))
	must(t, v.Put(Entry{Group: "a/b", Title: "K", Password: []byte("v1")})) // no change: no history
	must(t, v.Put(Entry{Group: "a/b", Title: "K", Password: []byte("v2"), Notes: "n"}))
	must(t, v.Put(Entry{Group: "a/b", Title: "K", Password: []byte("v3"), Notes: "n"}))
	es, _ := v.Entries("a/b")
	if es[0].History != 2 {
		t.Fatalf("history %d", es[0].History)
	}
	must(t, v.Move("a/b/K", "a/c/K2"))
	must(t, v.Move("a/c", "a/d"))
	if _, err := v.Get("a/d/K2"); err != nil {
		t.Fatal(err)
	}
	if err := v.Move("a", "a/d/inside"); err == nil {
		t.Fatal("moved a group into itself")
	}
	must(t, v.Remove("a/d/K2"))
	if _, err := v.Get("a/d/K2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("not removed")
	}
	bin, err := v.Entries(RecycleBinName)
	must(t, err)
	if len(bin) != 1 || bin[0].History != 2 {
		t.Fatalf("bin %+v", bin)
	}
	must(t, v.Save())
	v2 := mustOpen(t, p, creds())
	bin, _ = v2.Entries(RecycleBinName)
	if len(bin) != 1 {
		t.Fatal("recycle bin lost")
	}
	must(t, v2.Remove(RecycleBinName+"/K2"))
	if bin, _ = v2.Entries(RecycleBinName); len(bin) != 0 {
		t.Fatal("not removed for good")
	}
	must(t, v2.Save())
	for _, bad := range []string{"", "x/y"} {
		if err := v2.Put(Entry{Group: "g", Title: bad}); err == nil {
			t.Errorf("title %q accepted", bad)
		}
	}
}

// Everything this program does not model must survive a save: custom fields (protected and plain), tags, custom data, icons, times, UUIDs.
func TestUnknownDataSurvives(t *testing.T) {
	v, p := newVault(t, creds())
	must(t, v.Put(Entry{Group: "g", Title: "E", Password: []byte("p")}))
	g, _ := v.group("g")
	e := &g.Entries[0]
	e.Values = append(e.Values,
		gokeepasslib.ValueData{Key: "CustomProt", Value: gokeepasslib.V{Content: "cp-value", Protected: boolW(true)}},
		gokeepasslib.ValueData{Key: "CustomPlain", Value: gokeepasslib.V{Content: "pl-value"}})
	e.Tags = "t1;t2"
	e.IconID = 17
	e.CustomData = []gokeepasslib.CustomData{{Key: "k", Value: "v"}}
	uuid := e.UUID
	must(t, v.Save())
	for i := 0; i < 3; i++ { // a plain open and save, three times, loses nothing
		v = mustOpen(t, p, creds())
		must(t, v.Put(Entry{Group: "g", Title: "Other", Password: []byte("o")}))
		must(t, v.Save())
	}
	v = mustOpen(t, p, creds())
	g, _ = v.group("g")
	e = &g.Entries[0]
	if e.GetContent("CustomProt") != "cp-value" || !e.Get("CustomProt").Value.Protected.Bool || e.GetContent("CustomPlain") != "pl-value" ||
		e.Tags != "t1;t2" || e.IconID != 17 || len(e.CustomData) != 1 || e.UUID != uuid {
		t.Fatal("something was lost")
	}
}

// keepassxc-cli interop. Skipped, with the reason, when it is not installed.
func cli(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("keepassxc-cli", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keepassxc-cli %s: %v\n%s", args[0], err, strings.ReplaceAll(string(out), pw, "***"))
	}
	return string(out)
}

func needCLI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("keepassxc-cli"); err != nil {
		t.Skip("keepassxc-cli is not installed: the interop test is skipped")
	}
}

func TestInteropCLIMadeVault(t *testing.T) {
	needCLI(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "c.kdbx")
	in := pw + "\n"
	cli(t, pw+"\n"+pw+"\n", "db-create", "-p", "-t", "100", db)
	// a vault made by keepassxc-cli is KDBX 3.1: refused with the upgrade hint
	if _, err := Open(db, creds()); !errors.Is(err, ErrKDBX3) {
		t.Fatalf("3.1 vault: %v", err)
	}
	cli(t, in, "mkdir", db, "grp")
	cli(t, in, "mkdir", db, "grp2")
	cli(t, in+"cli-secret\n", "add", "-p", db, "grp/one", "--notes", "cli notes")
	att := filepath.Join(dir, "a.bin")
	must(t, os.WriteFile(att, []byte("attached by the cli"), 0o600))
	cli(t, in, "attachment-import", db, "grp/one", "content", att)
	cli(t, in+"x\n", "add", "-p", db, "grp/gone")
	cli(t, in, "rm", db, "grp/gone")
	cli(t, in, "mv", db, "grp/one", "grp2")
	// the first mv / rm upgraded the file to 4.x
	v, err := Open(db, creds())
	if err != nil {
		t.Fatalf("after mv: %v", err)
	}
	if v.Format().Major != 4 {
		t.Fatalf("format %+v", v.Format())
	}
	e, err := v.Get("grp2/one")
	must(t, err)
	if string(e.Password) != "cli-secret" || e.Notes != "cli notes" {
		t.Fatal("cli entry misread")
	}
	if a, err := v.Attachment("grp2/one", "content"); err != nil || string(a) != "attached by the cli" {
		t.Fatalf("attachment %q %v", a, err)
	}
	if bin, _ := v.Entries(RecycleBinName); len(bin) != 1 {
		t.Fatalf("the cli recycle bin entry is not seen: %d", len(bin))
	}
	// we edit; the cli reads it back
	must(t, v.Put(Entry{Group: "grp2", Title: "one", Password: []byte("go-secret"), Notes: "go notes"}))
	must(t, v.Put(Entry{Group: "new/deep", Title: "fresh", Password: []byte("fresh-pw"), Notes: "\u043d\u0456\u0447"}))
	must(t, v.SetAttachment("new/deep/fresh", "content", []byte("from go")))
	must(t, v.Remove("grp2/one"))
	must(t, v.Save())
	out := cli(t, in, "show", "-s", "-a", "password", db, "new/deep/fresh")
	if !strings.Contains(out, "fresh-pw") {
		t.Fatal("cli does not read our new entry")
	}
	if out := cli(t, in, "attachment-export", db, "new/deep/fresh", "content", "--stdout"); !strings.Contains(out, "from go") {
		t.Fatal("cli does not read our attachment")
	}
	if out := cli(t, in, "ls", "-R", "-f", db); !strings.Contains(out, "Recycle Bin/one") && !strings.Contains(out, "one") {
		t.Fatalf("ls: %s", out)
	}
	// the cli edits our file; we read it
	cli(t, in+"cli-edit\n", "edit", "-p", db, "new/deep/fresh")
	v2 := mustOpen(t, db, creds())
	if e, _ := v2.Get("new/deep/fresh"); string(e.Password) != "cli-edit" {
		t.Fatal("cli edit not seen")
	}
	// and a file made by us, with a custom field and a tag, edited by the cli, still has them when we read it again
	g, _ := v2.group("new/deep")
	g.Entries[0].Values = append(g.Entries[0].Values, gokeepasslib.ValueData{Key: "Extra", Value: gokeepasslib.V{Content: "extra-v", Protected: boolW(true)}})
	g.Entries[0].Tags = "tagged"
	must(t, v2.Save())
	cli(t, in, "mkdir", db, "by-cli")
	v3 := mustOpen(t, db, creds())
	g, _ = v3.group("new/deep")
	if g.Entries[0].GetContent("Extra") != "extra-v" || g.Entries[0].Tags != "tagged" {
		t.Fatal("custom field or tag lost after the cli saved the file")
	}
	if gg, _ := v3.Groups(""); !contains(gg, "by-cli") {
		t.Fatal("cli group not seen")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestInteropCLIKeyFile(t *testing.T) {
	needCLI(t)
	dir := t.TempDir()
	kf := filepath.Join(dir, "k.keyx")
	must(t, NewKeyFile(kf))
	p := filepath.Join(dir, "v.kdbx")
	v, err := Create(p, Credentials{Password: []byte(pw), KeyFile: kf}, CreateOptions{DecryptionTime: 100 * time.Millisecond})
	must(t, err)
	must(t, v.Put(Entry{Group: "g", Title: "e", Password: []byte("kfpw")}))
	must(t, v.Save())
	// KeePassXC opens our file with the same password and key file
	if out := cli(t, pw+"\n", "show", "-s", "-a", "password", "-k", kf, p, "g/e"); !strings.Contains(out, "kfpw") {
		t.Fatal("cli cannot open our key file vault")
	}
	// and a key file made by the cli opens in ours
	kf2 := filepath.Join(dir, "k2.keyx")
	db2 := filepath.Join(dir, "v2.kdbx")
	// a key file made by KeePassXC itself: the cli makes one when db-create is given a missing path? it does not, so make ours and let the cli use it
	must(t, NewKeyFile(kf2))
	cli(t, pw+"\n"+pw+"\n", "db-create", "-p", "-t", "100", "--set-key-file", kf2, db2)
	in := pw + "\n"
	cli(t, in, "mkdir", "-k", kf2, db2, "a")
	cli(t, in, "mkdir", "-k", kf2, db2, "b")
	cli(t, in+"x\n", "add", "-p", "-k", kf2, db2, "a/e")
	cli(t, in, "mv", "-k", kf2, db2, "a/e", "b")
	v2, err := Open(db2, Credentials{Password: []byte(pw), KeyFile: kf2})
	if err != nil {
		t.Fatal(err)
	}
	if e, err := v2.Get("b/e"); err != nil || string(e.Password) != "x" {
		t.Fatalf("%v", err)
	}
	if _, err := Open(db2, creds()); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("opened without the key file: %v", err)
	}
}
