package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

// Paths are slash separated and start below the root group, as in keepassxc-cli: "Notes/prod/gcp/API_KEY" is the entry API_KEY in that group.
// A group or entry name never contains a slash.

// ErrNotFound means no group or entry has that path.
var ErrNotFound = errors.New("not found")

// RecycleBinName is the group KeePass clients use for removed entries.
const RecycleBinName = "Recycle Bin"

// binaryBytes is the content of an attachment. The library's GetContentBytes tries base64 on every binary "for KDBX 3.1" and, when the bytes happen to be valid
// base64, returns the DECODED bytes even in a KDBX 4 file: a key file of 64 hex characters or the base64 of 32 bytes (a signing key, a ring key) came back as other
// bytes. In KDBX 4 the content is stored as it is (the inner header never compresses it), so it is returned as it is; only a 3.x file, which Open refuses, takes
// the library's way.
func binaryBytes(db *gokeepasslib.Database, b *gokeepasslib.Binary) ([]byte, error) {
	if db.Header.IsKdbx4() {
		return append([]byte(nil), b.Content...), nil
	}
	return b.GetContentBytes()
}

func boolW(b bool) w.BoolWrapper { return w.NewBoolWrapper(b) }

func now(f *Vault) w.TimeWrapper {
	t := w.Now()
	t.Formatted = !f.db.Header.IsKdbx4()
	return t
}

// EntryInfo describes an entry without its secret.
type EntryInfo struct {
	Title       string
	Group       string // path of its group
	UUID        string
	Notes       string
	Attachments []string
	Created     time.Time
	Modified    time.Time
	History     int       // saved earlier versions
	Expires     time.Time // the expiry of the entry (zero: it does not expire)
}

// Entry is a variable: title, secret and notes.
type Entry struct {
	Group    string
	Title    string
	UserName string
	URL      string
	Notes    string
	Password []byte // the caller wipes it
}

func split(path string) []string {
	var out []string
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (v *Vault) root() *gokeepasslib.Group { return &v.db.Content.Root.Groups[0] }

func findGroup(g *gokeepasslib.Group, name string) *gokeepasslib.Group {
	for i := range g.Groups {
		if g.Groups[i].Name == name {
			return &g.Groups[i]
		}
	}
	return nil
}

func findEntry(g *gokeepasslib.Group, title string) int {
	for i := range g.Entries {
		if g.Entries[i].GetTitle() == title {
			return i
		}
	}
	return -1
}

// group resolves a group path ("" is the root group). Pointers stay valid until the next change of the tree.
func (v *Vault) group(path string) (*gokeepasslib.Group, error) {
	g := v.root()
	for _, p := range split(path) {
		if g = findGroup(g, p); g == nil {
			return nil, fmt.Errorf("group %q: %w", path, ErrNotFound)
		}
	}
	return g, nil
}

func (v *Vault) entry(path string) (*gokeepasslib.Group, int, error) {
	parts := split(path)
	if len(parts) == 0 {
		return nil, 0, fmt.Errorf("entry %q: %w", path, ErrNotFound)
	}
	g, err := v.group(strings.Join(parts[:len(parts)-1], "/"))
	if err != nil {
		return nil, 0, err
	}
	i := findEntry(g, parts[len(parts)-1])
	if i < 0 {
		return nil, 0, fmt.Errorf("entry %q: %w", path, ErrNotFound)
	}
	return g, i, nil
}

func tm(t *w.TimeWrapper) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.Time
}

func (v *Vault) info(group string, e *gokeepasslib.Entry) EntryInfo {
	n := 0
	for _, h := range e.Histories {
		n += len(h.Entries)
	}
	var att []string
	for _, b := range e.Binaries {
		att = append(att, b.Name)
	}
	return EntryInfo{Title: e.GetTitle(), Group: group, UUID: uuidText(e.UUID), Notes: e.GetContent("Notes"), Attachments: att,
		Created: tm(e.Times.CreationTime), Modified: tm(e.Times.LastModificationTime), History: n, Expires: expiresOf(e)}
}

func uuidText(u gokeepasslib.UUID) string { return hex.EncodeToString(u[:]) }

// Groups lists the names of the child groups of a group, in file order.
func (v *Vault) Groups(path string) ([]string, error) {
	g, err := v.group(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(g.Groups))
	for _, c := range g.Groups {
		out = append(out, c.Name)
	}
	return out, nil
}

// Entries lists the entries of a group.
func (v *Vault) Entries(path string) ([]EntryInfo, error) {
	g, err := v.group(path)
	if err != nil {
		return nil, err
	}
	out := make([]EntryInfo, 0, len(g.Entries))
	for i := range g.Entries {
		out = append(out, v.info(strings.Join(split(path), "/"), &g.Entries[i]))
	}
	return out, nil
}

// Walk calls fn for every entry below the group (depth first, file order). The recycle bin is included: skip it by its group path.
func (v *Vault) Walk(path string, fn func(EntryInfo) error) error {
	g, err := v.group(path)
	if err != nil {
		return err
	}
	return walk(v, strings.Join(split(path), "/"), g, fn)
}

func walk(v *Vault, p string, g *gokeepasslib.Group, fn func(EntryInfo) error) error {
	for i := range g.Entries {
		if err := fn(v.info(p, &g.Entries[i])); err != nil {
			return err
		}
	}
	for i := range g.Groups {
		if err := walk(v, join(p, g.Groups[i].Name), &g.Groups[i], fn); err != nil {
			return err
		}
	}
	return nil
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "/" + b
}

// Get returns an entry with its secret.
func (v *Vault) Get(path string) (Entry, error) {
	g, i, err := v.entry(path)
	if err != nil {
		return Entry{}, err
	}
	e := &g.Entries[i]
	parts := split(path)
	return Entry{Group: strings.Join(parts[:len(parts)-1], "/"), Title: e.GetTitle(), UserName: e.GetContent("UserName"), URL: e.GetContent("URL"),
		Notes: e.GetContent("Notes"), Password: []byte(e.GetPassword())}, nil
}

// MakeGroup creates the group and every missing level above it (like mkdir -p). Existing groups are left alone.
func (v *Vault) MakeGroup(path string) error {
	g := v.root()
	for _, p := range split(path) {
		c := findGroup(g, p)
		if c == nil {
			n := gokeepasslib.NewGroup()
			n.Name = p
			n.Times.CreationTime = ptr(now(v))
			n.Times.LastModificationTime = n.Times.CreationTime
			n.Times.LastAccessTime = n.Times.CreationTime
			n.Times.LocationChanged = n.Times.CreationTime
			g.Groups = append(g.Groups, n)
			c = &g.Groups[len(g.Groups)-1]
		}
		g = c
	}
	return nil
}

func ptr(t w.TimeWrapper) *w.TimeWrapper { return &t }

func (v *Vault) valueData(key, val string, protectedMeta bool) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: val, Protected: boolW(protectedMeta)}}
}

func (v *Vault) setValue(e *gokeepasslib.Entry, key, val string) {
	mp := v.db.Content.Meta.MemoryProtection
	prot := map[string]bool{"Title": mp.ProtectTitle.Bool, "UserName": mp.ProtectUserName.Bool, "Password": true, "URL": mp.ProtectURL.Bool, "Notes": mp.ProtectNotes.Bool}[key]
	if i := e.GetIndex(key); i >= 0 {
		e.Values[i].Value.Content = val
		return
	}
	e.Values = append(e.Values, v.valueData(key, val, prot))
}

// snapshot saves the entry as it is now into its history (KeePass does it before every change) and trims the history to the database limit.
func (v *Vault) snapshot(e *gokeepasslib.Entry) {
	snap := *e
	snap.Histories = nil
	snap.Values = append([]gokeepasslib.ValueData(nil), e.Values...)
	snap.Binaries = append([]gokeepasslib.BinaryReference(nil), e.Binaries...)
	snap.CustomData = append([]gokeepasslib.CustomData(nil), e.CustomData...)
	if len(e.Histories) == 0 {
		e.Histories = []gokeepasslib.History{{}}
	}
	h := &e.Histories[0]
	h.Entries = append(h.Entries, snap)
	if max := int(v.db.Content.Meta.HistoryMaxItems); max >= 0 && len(h.Entries) > max {
		h.Entries = h.Entries[len(h.Entries)-max:]
	}
}

func (v *Vault) touch(e *gokeepasslib.Entry) {
	t := now(v)
	e.Times.LastModificationTime = &t
	e.Times.LastAccessTime = &t
}

// Put creates the entry (and its groups) or changes the one with that title in that group. A change that alters nothing writes nothing; a real change
// first saves the old version into the entry's history.
func (v *Vault) Put(e Entry) error {
	if e.Title == "" || strings.Contains(e.Title, "/") {
		return errors.New("an entry title is not empty and has no slash")
	}
	if err := v.MakeGroup(e.Group); err != nil {
		return err
	}
	g, _ := v.group(e.Group)
	i := findEntry(g, e.Title)
	if i < 0 {
		n := gokeepasslib.NewEntry()
		n.Times.CreationTime = ptr(now(v))
		t := n.Times.CreationTime
		n.Times.LastModificationTime, n.Times.LastAccessTime, n.Times.LocationChanged = t, t, t
		v.setValue(&n, "Title", e.Title)
		v.setValue(&n, "UserName", e.UserName)
		v.setValue(&n, "Password", string(e.Password))
		v.setValue(&n, "URL", e.URL)
		v.setValue(&n, "Notes", e.Notes)
		g.Entries = append(g.Entries, n)
		return nil
	}
	cur := &g.Entries[i]
	if cur.GetContent("UserName") == e.UserName && cur.GetContent("URL") == e.URL && cur.GetContent("Notes") == e.Notes && cur.GetPassword() == string(e.Password) {
		return nil
	}
	v.snapshot(cur)
	v.setValue(cur, "UserName", e.UserName)
	v.setValue(cur, "Password", string(e.Password))
	v.setValue(cur, "URL", e.URL)
	v.setValue(cur, "Notes", e.Notes)
	v.touch(cur)
	return nil
}

// Rename changes the title of an entry in place (the old version goes to its history). A title that is taken in the group is refused.
func (v *Vault) Rename(path, title string) error {
	if title == "" || strings.Contains(title, "/") {
		return errors.New("an entry title is not empty and has no slash")
	}
	g, i, err := v.entry(path)
	if err != nil {
		return err
	}
	if j := findEntry(g, title); j >= 0 && j != i {
		return fmt.Errorf("%q already exists in that group", title)
	}
	e := &g.Entries[i]
	if e.GetTitle() == title {
		return nil
	}
	v.snapshot(e)
	v.setValue(e, "Title", title)
	v.touch(e)
	return nil
}

// GroupPaths lists the path of the group and of every group below it (empty groups included), depth first.
func (v *Vault) GroupPaths(path string) ([]string, error) {
	g, err := v.group(path)
	if err != nil {
		return nil, err
	}
	var out []string
	var rec func(p string, g *gokeepasslib.Group)
	rec = func(p string, g *gokeepasslib.Group) {
		out = append(out, p)
		for i := range g.Groups {
			rec(join(p, g.Groups[i].Name), &g.Groups[i])
		}
	}
	rec(strings.Join(split(path), "/"), g)
	return out, nil
}

// HasGroup says whether a group exists.
func (v *Vault) HasGroup(path string) bool { _, err := v.group(path); return err == nil }

// Attachment returns the bytes of a named attachment of an entry.
func (v *Vault) Attachment(path, name string) ([]byte, error) {
	g, i, err := v.entry(path)
	if err != nil {
		return nil, err
	}
	for _, r := range g.Entries[i].Binaries {
		if r.Name == name {
			b := v.db.FindBinary(r.Value.ID)
			if b == nil {
				return nil, fmt.Errorf("attachment %q of %q is missing from the file", name, path)
			}
			return binaryBytes(v.db, b)
		}
	}
	return nil, fmt.Errorf("attachment %q of %q: %w", name, path, ErrNotFound)
}

// SetAttachment adds or replaces an attachment (same bytes: nothing changes). The old version goes to the entry's history.
func (v *Vault) SetAttachment(path, name string, data []byte) error {
	g, i, err := v.entry(path)
	if err != nil {
		return err
	}
	e := &g.Entries[i]
	for _, r := range e.Binaries {
		if r.Name == name {
			if b := v.db.FindBinary(r.Value.ID); b != nil {
				if cur, err := binaryBytes(v.db, b); err == nil && string(cur) == string(data) {
					return nil
				}
			}
		}
	}
	v.snapshot(e)
	b := v.db.AddBinary(data)
	ref := b.CreateReference(name)
	replaced := false
	for k := range e.Binaries {
		if e.Binaries[k].Name == name {
			e.Binaries[k], replaced = ref, true
		}
	}
	if !replaced {
		e.Binaries = append(e.Binaries, ref)
	}
	v.touch(e)
	return nil
}

func (v *Vault) recycleBin(create bool) *gokeepasslib.Group {
	meta := v.db.Content.Meta
	if !meta.RecycleBinUUID.IsZero() {
		if g := findByUUID(v.root(), meta.RecycleBinUUID); g != nil {
			return g
		}
	}
	if !create {
		return nil
	}
	n := gokeepasslib.NewGroup()
	n.Name = RecycleBinName
	n.IconID = 43
	n.EnableAutoType = w.NullableBoolWrapper{Valid: true, Bool: false}
	n.EnableSearching = w.NullableBoolWrapper{Valid: true, Bool: false}
	r := v.root()
	r.Groups = append(r.Groups, n)
	meta.RecycleBinUUID = n.UUID
	meta.RecycleBinEnabled = boolW(true)
	t := now(v)
	meta.RecycleBinChanged = &t
	return &r.Groups[len(r.Groups)-1]
}

func findByUUID(g *gokeepasslib.Group, u gokeepasslib.UUID) *gokeepasslib.Group {
	if g.UUID.Compare(u) {
		return g
	}
	for i := range g.Groups {
		if f := findByUUID(&g.Groups[i], u); f != nil {
			return f
		}
	}
	return nil
}

func inside(g *gokeepasslib.Group, u gokeepasslib.UUID) bool {
	return findByUUID(g, u) != nil
}

// Remove deletes an entry: into the recycle bin (made when missing), or for good when it is already in the bin or the bin is switched off.
func (v *Vault) Remove(path string) error {
	g, i, err := v.entry(path)
	if err != nil {
		return err
	}
	e := g.Entries[i]
	bin := v.recycleBin(false)
	inBin := bin != nil && inside(bin, g.UUID)
	if v.db.Content.Meta.RecycleBinEnabled.Bool && !inBin {
		v.recycleBin(true)
		g, i, _ = v.entry(path) // the root slice may have moved
		g.Entries = append(g.Entries[:i], g.Entries[i+1:]...)
		t := now(v)
		e.Times.LocationChanged = &t
		bin = v.recycleBin(false)
		bin.Entries = append(bin.Entries, e)
		return nil
	}
	g.Entries = append(g.Entries[:i], g.Entries[i+1:]...)
	v.db.Content.Root.DeletedObjects = append(v.db.Content.Root.DeletedObjects, gokeepasslib.DeletedObjectData{UUID: e.UUID, DeletionTime: ptr(now(v))})
	return nil
}

// Move moves an entry or a group to a new path (the last part is the new name). Moving a group into itself is refused.
func (v *Vault) Move(from, to string) error {
	fp, tp := split(from), split(to)
	if len(fp) == 0 || len(tp) == 0 {
		return errors.New("move needs two paths")
	}
	dest := strings.Join(tp[:len(tp)-1], "/")
	if g, i, err := v.entry(from); err == nil {
		e := g.Entries[i]
		if err := v.MakeGroup(dest); err != nil {
			return err
		}
		g, i, _ = v.entry(from)
		dg, _ := v.group(dest)
		if j := findEntry(dg, tp[len(tp)-1]); j >= 0 && dg != g {
			return fmt.Errorf("%q already exists", to)
		}
		g.Entries = append(g.Entries[:i], g.Entries[i+1:]...)
		dg, _ = v.group(dest)
		v.setValue(&e, "Title", tp[len(tp)-1])
		t := now(v)
		e.Times.LocationChanged = &t
		dg.Entries = append(dg.Entries, e)
		return nil
	}
	sg, err := v.group(from)
	if err != nil {
		return err
	}
	if strings.HasPrefix(strings.Join(tp, "/")+"/", strings.Join(fp, "/")+"/") {
		return errors.New("a group cannot be moved into itself")
	}
	moved := *sg
	if err := v.MakeGroup(dest); err != nil {
		return err
	}
	pp := split(strings.Join(fp[:len(fp)-1], "/"))
	pg, _ := v.group(strings.Join(pp, "/"))
	for k := range pg.Groups {
		if pg.Groups[k].Name == fp[len(fp)-1] {
			pg.Groups = append(pg.Groups[:k], pg.Groups[k+1:]...)
			break
		}
	}
	dg, err := v.group(dest)
	if err != nil {
		return err
	}
	if findGroup(dg, tp[len(tp)-1]) != nil {
		return fmt.Errorf("%q already exists", to)
	}
	moved.Name = tp[len(tp)-1]
	t := now(v)
	moved.Times.LocationChanged = &t
	dg.Groups = append(dg.Groups, moved)
	return nil
}

// fingerprint is a hash of everything this package can see: groups, entries, values, attachments (by content), history, times to the second, recycle bin,
// deleted objects. Save compares it before and after the write.
func fingerprint(db *gokeepasslib.Database) [32]byte {
	h := sha256.New()
	p := func(s ...string) {
		for _, x := range s {
			h.Write([]byte(x))
			h.Write([]byte{0})
		}
	}
	ts := func(t *w.TimeWrapper) string {
		if t == nil {
			return "-"
		}
		return fmt.Sprint(t.Time.Unix())
	}
	var ent func(e *gokeepasslib.Entry)
	ent = func(e *gokeepasslib.Entry) {
		p("E", uuidText(e.UUID), fmt.Sprint(e.IconID), e.Tags, e.ForegroundColor, e.BackgroundColor, e.OverrideURL, ts(e.Times.CreationTime), ts(e.Times.LastModificationTime))
		for _, v := range e.Values {
			p(v.Key, v.Value.Content, fmt.Sprint(v.Value.Protected.Bool))
		}
		for _, r := range e.Binaries {
			var s string
			if b := db.FindBinary(r.Value.ID); b != nil {
				if c, err := binaryBytes(db, b); err == nil {
					sum := sha256.Sum256(c)
					s = hex.EncodeToString(sum[:])
				}
			}
			p("B", r.Name, s)
		}
		for _, c := range e.CustomData {
			p("C", c.Key, c.Value)
		}
		for _, hs := range e.Histories {
			for k := range hs.Entries {
				p("H")
				ent(&hs.Entries[k])
			}
		}
	}
	var grp func(g *gokeepasslib.Group)
	grp = func(g *gokeepasslib.Group) {
		p("G", uuidText(g.UUID), g.Name, g.Notes, fmt.Sprint(g.IconID), ts(g.Times.CreationTime), ts(g.Times.LastModificationTime))
		for i := range g.Entries {
			ent(&g.Entries[i])
		}
		for i := range g.Groups {
			grp(&g.Groups[i])
		}
	}
	for i := range db.Content.Root.Groups {
		grp(&db.Content.Root.Groups[i])
	}
	d := make([]string, 0)
	for _, o := range db.Content.Root.DeletedObjects {
		d = append(d, uuidText(o.UUID))
	}
	sort.Strings(d)
	p(d...)
	p("M", db.Content.Meta.DatabaseName, uuidText(db.Content.Meta.RecycleBinUUID), fmt.Sprint(db.Content.Meta.HistoryMaxItems))
	for _, c := range db.Content.Meta.CustomData {
		p("MC", c.Key, c.Value)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
