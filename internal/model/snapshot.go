package model

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ItemKey names an item: its section and its name.
type ItemKey struct{ Section, Name string }

func (k ItemKey) String() string { return k.Section + "/" + k.Name }

// Entry is one variable.
type Entry struct {
	Key, Value, Group string
	Path              string // the full path in the vault
	Managed           string // owner | system
	Vis               string // plain | secret | sealed
	Title, Notes      string
	Description       string
	Labels            []string
	Changed           string
	Ref               bool    // the value is the resolved target of a KeePass field reference
	VisBy             string  // ManagedOwner when the owner chose the visibility
	ManagedSet        string  // ManagedOwner when the owner chose managed-by by hand: the automatic rule leaves it alone
	Raw               *string // set on the copy Resolve makes when the value had references: the value as typed
}

// NewEntry is an Entry with the defaults of the store (owner, secret).
func NewEntry(key, value, group, path string) *Entry {
	return &Entry{Key: key, Value: value, Group: group, Path: path, Managed: ManagedOwner, Vis: VisSecret, Title: key}
}

// FileEntry is a file attachment.
type FileEntry struct {
	Data    []byte
	Mode    int
	Sha     string
	Managed string
	Changed string
	Vis     string
	Scope   ItemKey // the item the file lives in
	Key     string  // the path under files/: <rel> or sites/<site>/<rel>
}

// SHA256 is the hex digest of data.
func SHA256(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }

// Item is an item of a section (an environment, a system, a site, ...).
type Item struct {
	Section, Name string
	Entries       []*Entry
	Files         map[string]*FileEntry
	Blobs         map[string][]byte
	BlobPaths     map[string]bool
	Title         string
	Description   string
	Uses          []ItemKey
	OnlySites     []string
	SiteType      string
	State         string
	HasMeta       bool
	Retired       []string
	RetiredInfo   []map[string]string
}

// NewItem is an empty active item.
func NewItem(section, name string) *Item {
	return &Item{Section: section, Name: name, Files: map[string]*FileEntry{}, Blobs: map[string][]byte{}, BlobPaths: map[string]bool{}, State: StateActive}
}

func (it *Item) Ref() string  { return it.Section + "/" + it.Name }
func (it *Item) Key() ItemKey { return ItemKey{it.Section, it.Name} }
func (it *Item) IsEnv() bool  { return it.Section == SecEnvs }

// Find returns the entry of a group and key, or nil.
func (it *Item) Find(group, key string) *Entry {
	for _, e := range it.Entries {
		if e.Group == group && e.Key == key {
			return e
		}
	}
	return nil
}

func (it *Item) HasKey(key string) bool {
	for _, e := range it.Entries {
		if e.Key == key {
			return true
		}
	}
	return false
}

// InUse reports whether the item has entries, files or an `.item` entry.
func (it *Item) InUse() bool { return len(it.Entries) > 0 || len(it.Files) > 0 || it.HasMeta }

// SectionMeta is what a `.section` entry carries.
type SectionMetaInfo struct {
	Title  string
	Order  int
	System bool
	State  string
}

// GroupMetaInfo is what a `.group` entry carries.
type GroupMetaInfo struct {
	Title, Description, State string
	OnlySites                 []string
}

type groupKey struct{ Section, Item, Group string }

// Snapshot is the projection of the vault the commands read (internal/vmodel.Compat lays the model out as one), in memory only.
type Snapshot struct {
	Items     map[ItemKey]*Item
	order     []ItemKey // insertion order of Items, for deterministic walks
	Sections  map[string]*SectionMetaInfo
	Extras    map[string]*FileEntry
	Groups    map[string]bool
	groupMeta map[groupKey]*GroupMetaInfo
}

func NewSnapshot() *Snapshot {
	return &Snapshot{Items: map[ItemKey]*Item{}, Sections: map[string]*SectionMetaInfo{}, Extras: map[string]*FileEntry{}, Groups: map[string]bool{}, groupMeta: map[groupKey]*GroupMetaInfo{}}
}

// Item returns an item or nil.
func (s *Snapshot) Item(section, name string) *Item { return s.Items[ItemKey{section, name}] }

// Make returns the item, made empty when it did not exist.
func (s *Snapshot) Make(section, name string) *Item {
	k := ItemKey{section, name}
	it := s.Items[k]
	if it == nil {
		it = NewItem(section, name)
		s.Items[k] = it
		s.order = append(s.order, k)
	}
	return it
}

// Put stores an item (replacing one of the same key).
func (s *Snapshot) Put(it *Item) {
	k := it.Key()
	if _, ok := s.Items[k]; !ok {
		s.order = append(s.order, k)
	}
	s.Items[k] = it
}

// All returns the items in insertion order.
func (s *Snapshot) All() []*Item {
	out := make([]*Item, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, s.Items[k])
	}
	return out
}

// GroupMeta returns the meta of a group, or nil.
func (s *Snapshot) GroupMeta(section, item, group string) *GroupMetaInfo {
	return s.groupMeta[groupKey{section, item, group}]
}

// SetGroupMeta stores the meta of a group.
func (s *Snapshot) SetGroupMeta(section, item, group string, m *GroupMetaInfo) {
	s.groupMeta[groupKey{section, item, group}] = m
}

// ItemNames: names of the live items of a section, sorted.
func (s *Snapshot) ItemNames(section string) []string {
	names := map[string]bool{}
	for g := range s.Groups {
		p := strings.Split(g, "/")
		if len(p) >= 3 && p[1] == section {
			names[p[2]] = true
		}
	}
	for k, it := range s.Items {
		if k.Section == section && it.InUse() {
			names[k.Name] = true
		}
	}
	var out []string
	for n := range names {
		if it := s.Items[ItemKey{section, n}]; it == nil || it.State != StateRetired {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// SectionNames: sections in the order the owner set (environments first),
// retired ones left out.
func (s *Snapshot) SectionNames() []string {
	found := map[string]bool{SecEnvs: true}
	for g := range s.Groups {
		p := strings.Split(g, "/")
		if len(p) >= 2 {
			found[p[1]] = true
		}
	}
	for n := range s.Sections {
		found[n] = true
	}
	delete(found, Files)
	var out []string
	for n := range found {
		if m := s.Sections[n]; m == nil || m.State != StateRetired {
			out = append(out, n)
		}
	}
	order := func(n string) int {
		if m := s.Sections[n]; m != nil {
			return m.Order
		}
		return 1000
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a != SecEnvs) != (b != SecEnvs) {
			return a == SecEnvs
		}
		if order(a) != order(b) {
			return order(a) < order(b)
		}
		return a < b
	})
	return out
}

// Linked returns the items an item links, in order (gone or retired ones left out).
func (s *Snapshot) Linked(section, name string) []*Item {
	it := s.Items[ItemKey{section, name}]
	if it == nil {
		return nil
	}
	var out []*Item
	for _, r := range it.Uses {
		if l := s.Items[r]; l != nil && l.State != StateRetired {
			out = append(out, l)
		}
	}
	return out
}

// BrokenLinks names the links of an item to something gone or retired.
func (s *Snapshot) BrokenLinks(section, name string) []ItemKey {
	it := s.Items[ItemKey{section, name}]
	if it == nil {
		return nil
	}
	var out []ItemKey
	for _, r := range it.Uses {
		if l := s.Items[r]; l == nil || l.State == StateRetired {
			out = append(out, r)
		}
	}
	return out
}

// UsersOf returns the environments (as "environments/<name>") that link an item.
func (s *Snapshot) UsersOf(section, name string) []string {
	var out []string
	for _, e := range s.All() {
		if !e.IsEnv() || e.State == StateRetired {
			continue
		}
		for _, u := range e.Uses {
			if u == (ItemKey{section, name}) {
				out = append(out, e.Ref())
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// GroupApplies: (applies, restricted) of a group for a site. Every group on
// the way (a, a/b, ...) that names only-sites must name the site; restricted =
// at least one does. site "" = no site asked: all apply.
func (s *Snapshot) GroupApplies(section, name, group, site string) (applies, restricted bool) {
	parts := strings.Split(group, "/")
	for i := 1; i <= len(parts); i++ {
		m := s.GroupMeta(section, name, strings.Join(parts[:i], "/"))
		if m == nil || len(m.OnlySites) == 0 {
			continue
		}
		restricted = true
		if site != "" && !contains(m.OnlySites, site) {
			return false, true
		}
	}
	return true, restricted
}

// GroupSites: the sites a group is limited to (its own or the nearest ancestor's); nil = every site.
func (s *Snapshot) GroupSites(section, name, group string) []string {
	parts := strings.Split(group, "/")
	for i := len(parts); i > 0; i-- {
		if m := s.GroupMeta(section, name, strings.Join(parts[:i], "/")); m != nil && len(m.OnlySites) > 0 {
			return append([]string(nil), m.OnlySites...)
		}
	}
	return nil
}

// SitesOf: the sites an environment has settings for (groups of it and of its
// linked items limited to sites), sorted.
func (s *Snapshot) SitesOf(env string) []string {
	names := map[string]bool{}
	it := s.Items[ItemKey{SecEnvs, env}]
	if it != nil {
		srcs := append([]*Item{it}, s.Linked(SecEnvs, env)...)
		for _, src := range srcs {
			for gk, m := range s.groupMeta {
				if gk.Section == src.Section && gk.Item == src.Name && m.State != StateRetired {
					for _, x := range m.OnlySites {
						names[x] = true
					}
				}
			}
		}
	}
	out := []string{}
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func contains(list []string, x string) bool {
	for _, l := range list {
		if l == x {
			return true
		}
	}
	return false
}

// ---- ingest: the classification of one vault entry (the KDBX side hands them over)

// RawEntry is one entry of the tree of a Snapshot (below Group).
type RawEntry struct {
	Path       []string // groups below Group
	Title      string
	Notes      string
	Password   string
	Changed    string
	Attachment []byte // the `content` attachment, if any
}

// Ingest classifies one entry into the snapshot (what parse_export did after
// reading the XML). Group paths must be added by the caller with AddGroup.
// A StoreError with OldLayout is returned for an old-layout vault.
func (s *Snapshot) Ingest(e RawEntry) error {
	path, title, notes := e.Path, e.Title, e.Notes
	n := ParseNotes(notes)
	if len(path) == 0 {
		return nil
	}
	mode := func() int {
		m, err := strconv.ParseInt(orDefault(n["mode"], "0600"), 8, 32)
		if err != nil {
			return 0o600
		}
		return int(m)
	}
	if path[0] == Files {
		rel := strings.Join(append(append([]string{}, path[1:]...), title), "/")
		s.Extras[rel] = &FileEntry{Data: e.Attachment, Mode: mode(), Sha: SHA256(e.Attachment)}
		return nil
	}
	if len(path) == 1 {
		if title == SectionMeta {
			order := 1000
			if v, err := strconv.Atoi(n["order"]); err == nil && v >= 0 {
				order = v
			}
			s.Sections[path[0]] = &SectionMetaInfo{Title: n["title"], Order: order, System: n[ManagedSystem] == "yes", State: orDefault(n["state"], StateActive)}
		}
		return nil
	}
	section, name, rest := path[0], path[1], path[2:]
	it := s.Make(section, name)
	scope := ItemKey{section, name}
	if len(rest) == 0 && title == ItemMeta {
		if _, ok := n["type"]; ok {
			return storeErr(OldLayout)
		}
		it.HasMeta, it.Title = true, n["title"]
		it.Description, it.State = HintOf(notes), orDefault(n["state"], StateActive)
		it.Uses = nil
		for _, x := range strings.Split(n["uses"], ",") {
			if r, ok := SplitRef(strings.TrimSpace(x)); ok {
				it.Uses = append(it.Uses, r)
			}
		}
		it.OnlySites, it.SiteType = ParseLabels(n["only-sites"]), n["site-type"]
		return nil
	}
	if len(rest) > 0 && rest[0] == Retired {
		info := map[string]string{}
		for k, v := range n {
			info[k] = v
		}
		info["title"] = strings.Join(append(append([]string{}, rest[1:]...), title), "/")
		info["changed"], info["value"], info["description"] = e.Changed, e.Password, HintOf(notes)
		it.Retired = append(it.Retired, info["title"])
		it.RetiredInfo = append(it.RetiredInfo, info)
		return nil
	}
	managed := orDefault(n["managed-by"], ManagedOwner)
	if len(rest) > 0 && rest[0] == Files {
		rel := strings.Join(append(append([]string{}, rest[1:]...), title), "/")
		it.Files[rel] = &FileEntry{Data: e.Attachment, Mode: mode(), Sha: SHA256(e.Attachment), Managed: managed, Changed: e.Changed, Vis: SafeVisibility(notes, managed), Scope: scope, Key: rel}
		return nil
	}
	full := strings.Join(append(append([]string{Group}, path...), title), "/")
	if len(rest) > 0 && rest[0] == Blobs {
		it.Blobs[title] = e.Attachment
		it.BlobPaths[full] = true
		return nil
	}
	if len(rest) == 0 {
		return nil
	}
	group := strings.Join(rest, "/")
	if title == GroupMeta {
		s.SetGroupMeta(section, name, group, &GroupMetaInfo{Title: n["title"], Description: HintOf(notes), State: orDefault(n["state"], StateActive), OnlySites: ParseLabels(n["only-sites"])})
		return nil
	}
	it.Entries = append(it.Entries, &Entry{Key: title, Value: e.Password, Group: group, Path: full, Managed: managed, Vis: SafeVisibility(notes, managed), Title: title,
		Notes: notes, Description: HintOf(notes), Labels: ParseLabels(n["labels"]), Changed: e.Changed, VisBy: n["vis-by"], ManagedSet: n["managed-set"]})
	return nil
}

// AddGroup records a group path below Group (e.g. "IceVault/global/main/net").
func (s *Snapshot) AddGroup(path string) { s.Groups[path] = true }

// ResolveKeePassRefs replaces the value of every entry whose password is
// {REF:P@I:<uuid>} with the target's password (byUUID: upper-case hex uuid ->
// password); a dangling reference stays as written.
func (s *Snapshot) ResolveKeePassRefs(byUUID map[string]string) {
	for _, it := range s.All() {
		for _, e := range it.Entries {
			if m := keepRefRE.FindStringSubmatch(e.Value); m != nil {
				if v, ok := byUUID[strings.ToUpper(m[1])]; ok {
					e.Value, e.Ref = v, true
				}
			}
		}
	}
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// CheckLayout refuses a vault in an older layout (a top-level group without a
// `.section` entry, or a `.layouts` group); call it after every entry and group
// has been added. No migration code: the owner starts a new vault.
func (s *Snapshot) CheckLayout() error {
	for g := range s.Groups {
		parts := strings.Split(g, "/")
		for _, p := range parts {
			if p == ".layouts" {
				return storeErr(OldLayout)
			}
		}
		if len(parts) == 2 && parts[1] != Files && s.Sections[parts[1]] == nil {
			return storeErr(OldLayout)
		}
	}
	return nil
}

// KPTime is a time of the XML export as UTC text YYYY-MM-DDTHH:MM:SSZ. A KDBX 3
// database writes ISO text; a KDBX 4 one the base64 of a little-endian int64 =
// seconds since 0001-01-01T00:00:00 UTC. Anything else: "".
func KPTime(text string) string {
	if isoTime.MatchString(text) {
		return text[:19] + "Z"
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(raw) != 8 {
		return ""
	}
	secs := int64(binary.LittleEndian.Uint64(raw))
	if secs < 0 || secs > 253402300799 {
		return ""
	}
	return time.Unix(secs-62135596800, 0).UTC().Format("2006-01-02T15:04:05Z") // seconds since 0001-01-01
}
