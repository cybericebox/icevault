package model

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Writer is the vault side of a write: adding, setting
// notes, attaching, moving. The KDBX package implements it; the
// tests use an in-memory recorder. password nil = leave it empty.
type Writer interface {
	Mkdir(group string) error
	Add(entry, notes string, password *string) error
	SetPassword(entry, password string) error
	SetNotes(entry, notes string) error
	Remove(entry string) error
	Move(entry, group string) error
	SetTitle(entry, title string) error
	Attach(entry string, data []byte, force bool) error
}

// CreateSpec describes the entry the consumer's checklist says can be made for a missing key.
type CreateSpec struct {
	Key, Group, Description, Visibility string
	Labels                              []string
}

// CheckRow is a row of the consumer's checklist (what the Store needs of it).
type CheckRow struct {
	Key, File, State string
	Required         bool
	Create           *CreateSpec
}

// Consumer is what a Store needs from the project consumer (render.Project
// implements it): the scope of an entry, the settings files a key belongs to,
// the checklist, and the label and value rules. A nil Consumer is a plain store.
type Consumer interface {
	Normalize(value, managed string) string
	CheckLabels(labels []string, vis string) error
	KeyVisibility(key string) string
	ScopeOf(e *Entry) string // "block" | "environment"
	RelsOf(e *Entry) []string
	EnvGroup(group, key string) string
	BlockRels(key string) []string
	BlockGroup(rel, key string) string
	BlockLabel(rel string) string
	StripBlock(labels []string) []string
	ChecklistRows(snap *Snapshot, env, site string) ([]CheckRow, bool)
}

// Store is the generic editor of the vault: sections -> items -> groups ->
// entries (variables and files), links and labels. Rules: managed-by=system
// entries are read-only here; nothing is ever deleted (retire moves an entry,
// a group, an item to retired/); a still-linked item cannot be archived. Every
// write returns a *Error when refused.
//
// A Store is not safe for concurrent use: hold Mu around each call (the Store takes no
// lock inside: its calls into each other would deadlock).
type Store struct {
	W        Writer
	Snap     *Snapshot
	Consumer Consumer
	Now      func() string
	Mu       sync.Mutex
}

// NewStore makes a Store with the real clock.
func NewStore(w Writer, snap *Snapshot, c Consumer) *Store {
	return &Store{W: w, Snap: snap, Consumer: c, Now: NowUTC}
}

// NowUTC is the time as the vault writes it: YYYY-MM-DDTHH:MM:SSZ.
func NowUTC() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }

func errp(status int, msg, code string, kv ...string) *Error {
	e := Err(status, msg, code)
	for i := 0; i+1 < len(kv); i += 2 {
		e.Params[kv[i]] = kv[i+1]
	}
	return e
}

// ---------------------------------------------------------------- helpers

func (s *Store) item(section, name string) (*Item, error) {
	it := s.Snap.Item(section, name)
	if it == nil || it.State == StateRetired || !contains(s.Snap.ItemNames(section), name) {
		return nil, errp(404, "no such item", "no_item")
	}
	return it, nil
}

func (s *Store) find(section, name, group, key string) (*Item, *Entry, error) {
	it, err := s.item(section, name)
	if err != nil {
		return nil, nil, err
	}
	e := it.Find(group, key)
	if e == nil {
		return nil, nil, errp(404, "no such entry", "no_entry")
	}
	return it, e, nil
}

// Item is the live item or a 404 error.
func (s *Store) Item(section, name string) (*Item, error) { return s.item(section, name) }

// Find is the live entry or a 404 error.
func (s *Store) Find(section, name, group, key string) (*Item, *Entry, error) {
	return s.find(section, name, group, key)
}

// OwnerOnly refuses a system-managed entry.
func OwnerOnly(e *Entry) error {
	if e.Managed != ManagedOwner {
		return errp(403, "managed by the system: read-only", "system_managed")
	}
	return nil
}

// GroupsOf: group keys that exist in an item (with entries, or made in the
// screen), not retired, sorted.
func (s *Store) GroupsOf(section, name string) ([]string, error) {
	it, err := s.item(section, name)
	if err != nil {
		return nil, err
	}
	base := ItemRoot(section, name) + "/"
	set := map[string]bool{}
	for g := range s.Snap.Groups {
		if strings.HasPrefix(g, base) {
			set[g[len(base):]] = true
		}
	}
	for _, e := range it.Entries {
		set[e.Group] = true
	}
	var out []string
	for g := range set {
		if IsReserved(strings.Split(g, "/")[0]) {
			continue
		}
		if m := s.Snap.GroupMeta(section, name, g); m != nil && m.State == StateRetired {
			continue
		}
		out = append(out, g)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) hasGroup(section, name, group string) bool {
	gs, _ := s.GroupsOf(section, name)
	return contains(gs, group)
}

// EnsureGroupPath makes every group on the way to entry (a full path) that the vault lacks.
func (s *Store) EnsureGroupPath(entry string) error {
	parts := strings.Split(entry, "/")
	parts = parts[:len(parts)-1]
	for i := 1; i <= len(parts); i++ {
		g := strings.Join(parts[:i], "/")
		if !s.Snap.Groups[g] {
			if err := s.W.Mkdir(g); err != nil {
				return err
			}
			s.Snap.Groups[g] = true
		}
	}
	return nil
}

func (s *Store) writeItemMeta(it *Item) error {
	entry := ItemEntry(it.Section, it.Name)
	if it.HasMeta {
		return func() error {
			nts, err := ItemNotes(it)
			if err != nil {
				return err
			}
			return s.W.SetNotes(entry, nts)
		}()
	}
	if err := s.EnsureSection(it.Section, "", -1); err != nil {
		return err
	}
	if err := s.EnsureGroupPath(entry); err != nil {
		return err
	}
	if err := func() error {
		nts, err := ItemNotes(it)
		if err != nil {
			return err
		}
		return s.W.Add(entry, nts, nil)
	}(); err != nil {
		return err
	}
	it.HasMeta = true
	return nil
}

// EnsureSection makes the `.section` entry of a section when missing (order < 0: none).
func (s *Store) EnsureSection(section, title string, order int) error {
	if _, ok := s.Snap.Sections[section]; ok {
		return nil
	}
	system := section == SecEnvs
	if title == "" && system {
		title = "Environments"
	}
	if system {
		order = 0
	} else if order < 0 {
		order = 1000
	}
	entry := SectionEntry(section)
	if err := s.EnsureGroupPath(entry); err != nil {
		return err
	}
	o := order
	if o >= 1000 {
		o = -1
	}
	if err := func() error {
		nts, err := SectionNotes(title, o, system, StateActive)
		if err != nil {
			return err
		}
		return s.W.Add(entry, nts, nil)
	}(); err != nil {
		return err
	}
	s.Snap.Sections[section] = &SectionMetaInfo{Title: title, Order: order, System: system, State: StateActive}
	return nil
}

// EnsureItem makes the item with its `.item` entry when it did not exist.
func (s *Store) EnsureItem(section, name, title string) (*Item, error) {
	it := s.Snap.Make(section, name)
	if it.HasMeta {
		return it, nil
	}
	if err := s.EnsureSection(section, "", -1); err != nil {
		return nil, err
	}
	it.HasMeta, it.Title = true, title
	entry := ItemEntry(section, name)
	if err := s.EnsureGroupPath(entry); err != nil {
		return nil, err
	}
	return it, func() error {
		nts, err := ItemNotes(it)
		if err != nil {
			return err
		}
		return s.W.Add(entry, nts, nil)
	}()
}

func (s *Store) checklist(env, site string) []CheckRow {
	if s.Consumer == nil {
		return nil
	}
	rows, ok := s.Consumer.ChecklistRows(s.Snap, env, site)
	if !ok {
		return nil
	}
	return rows
}

// namedByChecklists: keys that the checklist of the item itself (an
// environment) or of an environment that links it names: retiring them gets a warning.
func (s *Store) namedByChecklists(section, name string) map[string]bool {
	keys := map[string]bool{}
	if s.Consumer == nil {
		return keys
	}
	var envs []string
	if section == SecEnvs {
		envs = append(envs, name)
	}
	for _, r := range s.Snap.UsersOf(section, name) {
		envs = append(envs, strings.SplitN(r, "/", 2)[1])
	}
	for _, env := range envs {
		for _, r := range s.checklist(env, "") {
			keys[r.Key] = true
		}
	}
	return keys
}

func (s *Store) needsConfirm(section, name string, keys []string, confirm bool, what string) error {
	named := s.namedByChecklists(section, name)
	var hit []string
	seen := map[string]bool{}
	for _, k := range keys {
		if named[k] && !seen[k] {
			seen[k] = true
			hit = append(hit, k)
		}
	}
	sort.Strings(hit)
	if len(hit) > 0 && !confirm {
		shown := strings.Join(hit[:min(5, len(hit))], ", ")
		if len(hit) > 5 {
			shown += "..."
		}
		kind := "entry"
		if strings.HasPrefix(what, "the group") {
			kind = "group"
		}
		e := errp(409, fmt.Sprintf("deploy needs %s: confirm to archive %s anyway", shown, what), "confirm_needed", "keys", shown, "what", kind)
		e.Confirm = true
		return e
	}
	return nil
}

// ---------------------------------------------------------------- reads

// Reveal returns the value of a secret entry (the one read that shows a secret).
func (s *Store) Reveal(section, name, group, key string) (string, error) {
	_, e, err := s.find(section, name, group, key)
	if err != nil {
		return "", err
	}
	if e.Vis == VisSealed {
		return "", errp(403, "sealed: this value is never shown or copied here", "sealed_reveal")
	}
	if e.Vis != VisSecret {
		return "", errp(404, "nothing to reveal: the value is shown as text", "plain_reveal")
	}
	return e.Value, nil
}

// CompareCell is the state of one key of another environment next to this one.
type CompareCell struct {
	State      string
	Value      *string // only a plain value
	Visibility string
	Same       *bool  // nil: one side has no value to compare
	Mine       string // "set" | "empty" | "" (the key is not here)
}

// Compare: for one environment, the state (and a plain value) of every key of
// another environment (its linked items included), by key. Same / different is
// decided here, for secret and sealed values too; a secret never leaves.
func (s *Store) Compare(section, name, other string) (map[string]CompareCell, error) {
	if section != SecEnvs {
		return nil, errp(400, "compare is between environments", "compare_envs")
	}
	if _, err := s.item(section, name); err != nil {
		return nil, err
	}
	if _, err := s.item(SecEnvs, other); err != nil {
		return nil, err
	}
	mine := s.Snap.Resolve(section, name, "", nil).ByKey
	theirs := s.Snap.Resolve(SecEnvs, other, "", nil)
	out := map[string]CompareCell{}
	for _, key := range theirs.Order {
		e := theirs.ByKey[key][0].Entry
		cell := CompareCell{State: "empty", Visibility: e.Vis}
		if e.Value != "" {
			cell.State = "set"
		}
		if e.Vis == VisPlain {
			v := e.Value
			cell.Value = &v
		}
		if m := mine[key]; len(m) > 0 {
			cell.Mine = "empty"
			if m[0].Entry.Value != "" {
				cell.Mine = "set"
			}
			if m[0].Entry.Value != "" && e.Value != "" {
				same := m[0].Entry.Value == e.Value
				cell.Same = &same
			}
		}
		out[key] = cell
	}
	return out, nil
}

// ---------------------------------------------------------------- writes: sections and items

func isNameOK(name string) bool { return NameRE.MatchString(name) && !IsReserved(name) }

func (s *Store) CreateSection(name, title string) error {
	if !isNameOK(name) || name == SecEnvs {
		return errp(400, "a section name is 1-32 characters: a-z 0-9 _ -", "section_name")
	}
	if _, err := OneLine(title, "a title", 120); err != nil {
		return err
	}
	if contains(s.Snap.SectionNames(), name) || s.Snap.Sections[name] != nil {
		return errp(409, "that section exists (an archived one included)", "section_exists")
	}
	order := 10
	for _, m := range s.Snap.Sections {
		if m.Order < 1000 && m.Order > order {
			order = m.Order
		}
	}
	order++
	entry := SectionEntry(name)
	if err := s.EnsureGroupPath(entry); err != nil {
		return err
	}
	if err := func() error {
		nts, err := SectionNotes(title, order, false, StateActive)
		if err != nil {
			return err
		}
		return s.W.Add(entry, nts, nil)
	}(); err != nil {
		return err
	}
	s.Snap.Sections[name] = &SectionMetaInfo{Title: title, Order: order, State: StateActive}
	return nil
}

// UpdateSection changes the title and/or order (nil = keep).
func (s *Store) UpdateSection(name string, title *string, order *int) error {
	if name == SecEnvs {
		return errp(403, "the environments section cannot be renamed or moved", "envs_fixed")
	}
	meta := s.Snap.Sections[name]
	if meta == nil || !contains(s.Snap.SectionNames(), name) {
		return errp(404, "no such section", "no_section")
	}
	t, o := meta.Title, meta.Order
	if title != nil {
		var err error
		if t, err = OneLine(*title, "a title", 120); err != nil {
			return err
		}
	}
	if order != nil {
		o = *order
		if o < 0 || o >= 1000 {
			return errp(400, "an order is a number from 0 to 999", "order_range")
		}
	}
	if err := func() error {
		nts, err := SectionNotes(t, o, false, StateActive)
		if err != nil {
			return err
		}
		return s.W.SetNotes(SectionEntry(name), nts)
	}(); err != nil {
		return err
	}
	meta.Title, meta.Order = t, o
	return nil
}

// RetireSection archives an empty section; confirm must be its name.
func (s *Store) RetireSection(name, confirm string) error {
	if name == SecEnvs {
		return errp(403, "the environments section cannot be archived", "envs_not_retired")
	}
	meta := s.Snap.Sections[name]
	if meta == nil || !contains(s.Snap.SectionNames(), name) {
		return errp(404, "no such section", "no_section")
	}
	if confirm != name {
		return errp(409, fmt.Sprintf("type the name '%s' to confirm", name), "type_name", "name", name)
	}
	if len(s.Snap.ItemNames(name)) > 0 {
		return errp(409, "the section still has items: archive them first", "section_has_items")
	}
	if err := func() error {
		nts, err := SectionNotes(meta.Title, meta.Order, false, StateRetired)
		if err != nil {
			return err
		}
		return s.W.SetNotes(SectionEntry(name), nts)
	}(); err != nil {
		return err
	}
	meta.State = StateRetired
	return nil
}

func (s *Store) CreateItem(section, name, title string) (*Item, error) {
	if !isNameOK(name) {
		return nil, errp(400, "an item name is 1-32 characters: a-z 0-9 _ -", "item_name")
	}
	if _, err := OneLine(title, "a title", 120); err != nil {
		return nil, err
	}
	if section == SecExternal && name == GlobalRef {
		return nil, errp(400, fmt.Sprintf("'%s' is the name references use for the global section: pick another name", GlobalRef), "system_name_shared")
	}
	if !contains(s.Snap.SectionNames(), section) {
		return nil, errp(404, "no such section", "no_section")
	}
	if prev := s.Snap.Item(section, name); contains(s.Snap.ItemNames(section), name) || (prev != nil && prev.State == StateRetired) {
		return nil, errp(409, "that name is taken in this section (an archived one included: its entries are kept in the Archive)", "item_taken")
	}
	if err := s.EnsureSection(section, "", -1); err != nil {
		return nil, err
	}
	return s.EnsureItem(section, name, title)
}

// UpdateItem changes the title and/or description (nil = keep).
func (s *Store) UpdateItem(section, name string, title, description *string) error {
	it, err := s.item(section, name)
	if err != nil {
		return err
	}
	if title != nil {
		if it.Title, err = OneLine(*title, "a title", 120); err != nil {
			return err
		}
	}
	if description != nil {
		if it.Description, err = DescriptionText(*description); err != nil {
			return err
		}
	}
	return s.writeItemMeta(it)
}

func validSites(sites []string) ([]string, bool) {
	clean := ParseLabels(strings.Join(sites, ","))
	if len(clean) > 16 {
		return nil, false
	}
	for _, x := range clean {
		if !NameRE.MatchString(x) {
			return nil, false
		}
	}
	return clean, true
}

// SetItemSites limits an external system (or any item that is only
// referenced) to some sites; [] = every site.
func (s *Store) SetItemSites(section, name string, sites []string) error {
	it, err := s.item(section, name)
	if err != nil {
		return err
	}
	clean, ok := validSites(sites)
	if !ok {
		return errp(400, "sites are a list of site names (a-z 0-9 _ -)", "sites_form")
	}
	it.OnlySites = clean
	return s.writeItemMeta(it)
}

// SetSiteType sets the type of a site: a free word that selects the provider scripts.
func (s *Store) SetSiteType(name, siteType string) error {
	it, err := s.item(SecSites, name)
	if err != nil {
		return err
	}
	if !NameRE.MatchString(siteType) {
		return errp(400, "a site type is one word: a-z 0-9 _ -", "site_type_form")
	}
	it.SiteType = siteType
	return s.writeItemMeta(it)
}

// RefuseIfReferenced: a value of the global section or of an external system
// that other values refer to is not archived: the list says where it is used.
func (s *Store) RefuseIfReferenced(section, name string, keys []string) error {
	if section != SecGlobal && section != SecExternal {
		return nil
	}
	ref := name
	if section == SecGlobal {
		ref = GlobalRef
	}
	set := map[string]bool{}
	for _, key := range keys {
		for _, h := range s.Snap.Referencing(ref, key) {
			set[h.Item.Name+"/"+h.Entry.Key] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	list := make([]string, 0, len(set))
	for k := range set {
		list = append(list, k)
	}
	sort.Strings(list)
	shown := strings.Join(list[:min(5, len(list))], ", ")
	if len(list) > 5 {
		shown += "..."
	}
	return errp(409, fmt.Sprintf("still used by %s: change those values first", shown), "ref_used", "used", shown)
}

// RetireItem archives an item with all its entries and files; confirm must be its name.
func (s *Store) RetireItem(section, name, confirm string) error {
	it, err := s.item(section, name)
	if err != nil {
		return err
	}
	if confirm != name {
		return errp(409, fmt.Sprintf("type the name '%s' to confirm", name), "type_name", "name", name)
	}
	var keys []string
	for _, e := range it.Entries {
		keys = append(keys, e.Key)
	}
	if err := s.RefuseIfReferenced(section, name, keys); err != nil {
		return err
	}
	if users := s.Snap.UsersOf(section, name); len(users) > 0 {
		j := strings.Join(users, ", ")
		return errp(409, "still linked by: "+j+" (unlink it there first)", "still_linked", "users", j)
	}
	for _, e := range append([]*Entry(nil), it.Entries...) {
		if err := s.retireEntry(it, e); err != nil {
			return err
		}
	}
	rels := make([]string, 0, len(it.Files))
	for rel := range it.Files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		if err := s.retireFile(it, rel, true); err != nil {
			return err
		}
	}
	it.State = StateRetired
	return s.writeItemMeta(it)
}

// SetUses replaces the ordered list of items an environment links ("section/item").
func (s *Store) SetUses(env string, refs []string) error {
	it, err := s.item(SecEnvs, env)
	if err != nil {
		return err
	}
	var parsed []ItemKey
	for _, r := range refs {
		pr, ok := SplitRef(r)
		if !ok {
			return errp(400, "a link is section/item", "link_form")
		}
		if pr == (ItemKey{SecEnvs, env}) {
			return errp(409, "an environment cannot link itself", "link_self")
		}
		for _, q := range parsed {
			if q == pr {
				return errp(409, r+" is linked twice", "link_twice", "ref", r)
			}
		}
		li := s.Snap.Items[pr]
		if li == nil || li.State == StateRetired || !contains(s.Snap.ItemNames(pr.Section), pr.Name) {
			return errp(404, "no such item: "+r, "no_item_ref", "ref", r)
		}
		if len(li.Uses) > 0 {
			return errp(409, r+" links other items itself: links are one level, never nested", "link_nested", "ref", r)
		}
		parsed = append(parsed, pr)
	}
	if users := s.Snap.UsersOf(SecEnvs, env); len(parsed) > 0 && len(users) > 0 {
		j := strings.Join(users, ", ")
		return errp(409, "this environment is linked by "+j+": links are one level, never nested", "env_linked_by", "users", j)
	}
	it.Uses = parsed
	return s.writeItemMeta(it)
}

// ---------------------------------------------------------------- writes: groups and entries

func (s *Store) CreateGroup(section, name, group, title, description string) error {
	if _, err := s.item(section, name); err != nil {
		return err
	}
	parts := strings.Split(group, "/")
	bad := group == "" || len(parts) > MaxGroupDepth || IsReserved(parts[0])
	for _, x := range parts {
		bad = bad || !NameRE.MatchString(x)
	}
	if bad {
		return errp(400, "a group key is 1-32 characters: a-z 0-9 _ -; a subgroup is written parent/child", "group_key")
	}
	if _, err := OneLine(title, "a title", 120); err != nil {
		return err
	}
	description, err := DescriptionText(description)
	if err != nil {
		return err
	}
	if s.hasGroup(section, name, group) {
		return errp(409, "that group exists", "group_exists")
	}
	if len(parts) > 1 && !s.hasGroup(section, name, strings.Join(parts[:len(parts)-1], "/")) {
		return errp(404, "the parent group does not exist: make it first", "no_parent_group")
	}
	entry := GroupEntry(section, name, group)
	if err := s.EnsureGroupPath(entry); err != nil {
		return err
	}
	if err := func() error {
		nts, err := GroupNotes(StateActive, title, description, nil)
		if err != nil {
			return err
		}
		return s.W.Add(entry, nts, nil)
	}(); err != nil {
		return err
	}
	s.Snap.SetGroupMeta(section, name, group, &GroupMetaInfo{Title: title, Description: description, State: StateActive})
	return nil
}

func (s *Store) groupMetaOrNew(section, name, group string) (*GroupMetaInfo, bool) {
	if m := s.Snap.GroupMeta(section, name, group); m != nil {
		cp := *m
		return &cp, true
	}
	return &GroupMetaInfo{State: StateActive}, false
}

// SetGroupSites limits a group (and its subgroups) to some sites; [] = every
// site. The site need not exist yet.
func (s *Store) SetGroupSites(section, name, group string, sites []string) error {
	if _, err := s.item(section, name); err != nil {
		return err
	}
	clean, ok := validSites(sites)
	if !ok {
		return errp(400, "sites are a list of site names (a-z 0-9 _ -)", "sites_form")
	}
	if !s.hasGroup(section, name, group) {
		return errp(404, "no such group", "no_group")
	}
	meta, exists := s.groupMetaOrNew(section, name, group)
	entry := GroupEntry(section, name, group)
	notes, nerr := GroupNotes(StateActive, meta.Title, meta.Description, clean)
	if nerr != nil {
		return nerr
	}
	var err error
	if exists {
		err = s.W.SetNotes(entry, notes)
	} else {
		err = s.W.Add(entry, notes, nil)
	}
	if err != nil {
		return err
	}
	meta.State, meta.OnlySites = StateActive, clean
	s.Snap.SetGroupMeta(section, name, group, meta)
	return nil
}

func (s *Store) normalize(value string) string {
	if s.Consumer != nil {
		return s.Consumer.Normalize(value, ManagedOwner)
	}
	return value
}

func (s *Store) checkLabels(labels []string, vis string) error {
	if s.Consumer != nil {
		if err := s.Consumer.CheckLabels(labels, vis); err != nil {
			return Err(409, err.Error(), "label_refused")
		}
	}
	return nil
}

// CreateEntry makes a new variable. visibility "" = the rule of the key,
// recorded as not chosen by the owner.
func (s *Store) CreateEntry(section, name, group, key, description, visibility, value string, labels []string, visBy string) error {
	it, err := s.item(section, name)
	if err != nil {
		return err
	}
	if visibility == "" {
		visibility, visBy = VisSecret, ""
		if s.Consumer != nil {
			visibility = s.Consumer.KeyVisibility(key)
		}
	}
	if !KeyRE.MatchString(key) {
		return errp(400, "a key is letters, digits, _ . - and starts with a letter or _", "key_form")
	}
	if !ValidVis(visibility) {
		return errp(400, "visibility is plain, secret or sealed", "vis_form")
	}
	if _, err := OneLine(value, "a value", 20000); err != nil {
		return err
	}
	if description, err = DescriptionText(description); err != nil {
		return err
	}
	if labels, err = LabelsList(labels); err != nil {
		return err
	}
	if err := s.checkLabels(labels, visibility); err != nil {
		return err
	}
	if !s.hasGroup(section, name, group) {
		return errp(404, "no such group: make it first", "no_group_first")
	}
	if it.Find(group, key) != nil {
		return errp(409, "that key exists in this group", "key_exists")
	}
	if err := s.uniqueInScope(section, name, key); err != nil {
		return err
	}
	value = s.normalize(value)
	path := VarEntry(section, name, group, key)
	if err := s.EnsureGroupPath(path); err != nil {
		return err
	}
	if err := func() error {
		nts, err := EntryNotes(ManagedOwner, visibility, labels, description, visBy)
		if err != nil {
			return err
		}
		return s.W.Add(path, nts, &value)
	}(); err != nil {
		return err
	}
	it.Entries = append(it.Entries, &Entry{Key: key, Value: value, Group: group, Path: path, Managed: ManagedOwner, Vis: visibility, Title: key, Description: description,
		Labels: labels, Changed: s.Now(), VisBy: visBy})
	return nil
}

// uniqueInScope: global values: the key is unique across the whole section
// (groups are only structure); an external system: unique within the system.
func (s *Store) uniqueInScope(section, name, key string) error {
	var items []*Item
	switch section {
	case SecGlobal:
		for _, i := range s.Snap.All() {
			if i.Section == section && i.State != StateRetired {
				items = append(items, i)
			}
		}
	case SecExternal:
		it, err := s.item(section, name)
		if err != nil {
			return err
		}
		items = []*Item{it}
	default:
		return nil
	}
	for _, i := range items {
		for _, e := range i.Entries {
			if e.Key == key {
				where := i.Name + "/" + e.Group
				return errp(409, fmt.Sprintf("the key %s exists already (%s): in this part a key is unique, groups are only structure", key, where), "key_exists_scope", "where", where)
			}
		}
	}
	return nil
}

// CreateMissing creates, in the environment item, the entries the consumer's
// checklist reports as missing (empty, with the hint as description). mode:
// "required", "optional" or "all"; with a key (and its settings file) only that
// one, whatever its mode. file "" = any file.
func (s *Store) CreateMissing(env, mode, key, file string) (int, error) {
	if s.Consumer == nil {
		return 0, errp(404, "no checklist", "no_checklist")
	}
	if mode != "required" && mode != "optional" && mode != "all" {
		return 0, errp(400, "bad request", "bad_request")
	}
	it, err := s.item(SecEnvs, env)
	if err != nil {
		return 0, err
	}
	made := 0
	for _, row := range s.checklist(env, "") {
		spec := row.Create
		if row.State != "missing" || spec == nil {
			continue
		}
		if key != "" {
			if row.Key != key || (file != "" && row.File != file) {
				continue
			}
		} else if mode != "all" && row.Required != (mode == "required") {
			continue
		}
		g := spec.Group
		if !s.hasGroup(SecEnvs, env, g) {
			if err := s.CreateGroup(SecEnvs, env, g, "", ""); err != nil {
				return made, err
			}
		}
		if it.Find(g, spec.Key) == nil {
			vis := spec.Visibility
			if vis == "" {
				vis = VisSecret
			}
			if err := s.CreateEntry(SecEnvs, env, g, spec.Key, spec.Description, vis, "", spec.Labels, ""); err != nil {
				return made, err
			}
			made++
		}
	}
	return made, nil
}

func (s *Store) was(e *Entry) (string, error) {
	return WasNotes(e.Managed, e.Vis, e.Labels, e.Description)
}

func retiredInfoOf(notes, title, changed, value, description string) map[string]string {
	info := ParseNotes(notes)
	info["title"], info["changed"], info["value"], info["description"] = title, changed, value, description
	return info
}

// archiveValue: the value an owner entry is about to lose is kept: a copy in
// Retired (sealed, a dash for needed-until).
func (s *Store) archiveValue(it *Item, e *Entry) error {
	stamp := s.Now()
	title := e.Key + "@" + stamp
	dest := ItemRoot(it.Section, it.Name) + "/" + Retired + "/" + e.Group
	n := 1
	for contains(it.Retired, e.Group+"/"+title) {
		n++
		title = fmt.Sprintf("%s@%s-%d", e.Key, stamp, n)
	}
	if err := s.EnsureGroupPath(dest + "/x"); err != nil {
		return err
	}
	rn, nerr := RetiredNotes(e.Group+"/"+e.Key, SHA256([]byte(e.Value)), 0o600, stamp, "")
	if nerr != nil {
		return nerr
	}
	wn, nerr := s.was(e)
	if nerr != nil {
		return nerr
	}
	notes := rn + "\nvisibility=sealed\nretired-why=value" + wn
	v := e.Value
	if err := s.W.Add(dest+"/"+title, notes, &v); err != nil {
		return err
	}
	it.Retired = append(it.Retired, e.Group+"/"+title)
	it.RetiredInfo = append(it.RetiredInfo, retiredInfoOf(notes, e.Group+"/"+title, stamp, e.Value, e.Description))
	return nil
}

// SetValue sets the value of an owner entry; the old non-empty value is archived.
func (s *Store) SetValue(section, name, group, key, value string) error {
	if _, err := OneLine(value, "a value", 20000); err != nil {
		return err
	}
	it, e, err := s.find(section, name, group, key)
	if err != nil {
		return err
	}
	if err := OwnerOnly(e); err != nil {
		return err
	}
	nv := s.normalize(value)
	if e.Value != "" && e.Value != nv {
		if err := s.archiveValue(it, e); err != nil {
			return err
		}
	}
	if err := s.W.SetPassword(e.Path, nv); err != nil {
		return err
	}
	e.Value, e.Changed, e.Ref = nv, s.Now(), false
	return nil
}

// GenerateValue is a generated value for the page to put into a field. With an
// entry named (key != ""), only an owner-managed one may get it.
func (s *Store) GenerateValue(length int, alphabet, section, name, group, key string) (string, error) {
	if key != "" {
		_, e, err := s.find(section, name, group, key)
		if err != nil {
			return "", err
		}
		if err := OwnerOnly(e); err != nil {
			return "", err
		}
	}
	return Generate(length, alphabet)
}

// GenerateInto generates a value, stores it for the entry and seals it. The
// value never leaves: the answer is only its length and alphabet.
func (s *Store) GenerateInto(section, name, group, key string, length int, alphabet string) error {
	value, err := Generate(length, alphabet)
	if err != nil {
		return err
	}
	_, e, err := s.find(section, name, group, key)
	if err != nil {
		return err
	}
	if err := OwnerOnly(e); err != nil {
		return err
	}
	if err := s.SetValue(section, name, group, key, value); err != nil {
		return err
	}
	if e.Vis != VisSealed {
		v := VisSealed
		return s.UpdateMeta(section, name, group, key, MetaChange{Visibility: &v})
	}
	return nil
}

// MetaChange is a partial change of an entry (nil = keep).
type MetaChange struct {
	Description *string
	ToGroup     *string
	Visibility  *string
	Labels      *[]string
}

// UpdateMeta changes description, group, visibility or labels of an owner entry.
func (s *Store) UpdateMeta(section, name, group, key string, c MetaChange) error {
	it, e, err := s.find(section, name, group, key)
	if err != nil {
		return err
	}
	if err := OwnerOnly(e); err != nil {
		return err
	}
	vis, visBy := e.Vis, e.VisBy
	if c.Visibility != nil && *c.Visibility != vis {
		if !ValidVis(*c.Visibility) {
			return errp(400, "visibility is plain, secret or sealed", "vis_form")
		}
		if vis == VisSealed {
			return errp(409, "sealed cannot be undone: replace the value to change it", "seal_final")
		}
		vis, visBy = *c.Visibility, ManagedOwner
	}
	labels := e.Labels
	if c.Labels != nil {
		if labels, err = LabelsList(*c.Labels); err != nil {
			return err
		}
	}
	if err := s.checkLabels(labels, vis); err != nil {
		return err
	}
	desc := e.Description
	if c.Description != nil {
		if desc, err = DescriptionText(*c.Description); err != nil {
			return err
		}
	}
	moved := false
	if c.ToGroup != nil && *c.ToGroup != e.Group {
		if !s.hasGroup(section, name, *c.ToGroup) {
			return errp(404, "no such group", "no_group")
		}
		if it.Find(*c.ToGroup, key) != nil {
			return errp(409, "that key exists in the other group", "key_exists_other")
		}
		moved = true
	}
	notes, nerr := EntryNotesSet(ManagedOwner, vis, labels, desc, visBy, e.ManagedSet)
	if nerr != nil {
		return nerr
	}
	if err := s.W.SetNotes(e.Path, notes); err != nil {
		return err
	}
	if moved {
		dest := ItemRoot(section, name) + "/" + *c.ToGroup
		if err := s.EnsureGroupPath(dest + "/x"); err != nil {
			return err
		}
		if err := s.W.Move(e.Path, dest); err != nil {
			return err
		}
		e.Path, e.Group = dest+"/"+key, *c.ToGroup
	}
	e.Notes, e.Vis, e.VisBy, e.Description, e.Labels, e.Changed = notes, vis, visBy, desc, labels, s.Now()
	return nil
}

// SetManaged is the owner re-classifying a variable by hand: managed-by owner
// or system. It is the one write a system entry takes in the screen (it is how
// the owner makes it editable again). rule is what the automatic rule gives the
// entry ("" when there is none): a choice equal to it drops the managed-set
// mark, so the entry follows the rule again; any other choice records the mark
// and the automatic correction leaves the entry alone from then on. Only the
// notes change, never the value.
func (s *Store) SetManaged(section, name, group, key, managed, rule string) error {
	if managed != ManagedOwner && managed != ManagedSystem {
		return errp(400, "managed-by is owner or system", "managed_form")
	}
	if section != SecEnvs && section != SecSites {
		return errp(403, "only the variables of an environment or a site have a rule for who manages them", "managed_section")
	}
	_, e, err := s.find(section, name, group, key)
	if err != nil {
		return err
	}
	mark := ManagedOwner
	if rule != "" && managed == rule {
		mark = ""
	}
	if managed == e.Managed && mark == e.ManagedSet {
		return nil
	}
	notes, nerr := EntryNotesSet(managed, e.Vis, e.Labels, e.Description, e.VisBy, mark)
	if nerr != nil {
		return nerr
	}
	if err := s.W.SetNotes(e.Path, notes); err != nil {
		return err
	}
	e.Notes, e.Managed, e.ManagedSet, e.Changed = notes, managed, mark, s.Now()
	return nil
}

// RewriteManaged is the automatic correction of who manages an entry: managed-by
// owner <-> system in the notes, every other line kept, the value untouched.
// The caller has checked the rule and the owner's mark.
func (s *Store) RewriteManaged(e *Entry, managed string) error {
	if (managed != ManagedOwner && managed != ManagedSystem) || (e.Managed != ManagedOwner && e.Managed != ManagedSystem) {
		return errp(400, "managed-by is owner or system", "managed_form")
	}
	notes, err := EntryNotesSet(managed, e.Vis, e.Labels, e.Description, e.VisBy, e.ManagedSet)
	if err != nil {
		return err
	}
	if err := s.W.SetNotes(e.Path, notes); err != nil {
		return err
	}
	e.Notes, e.Managed = notes, managed
	return nil
}

// Seal makes a value sealed (one way).
func (s *Store) Seal(section, name, group, key string) error {
	v := VisSealed
	return s.UpdateMeta(section, name, group, key, MetaChange{Visibility: &v})
}

// RenameGroup changes the title and/or description of a group (nil = keep).
func (s *Store) RenameGroup(section, name, group string, title, description *string) error {
	if _, err := s.item(section, name); err != nil {
		return err
	}
	if !s.hasGroup(section, name, group) {
		return errp(404, "no such group", "no_group")
	}
	meta, exists := s.groupMetaOrNew(section, name, group)
	t, d := meta.Title, meta.Description
	var err error
	if title != nil {
		if t, err = OneLine(*title, "a title", 120); err != nil {
			return err
		}
	}
	if description != nil {
		if d, err = DescriptionText(*description); err != nil {
			return err
		}
	}
	entry := GroupEntry(section, name, group)
	notes, nerr := GroupNotes(StateActive, t, d, meta.OnlySites)
	if nerr != nil {
		return nerr
	}
	if exists {
		err = s.W.SetNotes(entry, notes)
	} else {
		err = s.W.Add(entry, notes, nil)
	}
	if err != nil {
		return err
	}
	s.Snap.SetGroupMeta(section, name, group, &GroupMetaInfo{Title: t, Description: d, State: StateActive, OnlySites: meta.OnlySites})
	return nil
}

// ---- retire: nothing is deleted

func (s *Store) retireEntry(it *Item, e *Entry) error {
	stamp := s.Now()
	root := ItemRoot(it.Section, it.Name)
	title := e.Key + "@" + stamp
	dest := root + "/" + Retired + "/" + e.Group
	if err := s.EnsureGroupPath(dest + "/x"); err != nil {
		return err
	}
	if err := s.W.SetTitle(e.Path, title); err != nil {
		return err
	}
	parent := e.Path[:strings.LastIndex(e.Path, "/")]
	if err := s.W.Move(parent+"/"+title, dest); err != nil {
		return err
	}
	rn, nerr := RetiredNotes(e.Group+"/"+e.Key, SHA256([]byte(e.Value)), 0o600, stamp, "")
	if nerr != nil {
		return nerr
	}
	wn, nerr := s.was(e)
	if nerr != nil {
		return nerr
	}
	notes := rn + "\nvisibility=sealed\nretired-why=entry" + wn
	if err := s.W.SetNotes(dest+"/"+title, notes); err != nil {
		return err
	}
	for i, x := range it.Entries {
		if x == e {
			it.Entries = append(it.Entries[:i], it.Entries[i+1:]...)
			break
		}
	}
	it.Retired = append(it.Retired, e.Group+"/"+title)
	it.RetiredInfo = append(it.RetiredInfo, retiredInfoOf(notes, e.Group+"/"+title, stamp, e.Value, e.Description))
	return nil
}

// RetireEntry moves an owner entry to retired/ (never deletes).
func (s *Store) RetireEntry(section, name, group, key string, confirm bool) error {
	it, e, err := s.find(section, name, group, key)
	if err != nil {
		return err
	}
	if err := OwnerOnly(e); err != nil {
		return err
	}
	if err := s.RefuseIfReferenced(section, name, []string{key}); err != nil {
		return err
	}
	if err := s.needsConfirm(section, name, []string{key}, confirm, "this entry"); err != nil {
		return err
	}
	return s.retireEntry(it, e)
}

// RetireGroup moves every entry of a group to retired/ and marks the group retired.
func (s *Store) RetireGroup(section, name, group string, confirm bool) error {
	it, err := s.item(section, name)
	if err != nil {
		return err
	}
	if !s.hasGroup(section, name, group) {
		return errp(404, "no such group", "no_group")
	}
	var members []*Entry
	var keys []string
	for _, e := range it.Entries {
		if e.Group == group {
			members = append(members, e)
			keys = append(keys, e.Key)
		}
	}
	for _, e := range members {
		if e.Managed != ManagedOwner {
			return errp(403, fmt.Sprintf("the group holds %s, managed by the system: it cannot be archived", e.Key), "group_system", "key", e.Key)
		}
	}
	if err := s.RefuseIfReferenced(section, name, keys); err != nil {
		return err
	}
	if err := s.needsConfirm(section, name, keys, confirm, "the group"); err != nil {
		return err
	}
	for _, e := range members {
		if err := s.retireEntry(it, e); err != nil {
			return err
		}
	}
	meta := s.Snap.GroupMeta(section, name, group)
	title := ""
	var sites []string
	if meta != nil {
		title, sites = meta.Title, meta.OnlySites
	}
	notes, nerr := GroupNotes(StateRetired, title, "", sites)
	if nerr != nil {
		return nerr
	}
	if meta != nil {
		err = s.W.SetNotes(GroupEntry(section, name, group), notes)
	} else {
		err = s.W.Add(GroupEntry(section, name, group), notes, nil)
	}
	if err != nil {
		return err
	}
	nm := GroupMetaInfo{State: StateRetired, OnlySites: sites, Title: title}
	if meta != nil {
		nm.Description = meta.Description
	}
	s.Snap.SetGroupMeta(section, name, group, &nm)
	return nil
}

// LegacyOwner is the needed-until text old retired owner entries carry.
const LegacyOwner = "the data or the cluster it served is gone"

// RetiredRow is a line of the Archive tab.
type RetiredRow struct {
	Why, Name, RetiredAt, NeededUntil, Title string
	Owner, Restorable, Exists                bool
}

// RetiredRowOf describes one retired entry. An owner entry can come back
// (Restorable) unless its key is live again (Exists); a system one is kept for the commands.
func (s *Store) RetiredRowOf(it *Item, r map[string]string) RetiredRow {
	frm := r["retired-from"]
	def := ManagedSystem
	if nu := r["needed-until"]; nu == "" || nu == LegacyOwner {
		def = ManagedOwner
	}
	was, ok := r["was-managed"]
	if !ok {
		was = def
	}
	owner := was == ManagedOwner
	i := strings.LastIndex(frm, "/")
	group, key := "", frm
	if i >= 0 {
		group, key = frm[:i], frm[i+1:]
	}
	live := frm != "" && it.Find(group, key) != nil
	until := r["needed-until"]
	if until == LegacyOwner {
		until = ""
	}
	name := frm
	if name == "" {
		name = r["title"]
	}
	return RetiredRow{Why: r["retired-why"], Name: name, RetiredAt: r["retired-at"], NeededUntil: until, Title: r["title"], Owner: owner, Restorable: owner && frm != "" && !live, Exists: live}
}

// RestoreEntry brings an archived OWNER entry back where it was, as it was.
func (s *Store) RestoreEntry(section, name, title string) error {
	it, err := s.item(section, name)
	if err != nil {
		return err
	}
	var info map[string]string
	idx := -1
	for i, r := range it.RetiredInfo {
		if r["title"] == title {
			info, idx = r, i
			break
		}
	}
	if info == nil || !strings.Contains(title, "@") {
		return errp(404, "no such entry", "no_entry")
	}
	row := s.RetiredRowOf(it, info)
	if !row.Owner {
		return errp(403, "managed by the system: read-only", "system_managed")
	}
	frm := info["retired-from"]
	cut := strings.LastIndex(frm, "/")
	group, key := frm[:max(cut, 0)], frm[cut+1:]
	if it.Find(group, key) != nil {
		return errp(409, "that key exists in this group", "restore_exists")
	}
	root := ItemRoot(section, name)
	sc := strings.LastIndex(title, "/")
	srcGroup, srcTitle := "", title
	if sc >= 0 {
		srcGroup, srcTitle = title[:sc], title[sc+1:]
	}
	if !s.hasGroup(section, name, group) {
		if err := s.CreateGroup(section, name, group, "", ""); err != nil {
			return err
		}
	}
	labels := ParseLabels(info["was-labels"])
	vis := info["was-visibility"]
	if !ValidVis(vis) {
		vis = VisSecret
	}
	if err := s.W.SetTitle(root+"/"+Retired+"/"+srcGroup+"/"+srcTitle, key); err != nil {
		return err
	}
	if err := s.W.Move(root+"/"+Retired+"/"+srcGroup+"/"+key, root+"/"+group); err != nil {
		return err
	}
	notes, nerr := EntryNotes(ManagedOwner, vis, labels, info["description"], "")
	if nerr != nil {
		return nerr
	}
	if err := s.W.SetNotes(root+"/"+group+"/"+key, notes); err != nil {
		return err
	}
	it.Entries = append(it.Entries, &Entry{Key: key, Value: info["value"], Group: group, Path: root + "/" + group + "/" + key, Managed: ManagedOwner, Vis: vis, Title: key,
		Notes: notes, Description: info["description"], Labels: labels, Changed: s.Now()})
	for i, t := range it.Retired {
		if t == title {
			it.Retired = append(it.Retired[:i], it.Retired[i+1:]...)
			break
		}
	}
	it.RetiredInfo = append(it.RetiredInfo[:idx], it.RetiredInfo[idx+1:]...)
	return nil
}

// ---- files

func validRel(rel string) error {
	bad := rel == "" || strings.HasPrefix(rel, "/") || len(rel) > 200
	for _, p := range strings.Split(rel, "/") {
		bad = bad || !PathPart.MatchString(p)
	}
	if bad {
		return errp(400, "a path of names (letters, digits, . _ -) separated by /", "path_form")
	}
	return nil
}

func validData(data []byte) error {
	if len(data) == 0 || len(data) > 10_000_000 {
		return errp(400, "a file of 1 byte to 10 MB", "file_size")
	}
	return nil
}

func (s *Store) CreateFile(section, name, rel string, data []byte) error {
	it, err := s.item(section, name)
	if err != nil {
		return err
	}
	if err := validRel(rel); err != nil {
		return err
	}
	if err := validData(data); err != nil {
		return err
	}
	if _, ok := it.Files[rel]; ok {
		return errp(409, "that file exists: replace it", "file_exists")
	}
	entry := FileEntryPath(section, name, rel)
	if err := s.EnsureGroupPath(entry); err != nil {
		return err
	}
	if err := func() error {
		nts, err := PendingFileNotes(rel, ManagedOwner)
		if err != nil {
			return err
		}
		return s.W.Add(entry, nts, nil)
	}(); err != nil {
		return err
	}
	if err := s.W.Attach(entry, data, false); err != nil {
		return err
	}
	sha := SHA256(data)
	now := s.Now()
	if err := func() error {
		nts, err := FileNotes(rel, sha, 0o600, now, ManagedOwner, VisSealed)
		if err != nil {
			return err
		}
		return s.W.SetNotes(entry, nts)
	}(); err != nil {
		return err
	}
	it.Files[rel] = &FileEntry{Data: data, Mode: 0o600, Sha: sha, Managed: ManagedOwner, Changed: now, Vis: VisSealed, Scope: ItemKey{section, name}}
	return nil
}

func (s *Store) ReplaceFile(section, name, rel string, data []byte) error {
	it, err := s.item(section, name)
	if err != nil {
		return err
	}
	fe := it.Files[rel]
	if fe == nil {
		return errp(404, "no such file", "no_file")
	}
	if fe.Managed != ManagedOwner {
		return errp(403, "managed by the system: read-only", "system_managed")
	}
	if err := validData(data); err != nil {
		return err
	}
	entry := FileEntryPath(section, name, rel)
	if err := s.W.Attach(entry, data, true); err != nil {
		return err
	}
	sha := SHA256(data)
	now := s.Now()
	if err := func() error {
		nts, err := FileNotes(rel, sha, fe.Mode, now, ManagedOwner, VisSealed)
		if err != nil {
			return err
		}
		return s.W.SetNotes(entry, nts)
	}(); err != nil {
		return err
	}
	fe.Data, fe.Sha, fe.Changed = data, sha, now
	return nil
}

func (s *Store) retireFile(it *Item, rel string, force bool) error {
	fe := it.Files[rel]
	if fe == nil {
		return errp(404, "no such file", "no_file")
	}
	if !force && fe.Managed != ManagedOwner {
		return errp(403, "managed by the system: read-only", "system_managed")
	}
	root, stamp := ItemRoot(it.Section, it.Name), s.Now()
	title := strings.ReplaceAll(rel, "/", "~") + "@" + stamp
	src := root + "/" + Files + "/" + rel
	where := ""
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		where = rel[:i]
	}
	dest := root + "/" + Retired
	if err := s.EnsureGroupPath(dest + "/x"); err != nil {
		return err
	}
	if err := s.W.SetTitle(src, title); err != nil {
		return err
	}
	prefix := ""
	if where != "" {
		prefix = where + "/"
	}
	if err := s.W.Move(root+"/"+Files+"/"+prefix+title, dest); err != nil {
		return err
	}
	rn, nerr := RetiredNotes(rel, fe.Sha, fe.Mode, stamp, LegacyOwner)
	if nerr != nil {
		return nerr
	}
	notes := rn + "\nvisibility=sealed"
	if err := s.W.SetNotes(dest+"/"+title, notes); err != nil {
		return err
	}
	delete(it.Files, rel)
	it.Retired = append(it.Retired, title)
	info := ParseNotes(notes)
	info["title"], info["changed"] = title, stamp
	it.RetiredInfo = append(it.RetiredInfo, info)
	return nil
}

func (s *Store) RetireFile(section, name, rel string) error {
	it, err := s.item(section, name)
	if err != nil {
		return err
	}
	return s.retireFile(it, rel, false)
}

// RetireEntryRaw moves an entry to retired/ without the owner, reference and
// checklist checks (for the callers that already did them: scope moves).
func (s *Store) RetireEntryRaw(it *Item, e *Entry) error { return s.retireEntry(it, e) }
