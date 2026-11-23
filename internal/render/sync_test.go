package render

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cybericebox/icevault/internal/model"
)

// ---- an in-memory vault: the Writer of the tests. It keeps entries and groups
// like KeePass does (an entry needs its group, a title is the last path part) and
// hands out Snapshots, so an import can be checked end to end: import, read the
// vault back, render, compare with the files that went in.

type kpEntry struct {
	pw, notes string
	att       []byte
	hasAtt    bool
}

type memVault struct {
	t      *testing.T
	groups map[string]bool
	ents   map[string]*kpEntry
	writes int
}

func newMemVault(t *testing.T) *memVault {
	return &memVault{t: t, groups: map[string]bool{}, ents: map[string]*kpEntry{}}
}

func parent(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}

func (m *memVault) Mkdir(g string) error {
	m.writes++
	if m.groups[g] {
		return fmt.Errorf("group exists: %s", g)
	}
	if par := parent(g); par != "" && !m.groups[par] {
		return fmt.Errorf("no parent group for %s", g)
	}
	m.groups[g] = true
	return nil
}

func (m *memVault) Add(e, notes string, pw *string) error {
	m.writes++
	if m.ents[e] != nil {
		return fmt.Errorf("entry exists: %s", e)
	}
	if !m.groups[parent(e)] {
		return fmt.Errorf("no group for entry %s", e)
	}
	ent := &kpEntry{notes: notes}
	if pw != nil {
		ent.pw = *pw
	}
	m.ents[e] = ent
	return nil
}

func (m *memVault) get(e string) (*kpEntry, error) {
	ent := m.ents[e]
	if ent == nil {
		return nil, fmt.Errorf("no such entry: %s", e)
	}
	return ent, nil
}

func (m *memVault) SetPassword(e, pw string) error {
	m.writes++
	ent, err := m.get(e)
	if err == nil {
		ent.pw = pw
	}
	return err
}
func (m *memVault) SetNotes(e, n string) error {
	m.writes++
	ent, err := m.get(e)
	if err == nil {
		ent.notes = n
	}
	return err
}
func (m *memVault) Remove(e string) error {
	m.writes++
	if _, err := m.get(e); err != nil {
		return err
	}
	delete(m.ents, e)
	return nil
}
func (m *memVault) Move(e, g string) error {
	m.writes++
	ent, err := m.get(e)
	if err != nil {
		return err
	}
	if !m.groups[g] {
		return fmt.Errorf("no group %s", g)
	}
	dest := g + "/" + e[strings.LastIndex(e, "/")+1:]
	if m.ents[dest] != nil {
		return fmt.Errorf("entry exists: %s", dest)
	}
	delete(m.ents, e)
	m.ents[dest] = ent
	return nil
}
func (m *memVault) SetTitle(e, title string) error {
	m.writes++
	ent, err := m.get(e)
	if err != nil {
		return err
	}
	dest := parent(e) + "/" + title
	if m.ents[dest] != nil {
		return fmt.Errorf("entry exists: %s", dest)
	}
	delete(m.ents, e)
	m.ents[dest] = ent
	return nil
}
func (m *memVault) Attach(e string, data []byte, force bool) error {
	m.writes++
	ent, err := m.get(e)
	if err != nil {
		return err
	}
	if ent.hasAtt && !force {
		return fmt.Errorf("attachment exists: %s", e)
	}
	ent.att, ent.hasAtt = append([]byte{}, data...), true
	return nil
}

// snap reads the vault back, as every unlock does.
func (m *memVault) snap() *model.Snapshot {
	s := model.NewSnapshot()
	for g := range m.groups {
		s.AddGroup(g)
	}
	paths := make([]string, 0, len(m.ents))
	for p := range m.ents {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		parts := strings.Split(p, "/")
		if parts[0] != model.Group || len(parts) < 2 {
			continue
		}
		e := m.ents[p]
		if err := s.Ingest(model.RawEntry{Path: parts[1 : len(parts)-1], Title: parts[len(parts)-1], Notes: e.notes, Password: e.pw, Attachment: e.att}); err != nil {
			m.t.Fatal(err)
		}
	}
	return s
}

func (m *memVault) reset() int { n := m.writes; m.writes = 0; return n }

// ---- fixtures: a plaintext tree of the test project

const (
	secretValue = "S3CRET-VALUE-must-never-be-printed"
	imWeb       = "# Web settings.\n# Everything the web needs.\n\n# the base domain; every host derives from it\nBASE_HOST=example.org\n" +
		"OWNER_EMAIL=\"owner@example.org\"   # REQUIRED: replace\nCOOKIE_SECRET=" + secretValue + "\nNAME_WITH_SPACE=\"two words\"\nEMPTY_ONE=\n#COMMENTED_OUT=1\n\nOTHER='single quoted'\n"
	imAPI    = "# api\nAPI_REPLICAS=2\nAPI_NAME=demo\n"
	imDNS    = "DNS_API_TOKEN=dns-token-value\nDNS_ACCOUNT_ID=acc\n"
	imGoogle = "POOL_NAME=shop\nZONE=europe-west4\n"
)

type tree map[string]*fstest.MapFile

func (tr tree) put(rel, data string, mode int) {
	tr[rel] = &fstest.MapFile{Data: []byte(data), Mode: fileMode(mode)}
}

func populate() tree {
	tr := tree{}
	tr.put("apps/web.env", imWeb, 0o600)
	tr.put("apps/api.env", imAPI, 0o600)
	tr.put("net/dns.env", imDNS, 0o600)
	tr.put("cloud/gcp-site.env", imGoogle, 0o600)
	tr.put("made/google/keys/signing/k1.key", strings.Repeat("ab", 32)+"\n", 0o400)
	tr.put("made/google/keys/signing/CURRENT", "k1\n", 0o400)
	tr.put("made/google/keys/session-secret", secretValue, 0o600)
	tr.put("made/google/account/credentials.json", `{"private_key": "x"}`, 0o600)
	tr.put("made/google/kubeconfig.yaml", "kube: "+secretValue, 0o600)
	tr.put("made/google/keys/edge-send-next", "", 0o600)
	return tr
}

func (tr tree) src() Source { return FSSource{fstest.MapFS(tr)} }

// kept is the secret-bearing part of a tree: rel -> data and mode.
func (tr tree) kept() map[string]string {
	out := map[string]string{}
	for rel, f := range tr {
		if k, _ := proj().Classify(rel); k != "" {
			out[rel] = fmt.Sprintf("%o|%s", f.Mode.Perm(), f.Data)
		}
	}
	return out
}

func rendered(t *testing.T, p *Project, snap *model.Snapshot, env, site string, conf bool) map[string]string {
	t.Helper()
	files, err := p.Render(snap, env, site, conf)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range files {
		out[f.Rel] = fmt.Sprintf("%o|%s", f.Mode, f.Data)
	}
	return out
}

func equalMaps(t *testing.T, got, want map[string]string, what string) {
	t.Helper()
	var diff []string
	for k, v := range want {
		if g, ok := got[k]; !ok {
			diff = append(diff, "missing "+k)
		} else if g != v {
			diff = append(diff, "differs "+k)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			diff = append(diff, "extra "+k)
		}
	}
	sort.Strings(diff)
	if len(diff) > 0 {
		t.Errorf("%s: %s", what, strings.Join(diff, "; "))
	}
}

type run struct {
	t  *testing.T
	p  *Project
	mv *memVault
}

func newRun(t *testing.T) *run { return &run{t, proj(), newMemVault(t)} }

func (r *run) snap() *model.Snapshot { return r.mv.snap() }

var fixedNow = func() string { return "2026-03-04T05:06:07Z" }

func (r *run) imp(env string, tr tree, mut func(*Options)) ([]string, *Report, error) {
	r.t.Helper()
	o := Options{Env: env, Tree: tr.src(), Now: fixedNow}
	if mut != nil {
		mut(&o)
	}
	rep, out, err := r.p.ImportTree(r.mv, r.snap(), o, "the tree")
	return out, rep, err
}

func (r *run) mustImport(env string, tr tree, mut func(*Options)) string {
	r.t.Helper()
	out, _, err := r.imp(env, tr, mut)
	if err != nil {
		r.t.Fatalf("import: %v", err)
	}
	return strings.Join(out, "\n")
}

func withConf(text string) func(*Options) {
	return func(o *Options) { o.Extra = map[string][]byte{"base.env": []byte(text)} }
}

func contains2(t *testing.T, text, want string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Errorf("output lacks %q:\n%s", want, text)
	}
}

func varsOf(snap *model.Snapshot, section, name string) map[string]string {
	out := map[string]string{}
	if it := snap.Item(section, name); it != nil {
		for _, e := range it.Entries {
			out[e.Key] = e.Value
		}
	}
	return out
}

// ---------------------------------------------------------------- import and render

func TestImportRendersTheTreeByteForByteWithModes(t *testing.T) {
	r := newRun(t)
	tr := populate()
	out := r.mustImport("staging", tr, withConf("HOSTING=google\n"))
	contains2(t, out, "imported: 11 new, 0 changed; 0 unchanged")
	snap := r.snap()
	got := rendered(t, r.p, snap, "staging", "", false)
	equalMaps(t, got, tr.kept(), "the rendered tree")
	if _, ok := varsOf(snap, "environments", "staging")["DNS_API_TOKEN"]; !ok {
		t.Error("every variable goes into the environment item (the writer of the model places it)")
	}
	conf := rendered(t, r.p, snap, "staging", "", true)["base.env"]
	eq(t, conf, "600|HOSTING=google\n", "the general file")
}

func TestImportAgainChangesNothing(t *testing.T) {
	r := newRun(t)
	tr := populate()
	r.mustImport("staging", tr, withConf("HOSTING=google\n"))
	r.mv.reset()
	out := r.mustImport("staging", tr, withConf("HOSTING=google\n"))
	contains2(t, out, "0 new, 0 changed; 11 unchanged")
	eq(t, r.mv.reset(), 0, "no write to the vault")
}

func TestImportDryRunWritesNothingAndNamesWhatItWouldDo(t *testing.T) {
	r := newRun(t)
	out := r.mustImport("staging", populate(), func(o *Options) { o.DryRun = true })
	contains2(t, out, "would import: 10 new, 0 changed; 0 unchanged")
	eq(t, r.mv.reset(), 0, "no write")
	if len(r.mv.ents) != 0 || len(r.mv.groups) != 0 {
		t.Error("the vault is untouched")
	}
}

func TestChangedSystemVariableAndKeyFileAreTheOnlyWritesAndOldValuesAreRetired(t *testing.T) {
	r := newRun(t)
	tr := populate()
	r.mustImport("staging", tr, withConf("HOSTING=google\n"))
	tr.put("apps/web.env", strings.Replace(imWeb, secretValue, "rotated-session-value", 1), 0o600)
	tr.put("made/google/keys/session-secret", "new-secret", 0o600)
	out := r.mustImport("staging", tr, withConf("HOSTING=google\n"))
	contains2(t, out, "2 changed")
	contains2(t, out, "edit COOKIE_SECRET")
	contains2(t, out, "replaced system value(s) kept as retired")
	equalMaps(t, rendered(t, r.p, r.snap(), "staging", "", false), tr.kept(), "the rendered tree follows")
}

func TestOwnerEntryThatDiffersIsReportedAndLeftAlone(t *testing.T) {
	r := newRun(t)
	tr := populate()
	r.mustImport("staging", tr, nil)
	tr.put("apps/web.env", strings.Replace(imWeb, "BASE_HOST=example.org", "BASE_HOST=other.example", 1), 0o600)
	out := r.mustImport("staging", tr, nil)
	contains2(t, out, "1 owner entry(ies) differ from the file and were left as they are")
	eq(t, varsOf(r.snap(), "environments", "staging")["BASE_HOST"], "example.org", "the owner's value stays")
}

func TestPlaceholderAndEmptyValueAreEntriesWithAnEmptyPassword(t *testing.T) {
	r := newRun(t)
	tr := tree{}
	tr.put("cloud/gcp-site.env", "POOL_NAME=CHANGE-ME\nZONE=<fill in>\n", 0o600)
	r.mustImport("staging", tr, nil)
	v := varsOf(r.snap(), "environments", "staging")
	eq(t, []string{v["POOL_NAME"], v["ZONE"]}, []string{"", ""}, "placeholders are empty")
}

func TestImportNeedsFilesAndBadInputsAreRefused(t *testing.T) {
	r := newRun(t)
	if _, _, err := r.imp("staging", tree{}, nil); err == nil || !strings.Contains(err.Error(), "holds no secret files") {
		t.Errorf("an empty tree: %v", err)
	}
	if _, _, err := r.imp("Bad Name", populate(), nil); err == nil {
		t.Error("a bad environment name")
	}
	if _, _, err := r.imp("staging", populate(), func(o *Options) { o.Site = "Bad Site" }); err == nil {
		t.Error("a bad site name")
	}
}

func TestImportExtraFile(t *testing.T) {
	r := newRun(t)
	lines, did, err := ImportExtra(r.mv, r.snap(), "dump.sql", []byte("select 1;"), 0o600, false, fixedNow)
	if err != nil || !did || !strings.Contains(lines[0], "new") {
		t.Fatalf("%v %v %v", lines, did, err)
	}
	lines, did, _ = ImportExtra(r.mv, r.snap(), "dump.sql", []byte("select 1;"), 0o600, false, fixedNow)
	if did || !strings.Contains(lines[0], "1 unchanged") {
		t.Fatalf("%v %v", lines, did)
	}
}
