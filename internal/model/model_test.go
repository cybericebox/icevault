package model

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// row is one vault entry of a fixture: the path below IceVault, the title,
// the password and the notes.
type row struct{ path, title, pw, notes string }

const own = "managed-by=owner\nvisibility="

func snapOf(t *testing.T, rows ...row) *Snapshot {
	t.Helper()
	s := NewSnapshot()
	for _, r := range rows {
		parts := strings.Split(r.path, "/")
		for i := 1; i <= len(parts); i++ {
			s.AddGroup(Group + "/" + strings.Join(parts[:i], "/"))
		}
		if err := s.Ingest(RawEntry{Path: parts, Title: r.title, Notes: r.notes, Password: r.pw}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func baseRows(extra ...row) []row {
	rows := []row{
		{"environments/prod", ".item", "", "state=active"},
		{"environments/prod/web", "PUBLIC_HOST", "https://${{ shared.HOST }}/api", own + "plain"},
		{"environments/prod/web", "SVC_TOKEN", "${{ dns.API }}", own + "plain"},
		{"environments/prod/web", "LIT", "$${{ shared.HOST }}", own + "plain"},
		{"environments/prod/web", "BAD", "${{ nothing.X }} and ${{ shared.MISSING }}", own + "plain"},
		{"environments/prod/web", "PLAIN", "x", own + "plain"},
		{"global/main", ".item", "", "state=active"},
		{"global/main/net", "HOST", "example.org", own + "plain"},
		{"global/main/net/deep/er", "PORT", "8443", own + "plain"},
		{"global/main/net/deep", ".group", "", "state=active\ntitle=Deep"},
		{"external/dns", ".item", "", "state=active\nonly-sites=aws-main,aws-eu"},
		{"external/dns/account", "API", "cf-token-value", own + "secret"},
		{"external/dns/account", "ZONE", "zone-1", own + "plain"},
		{"external/hcp", ".item", "", "state=active"},
		{"external/hcp/org", "SVC_TOKEN", "hcp-token", own + "sealed"},
		{"sites/aws-main", ".item", "", "state=active\nsite-type=aws"},
		{"sites/aws-main/credentials", "TARGET_ZONE", "eu-west-1", own + "plain"},
	}
	return append(rows, extra...)
}

func eq(t *testing.T, got, want any, what string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: got %#v, want %#v", what, got, want)
	}
}

func TestParsing(t *testing.T) {
	// test_groups_nest_to_any_depth_and_site_notes_are_read
	s := snapOf(t, baseRows(row{"environments/prod/cluster", ".group", "", "state=active\nonly-sites=aws-main"},
		row{"environments/prod/cluster/etcd", "ETCD_KEY", "k", own + "secret"})...)
	groups := map[string]string{}
	for _, e := range s.Item("global", "main").Entries {
		groups[e.Key] = e.Group
	}
	eq(t, groups, map[string]string{"HOST": "net", "PORT": "net/deep/er"}, "groups")
	eq(t, s.GroupMeta("global", "main", "net/deep").Title, "Deep", "group title")
	eq(t, s.GroupMeta("environments", "prod", "cluster").OnlySites, []string{"aws-main"}, "group sites")
	eq(t, s.GroupSites("environments", "prod", "cluster/etcd"), []string{"aws-main"}, "subgroup inherits")
	eq(t, s.Item("external", "dns").OnlySites, []string{"aws-main", "aws-eu"}, "item sites")
	eq(t, s.Item("sites", "aws-main").SiteType, "aws", "site type")
}

func TestNotesRoundTrip(t *testing.T) {
	// test_item_and_group_notes_round_trip
	it := NewItem("external", "cf")
	it.OnlySites, it.Title = []string{"a", "b"}, "CF"
	eq(t, nn(ItemNotes(it)), "title=CF\nonly-sites=a,b\nstate=active", "item notes")
	eq(t, nn(GroupNotes("active", "T", "d", []string{"x"})), "state=active\ntitle=T\nonly-sites=x\nd", "group notes")
	eq(t, nn(EntryNotes("owner", "plain", []string{"a", "b"}, "desc", "owner")), "managed-by=owner\nvisibility=plain\nvis-by=owner\nlabels=a,b\ndesc", "entry notes")
	eq(t, nn(SectionNotes("T", 3, true, "active")), "state=active\ntitle=T\norder=3\nsystem=yes", "section notes")
}

func TestNotesParsing(t *testing.T) {
	n := ParseNotes("managed-by=owner\nvisibility=plain\nvisibility=secret\nfree text = here")
	eq(t, n["visibility"], "plain", "first line of a key wins")
	eq(t, HintOf("managed-by=owner\nlabels=a\nthe description\nnot=machine"), "the description\nnot=machine", "hint")
	eq(t, SafeVisibility("", "system"), "sealed", "system default")
	eq(t, SafeVisibility("visibility=weird", "owner"), "secret", "owner default")
	eq(t, SafeVisibility("visibility=plain", "system"), "plain", "stated")
	eq(t, ParseLabels(" a, ,b ,"), []string{"a", "b"}, "labels")
	if _, err := CheckLabels([]string{"ok", "bad label"}); err == nil {
		t.Error("a label with a space must be refused")
	}
	if _, err := CheckLabels(make([]string, 9)); err == nil {
		t.Error("nine labels must be refused")
	}
	got, _ := CheckLabels([]string{"a", "a", "b:c"})
	eq(t, got, []string{"a", "b:c"}, "dedupe")
}

func TestStorePaths(t *testing.T) {
	// test_the_store_paths
	eq(t, VarEntry("environments", "staging", "web", "PUBLIC_HOST"), "IceVault/environments/staging/web/PUBLIC_HOST", "var")
	eq(t, FileEntryPath("environments", "prod", "generated/x/y"), "IceVault/environments/prod/files/generated/x/y", "file")
	eq(t, BlobEntry("environments", "prod", "services-portal"), "IceVault/environments/prod/.blobs/services-portal", "blob")
	eq(t, ItemEntry("mine", "box"), "IceVault/mine/box/.item", "item")
	eq(t, SectionEntry("mine"), "IceVault/mine/.section", "section")
	eq(t, GroupEntry("mine", "box", "g"), "IceVault/mine/box/g/.group", "group")
	r, ok := SplitRef("mine/aws")
	eq(t, []any{r, ok}, []any{ItemKey{"mine", "aws"}, true}, "split ref")
	if _, ok := SplitRef("aws"); ok {
		t.Error("a bare name is not a ref")
	}
}

func fixtureSites(t *testing.T) *Snapshot {
	return snapOf(t, baseRows(
		row{"environments/prod/cluster", ".group", "", "state=active\nonly-sites=aws-main"},
		row{"environments/prod/cluster", "GKE_POOL", "main", own + "plain"},
		row{"environments/prod/cluster", "SHARED_NAME", "on-site", own + "plain"},
		row{"environments/prod/web", "SHARED_NAME", "for-all", own + "plain"},
		row{"environments/prod/other", ".group", "", "state=active\nonly-sites=aws-eu"},
		row{"environments/prod/other", "EU_ONLY", "eu", own + "plain"})...)
}

func values(rs []*Resolved) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Entry.Value)
	}
	return out
}

func TestSites(t *testing.T) {
	s := fixtureSites(t)
	// test_a_group_limited_to_a_site_applies_only_there_and_comes_first
	main := s.Resolve("environments", "prod", "aws-main", nil)
	if main.ByKey["GKE_POOL"] == nil || main.ByKey["EU_ONLY"] != nil {
		t.Error("aws-main sees GKE_POOL and not EU_ONLY")
	}
	eq(t, values(main.Holders["SHARED_NAME"]), []string{"on-site", "for-all"}, "env@site before env")
	eu := s.Resolve("environments", "prod", "aws-eu", nil)
	if eu.ByKey["EU_ONLY"] == nil || eu.ByKey["GKE_POOL"] != nil {
		t.Error("aws-eu sees EU_ONLY and not GKE_POOL")
	}
	eq(t, eu.ByKey["SHARED_NAME"][0].Entry.Value, "for-all", "eu shared")
	// test_no_site_asked_sees_every_group_as_before
	all := s.Resolve("environments", "prod", "", nil)
	if all.ByKey["GKE_POOL"] == nil || all.ByKey["EU_ONLY"] == nil {
		t.Error("no site: every group applies")
	}
	// test_the_site_credentials_come_last_and_only_for_that_site
	eq(t, main.ByKey["TARGET_ZONE"][0].Section, "sites", "site credentials")
	if eu.ByKey["TARGET_ZONE"] != nil || all.ByKey["TARGET_ZONE"] != nil {
		t.Error("site credentials only for their site")
	}
	eq(t, s.SitesOf("prod"), []string{"aws-eu", "aws-main"}, "sites of")
}

func TestReferences(t *testing.T) {
	res := snapOf(t, baseRows()...).Resolve("environments", "prod", "aws-main", nil)
	// test_references_expand_inside_a_value_with_text_around_them
	d := res.ByKey["PUBLIC_HOST"][0].Entry
	eq(t, d.Value, "https://example.org/api", "expanded")
	eq(t, *d.Raw, "https://${{ shared.HOST }}/api", "raw")
	if res.ByKey["PLAIN"][0].Entry.Raw != nil {
		t.Error("a plain value has no raw")
	}
	// test_the_visibility_is_the_strictest_of_the_value_and_its_targets
	eq(t, d.Vis, "plain", "domain vis")
	eq(t, res.ByKey["SVC_TOKEN"][0].Entry.Vis, "secret", "token vis")
	s2 := snapOf(t, baseRows(row{"environments/prod/web", "H", "${{ hcp.SVC_TOKEN }}", own + "plain"})...)
	eq(t, s2.Resolve("environments", "prod", "", nil).ByKey["H"][0].Entry.Vis, "sealed", "sealed target")
	// test_an_escaped_reference_is_text
	eq(t, res.ByKey["LIT"][0].Entry.Value, "${{ shared.HOST }}", "escaped")
	eq(t, ReferencesIn("$${{ shared.A }} ${{ shared.B }}"), [][2]string{{"shared", "B"}}, "references_in")
	// test_a_broken_reference_is_an_error_naming_it_and_the_value_is_empty_there
	var msgs []string
	for _, e := range res.Errors {
		if e.R.Entry.Key == "BAD" {
			msgs = append(msgs, e.Msg)
		}
	}
	if len(msgs) != 2 || !strings.Contains(strings.Join(msgs, "|"), "nothing") || !strings.Contains(strings.Join(msgs, "|"), "shared.MISSING") {
		t.Errorf("BAD errors: %v", msgs)
	}
	eq(t, res.ByKey["BAD"][0].Entry.Value, " and ", "bad value")
}

func errsOf(res *Resolution, key string) []string {
	var out []string
	for _, e := range res.Errors {
		if e.R.Entry.Key == key {
			out = append(out, e.Msg)
		}
	}
	return out
}

func TestReferenceSiteAndChains(t *testing.T) {
	s := snapOf(t, baseRows()...)
	// test_a_system_not_allowed_on_the_site_is_an_error
	us := errsOf(s.Resolve("environments", "prod", "aws-us", nil), "SVC_TOKEN")
	if len(us) != 1 || !strings.Contains(us[0], "not allowed on site 'aws-us'") {
		t.Errorf("aws-us: %v", us)
	}
	if got := errsOf(s.Resolve("environments", "prod", "aws-eu", nil), "SVC_TOKEN"); len(got) != 0 {
		t.Errorf("aws-eu: %v", got)
	}
	// test_references_chain_and_a_cycle_names_its_chain
	s = snapOf(t, baseRows(
		row{"global/main/net", "A", "${{ shared.B }}!", own + "plain"}, row{"global/main/net", "B", "b-${{ shared.HOST }}", own + "plain"},
		row{"environments/prod/web", "CHAIN", "${{ shared.A }}", own + "plain"},
		row{"global/main/net", "C1", "${{ shared.C2 }}", own + "plain"}, row{"global/main/net", "C2", "${{ shared.C1 }}", own + "plain"},
		row{"environments/prod/web", "LOOP", "${{ shared.C1 }}", own + "plain"})...)
	res := s.Resolve("environments", "prod", "aws-main", nil)
	eq(t, res.ByKey["CHAIN"][0].Entry.Value, "b-example.org!", "chain")
	eq(t, errsOf(res, "LOOP"), []string{"cycle: shared.C1 -> shared.C2 -> shared.C1"}, "cycle")
	// test_a_key_that_exists_twice_in_the_global_section_is_refused
	s = snapOf(t, baseRows(row{"global/main/other", "HOST", "second", own + "plain"})...)
	twice := errsOf(s.Resolve("environments", "prod", "aws-main", nil), "PUBLIC_HOST")
	if len(twice) != 1 || !strings.Contains(twice[0], "exists 2 times") {
		t.Errorf("twice: %v", twice)
	}
	// test_used_by_lists_the_values_that_refer_to_a_key
	s = snapOf(t, baseRows()...)
	used := func(name, key string) []string {
		var out []string
		for _, h := range s.Referencing(name, key) {
			out = append(out, h.Item.Name+"/"+h.Entry.Key)
		}
		sort.Strings(out)
		return out
	}
	eq(t, used("shared", "HOST"), []string{"prod/PUBLIC_HOST"}, "used by host")
	eq(t, used("dns", "API"), []string{"prod/SVC_TOKEN"}, "used by api")
}

func TestSelfReferences(t *testing.T) {
	s := snapOf(t, baseRows(
		row{"environments/prod/web", "ADMIN", "root@example.org", own + "plain"},
		row{"environments/prod/web", "SUPPORT", "mail:${{ self.ADMIN }}", own + "plain"},
		row{"environments/prod/web", "VIA_SHARED", "${{ self.PUBLIC_HOST }}/x", own + "plain"},
		row{"environments/prod/web", "SELF_TOKEN", "t-${{ self.SECRET }}", own + "plain"},
		row{"environments/prod/web", "SECRET", "s3", own + "secret"},
		row{"environments/prod/web", "SEALED", "z", own + "sealed"},
		row{"environments/prod/web", "THROUGH", "${{ self.SEALED }}", own + "plain"},
		row{"environments/prod/web", "C1", "${{ self.C2 }}", own + "plain"},
		row{"environments/prod/web", "C2", "${{ self.C1 }}", own + "plain"},
		row{"environments/prod/web", "ME", "${{ self.ME }}", own + "plain"},
		row{"environments/prod/web", "NOPE", "${{ self.NOTHING }}", own + "plain"},
		row{"environments/prod/web", "TWICE", "${{ self.DUP }}", own + "plain"},
		row{"environments/prod/web", "DUP", "a", own + "plain"},
		row{"global/main/net", "G_SELF", "${{ self.ADMIN }}", own + "plain"},
		row{"environments/prod/web", "USE_G", "${{ shared.G_SELF }}", own + "plain"},
		row{"environments/prod/edge", "DUP", "b", own + "plain"})...)
	res := s.Resolve("environments", "prod", "aws-main", nil)
	v := func(k string) string { return res.ByKey[k][0].Entry.Value }
	eq(t, v("SUPPORT"), "mail:root@example.org", "self")
	eq(t, v("VIA_SHARED"), "https://example.org/api/x", "self -> shared chain")
	eq(t, res.ByKey["SUPPORT"][0].Entry.Vis, "plain", "plain stays plain")
	eq(t, res.ByKey["SELF_TOKEN"][0].Entry.Vis, "secret", "strictest of own and target")
	eq(t, res.ByKey["THROUGH"][0].Entry.Vis, "sealed", "sealed target")
	eq(t, errsOf(res, "C1"), []string{"cycle: self.C2 -> self.C1 -> self.C2"}, "cycle")
	eq(t, errsOf(res, "ME"), []string{"cycle: self.ME -> self.ME"}, "self cycle")
	eq(t, errsOf(res, "NOPE"), []string{"no value self.NOTHING"}, "unresolved")
	if e := errsOf(res, "TWICE"); len(e) != 1 || !strings.Contains(e[0], "self.DUP exists 2 times") {
		t.Errorf("twice: %v", e)
	}
	// a global value has no environment: self is an error there, and through a reference to it
	if e := errsOf(res, "USE_G"); len(e) != 1 || !strings.Contains(e[0], "no environment") {
		t.Errorf("global self: %v", e)
	}
	_, _, errs := s.Expand("${{ self.ADMIN }}", "plain", "")
	if len(errs) != 1 || !strings.Contains(errs[0], "no environment") {
		t.Errorf("Expand: %v", errs)
	}
	// the site pair: a group limited to a site wins for that site
	s = snapOf(t, baseRows(
		row{"environments/prod/cluster", ".group", "", "state=active\nonly-sites=aws-main"},
		row{"environments/prod/cluster", "POOL", "main-pool", own + "plain"},
		row{"environments/prod/other", ".group", "", "state=active\nonly-sites=aws-eu"},
		row{"environments/prod/other", "POOL", "eu-pool", own + "plain"},
		row{"environments/prod/web", "WHERE", "${{ self.POOL }}", own + "plain"},
		row{"environments/prod/web", "ZONE", "${{ self.TARGET_ZONE }}", own + "plain"})...)
	eq(t, s.Resolve("environments", "prod", "aws-main", nil).ByKey["WHERE"][0].Entry.Value, "main-pool", "pair main")
	eq(t, s.Resolve("environments", "prod", "aws-eu", nil).ByKey["WHERE"][0].Entry.Value, "eu-pool", "pair eu")
	eq(t, s.Resolve("environments", "prod", "aws-main", nil).ByKey["ZONE"][0].Entry.Value, "eu-west-1", "site credentials")
	if e := errsOf(s.Resolve("environments", "prod", "aws-eu", nil), "ZONE"); len(e) != 1 {
		t.Errorf("zone on eu: %v", e)
	}
	if e := errsOf(s.Resolve("environments", "prod", "", nil), "WHERE"); len(e) != 1 || !strings.Contains(e[0], "exists 2 times") {
		t.Errorf("no site: %v", e)
	}
}

func TestSelfNameIsReserved(t *testing.T) {
	st := &Store{Snap: NewSnapshot()}
	if _, err := st.CreateItem(SecExternal, "self", "x"); err == nil || !strings.Contains(err.Error(), "'self'") {
		t.Errorf("item: %v", err)
	}
	if err := st.CreateSection("self", "x"); err == nil {
		t.Error("section self accepted")
	}
}

func TestDepthLimit(t *testing.T) {
	rows := baseRows()
	for i := 0; i < 10; i++ {
		rows = append(rows, row{"global/main/chain", "K" + string(rune('0'+i)), "${{ shared.K" + string(rune('1'+i)) + " }}", own + "plain"})
	}
	rows = append(rows, row{"environments/prod/web", "TOP", "${{ shared.K0 }}", own + "plain"})
	res := snapOf(t, rows...).Resolve("environments", "prod", "", nil)
	e := errsOf(res, "TOP")
	if len(e) == 0 || !strings.Contains(e[0], "deeper than 8") {
		t.Errorf("depth: %v", e)
	}
}

func TestLayeringAndShadows(t *testing.T) {
	s := snapOf(t,
		row{"environments/prod", ".item", "", "state=active\nuses=providers/a,providers/b"},
		row{"environments/prod/g", "OWN_EMPTY", "", own + "plain"},
		row{"environments/prod/g", "BOTH", "own", own + "plain"},
		row{"providers/a", ".item", "", "state=active"},
		row{"providers/a/x", "OWN_EMPTY", "from-a", own + "plain"},
		row{"providers/a/x", "BOTH", "from-a", own + "plain"},
		row{"providers/a/x", "ONLY_A", "", own + "plain"},
		row{"providers/b", ".item", "", "state=active"},
		row{"providers/b/x", "ONLY_A", "from-b", own + "plain"},
		row{"providers/b/x", "BOTH", "from-b", own + "plain"})
	res := s.Resolve("environments", "prod", "", nil)
	eq(t, res.ByKey["OWN_EMPTY"][0].Entry.Value, "from-a", "an empty entry never shadows a filled one")
	eq(t, res.ByKey["OWN_EMPTY"][0].Source(), "providers/a", "source of the filled one")
	eq(t, res.ByKey["ONLY_A"][0].Source(), "providers/b", "first non-empty holder")
	eq(t, res.ByKey["BOTH"][0].Entry.Value, "own", "own wins")
	eq(t, len(res.Holders["BOTH"]), 3, "every holder is listed")
	if len(res.Shadowed) != 2 || len(res.Emptied) != 2 {
		t.Errorf("shadowed %d emptied %d", len(res.Shadowed), len(res.Emptied))
	}
	eq(t, res.Order, []string{"OWN_EMPTY", "BOTH", "ONLY_A"}, "order")
	eq(t, s.UsersOf("providers", "a"), []string{"environments/prod"}, "users")
	eq(t, len(s.Linked("environments", "prod")), 2, "linked")
	eq(t, s.BrokenLinks("environments", "prod"), []ItemKey(nil), "no broken links")
}

func TestFilesOfAPair(t *testing.T) {
	s := NewSnapshot()
	env := s.Make("environments", "prod")
	env.HasMeta = true
	s.AddGroup("IceVault/environments/prod/g")
	s.SetGroupMeta("environments", "prod", "a", &GroupMetaInfo{State: "active", OnlySites: []string{"s1"}})
	s.SetGroupMeta("environments", "prod", "b", &GroupMetaInfo{State: "active", OnlySites: []string{"s2"}})
	mk := func(data string) *FileEntry {
		return &FileEntry{Data: []byte(data), Sha: SHA256([]byte(data)), Scope: env.Key()}
	}
	env.Files["creds/gcp.kubeconfig"] = mk("env-level")
	env.Files["sites/s1/creds/gcp.kubeconfig"] = mk("site-one")
	env.Files["keys/gcp/release/r1.key"] = mk("master")
	bound := func(rel string) bool { return !strings.Contains(rel, "/release/") }
	r1 := s.Resolve("environments", "prod", "s1", bound)
	eq(t, string(r1.Files["creds/gcp.kubeconfig"].Data), "site-one", "a site file beats the environment one")
	eq(t, string(r1.Files["keys/gcp/release/r1.key"].Data), "master", "the signing key stays environment-level")
	r2 := s.Resolve("environments", "prod", "s2", bound)
	if _, ok := r2.Files["creds/gcp.kubeconfig"]; ok {
		t.Error("with two sites an environment-level site-bound file is hidden")
	}
	if len(r1.ShadowedFiles) != 0 {
		t.Errorf("the hidden environment file is not a shadow: %v", r1.ShadowedFiles)
	}
}

func TestIngestClassifies(t *testing.T) {
	s := snapOf(t,
		row{"environments", ".section", "", "state=active\norder=0\nsystem=yes"},
		row{"environments/prod", ".item", "", "title=Prod\nuses=mine/aws,bad\nstate=active\nlong text"},
		row{"environments/prod/g", "K", "v", "managed-by=system\nlabels=a,b\nvis-by=owner\nhello"},
		row{"environments/prod/retired", "old@t", "oldv", "managed-by=retired\nretired-at=now"})
	eq(t, s.Sections["environments"], &SectionMetaInfo{Title: "", Order: 0, System: true, State: "active"}, "section")
	it := s.Item("environments", "prod")
	eq(t, []any{it.Title, it.Description, it.Uses}, []any{"Prod", "long text", []ItemKey{{"mine", "aws"}}}, "item")
	e := it.Find("g", "K")
	eq(t, []any{e.Managed, e.Vis, e.Labels, e.VisBy, e.Description, e.Path}, []any{"system", "sealed", []string{"a", "b"}, "owner", "hello", "IceVault/environments/prod/g/K"}, "entry")
	eq(t, it.Retired, []string{"old@t"}, "retired")
	old := NewSnapshot()
	if err := old.Ingest(RawEntry{Path: []string{"environments", "prod"}, Title: ".item", Notes: "type=aws"}); err == nil || err.Error() != OldLayout {
		t.Error("an old layout is refused")
	}
	// {REF:P@I:uuid}
	s2 := snapOf(t, row{"environments/prod/g", "K", "{REF:P@I:0123456789ABCDEF0123456789abcdef}", own + "plain"}, row{"environments/prod/g", "D", "{REF:P@I:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF}", own + "plain"})
	s2.ResolveKeePassRefs(map[string]string{"0123456789ABCDEF0123456789ABCDEF": "target"})
	eq(t, s2.Item("environments", "prod").Find("g", "K").Value, "target", "ref resolved")
	eq(t, s2.Item("environments", "prod").Find("g", "K").Ref, true, "ref flag")
	eq(t, s2.Item("environments", "prod").Find("g", "D").Value, "{REF:P@I:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF}", "dangling stays")
}

func TestNamesAndGenerate(t *testing.T) {
	for _, n := range []string{"a", "prod", "aws-main", "a_b-1", strings.Repeat("a", 32)} {
		if !ValidName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range []string{"", "Bad", "-a", "a b", strings.Repeat("a", 33), "a.b", "a\n"} {
		if ValidName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
	for _, k := range []string{"A", "_x", "A.b-c"} {
		if !KeyRE.MatchString(k) {
			t.Errorf("key %q", k)
		}
	}
	if KeyRE.MatchString("1A") || PathPart.MatchString(".x") || !PathPart.MatchString("a.b_c-1") {
		t.Error("key/path rules")
	}
	for _, alpha := range []string{"alnum", "symbols", "hex", "base64url"} {
		v, err := Generate(40, alpha)
		if err != nil || len(v) != 40 || strings.Trim(v, Alphabets[alpha]) != "" {
			t.Errorf("generate %s: len %d err %v", alpha, len(v), err)
		}
	}
	for _, c := range [][2]any{{7, "alnum"}, {257, "alnum"}, {16, "nope"}} {
		if _, err := Generate(c[0].(int), c[1].(string)); err == nil {
			t.Errorf("generate %v must be refused", c)
		}
	}
	if _, err := OneLine("a\nb", "a title", 120); err == nil {
		t.Error("one_line newline")
	}
	if _, err := OneLine(strings.Repeat("x", 121), "a title", 120); err == nil {
		t.Error("one_line long")
	}
	if _, err := DescriptionText("ok\nmanaged-by=system"); err == nil {
		t.Error("reserved description line")
	}
	if d, err := DescriptionText("  hi = there is not reserved  \n"); err != nil || d != "hi = there is not reserved" {
		t.Errorf("description %q %v", d, err)
	}
}

func TestOlderLayoutIsRefused(t *testing.T) {
	ok := snapOf(t, row{"environments", ".section", "", "state=active"}, row{"environments/prod", ".item", "", "state=active"})
	if err := ok.CheckLayout(); err != nil {
		t.Errorf("a current layout: %v", err)
	}
	old := NewSnapshot()
	old.AddGroup("IceVault/staging")
	old.AddGroup("IceVault/staging/services-portal")
	if err := old.CheckLayout(); err == nil || !strings.Contains(err.Error(), "older layout") || !strings.Contains(err.Error(), "init-vault") {
		t.Errorf("top-level group without .section: %v", err)
	}
	layouts := snapOf(t, row{"environments", ".section", "", "state=active"})
	layouts.AddGroup("IceVault/environments/staging/.layouts")
	if err := layouts.CheckLayout(); err == nil {
		t.Error(".layouts group")
	}
	files := NewSnapshot()
	files.AddGroup("IceVault/files")
	if err := files.CheckLayout(); err != nil {
		t.Error("the files group is not a section")
	}
}

func TestKPTimeBothFormats(t *testing.T) {
	// reference: one entry made at 21:32:04 UTC, ISO text (KDBX 3.1) and, after the file turned KDBX 4, base64
	eq(t, KPTime("2026-11-17T21:32:04Z"), "2026-11-17T21:32:04Z", "iso")
	eq(t, KPTime("1L6O4g4AAAA="), "2026-11-17T21:32:04Z", "kdbx4")
	eq(t, KPTime("1b6O4g4AAAA="), "2026-11-17T21:32:05Z", "next second")
	for _, bad := range []string{"", "not a time", "AAAA"} {
		eq(t, KPTime(bad), "", bad)
	}
}

func nn(s string, err error) string {
	if err != nil {
		panic(err)
	}
	return s
}
