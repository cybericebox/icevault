package render

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
)

const value = "S3CRET-VALUE-must-never-be-printed"

var webEnv = "# Web settings.\n# Everything the web needs.\n\n# the base domain; every host derives from it\nBASE_HOST=example.org\n" +
	"OWNER_EMAIL=\"owner@example.org\"   # REQUIRED: replace\nCOOKIE_SECRET=" + value + "\nNAME_WITH_SPACE=\"two words\"\nEMPTY_ONE=\n#COMMENTED_OUT=1\n\nOTHER='single quoted'\n"

const apiEnv = "# api\nAPI_REPLICAS=2\nAPI_NAME=demo\n"
const dnsEnv = "DNS_API_TOKEN=dns-token-value\nDNS_ACCOUNT_ID=acc\n"

const webRel = "apps/web.env"

// testDescription is the small project of these tests: its files, conditions, kept files and the variables the scripts write.
const testDescription = `format: 2
name: Test notes
checkout: {environments: envs, plaintext: plain, vault: plain/vault/t.kdbx}
conditions:
  defaults: {WEB: cluster, API: cluster, WORKER: none}
  word-before: ":"
files:
  - base.env
  - {path: cloud/aws-login.env, used-when: HOSTING=aws}
  - {path: net/dns.env, used-when: "HOSTING in [aws, google]"}
  - {path: cloud/aws-site.env, used-when: HOSTING=aws}
  - {path: cloud/gcp-site.env, used-when: HOSTING=google}
  - path: apps/api.env
    used-when: API=cluster and HOSTING in [aws, google]
    partly-used: {when: HOSTING=local and API=cluster, keys: [API_NAME]}
  - {path: apps/web.env, used-when: "WEB=cluster or (API=cluster and HOSTING in [aws, google])"}
  - {path: apps/worker.env, used-when: "WORKER in [host, cluster]"}
kept-files:
  - {name: signing key state, pattern: "made/[a-z0-9_-]+/keys/signing/CURRENT", mode: "0400", why: the name of the key in use}
  - {name: signing keys, pattern: "made/[a-z0-9_-]+/keys/signing/.+", mode: "0400", why: signed orders need them, keep-retired: true, needed-until: the last order signed with it has expired, guard: signing}
  - {name: key ring order, pattern: "made/[a-z0-9_-]+/keys/ring/order", mode: "0600", why: the order of the ring, site-bound: true}
  - {name: key ring, pattern: "made/[a-z0-9_-]+/keys/ring/.+", mode: "0600", why: the keys of the ring, keep-retired: true, needed-until: the last ring backup made before it is gone, site-bound: true}
  - {name: cluster keys, pattern: "made/[a-z0-9_-]+/keys/.+", mode: "0600", why: made once, keep-retired: true, site-bound: true}
  - {name: cloud credentials, pattern: "made/[a-z0-9_-]+/account/credentials(\\.json)?", mode: "0600", why: a new one needs an admin, managed: owner, site-bound: true}
  - {name: cluster access, pattern: "made/[a-z0-9_-]+/kubeconfig\\.yaml", mode: "0600", why: the access, site-bound: true}
  - {name: enrollment token, pattern: "made/web/enroll\\.env", mode: "0600", why: a token the web reads}
left-out:
  - {pattern: "made/[a-z0-9_-]+/tf-data(/.*)?", why: working files}
  - {pattern: "dumps/.*", why: database copies}
  - {pattern: "vault/.*", why: the vault itself}
derived:
  - {name: HOSTING, file: base.env, from: site.provider}
general:
  file: base.env
  variables:
    - {name: LABEL_TEXT}
    - {name: BASE_HOST, file: apps/web.env, required: true}
site-kinds:
  aws-cluster:
    provider: aws
    file: cloud/aws-site.env
    connection:
      kind: aws
      file: cloud/aws-login.env
      variables: [{name: LOGIN_ACCESS_KEY_ID, field: access_key_id, secret: true}]
    variables: [{name: POOL_NAME}, {name: ZONE}]
  google-cluster:
    provider: google
    file: cloud/gcp-site.env
    variables: [{name: POOL_NAME}, {name: ZONE}]
  local: {provider: local}
products:
  - name: web
    file: apps/web.env
    place-variable: WEB
    connections:
      - kind: cloudflare
        file: net/dns.env
        variables: [{name: DNS_API_TOKEN, field: api_token, secret: true}]
    variables:
      - {name: COOKIE_SECRET, secret: true, generated: true}
      - {name: WIDGET_SITE_KEY}
      - {name: WIDGET_SECRET, secret: true}
      - {name: FOURTH}
  - name: api
    file: apps/api.env
    place-variable: API
    variables: [{name: API_NAME}, {name: API_CHART, managed: system}]
  - name: worker
    file: apps/worker.env
    place-variable: WORKER
    variables:
      - {name: WORKER_TOKEN, secret: true, generated: true}
      - {name: QUEUE_KEYS, secret: true, generated: true}
      - {name: QUEUE_URL, required-when: WORKER=cluster}
`

// testTemplates are the sample settings files of the test project.
var testTemplates = map[string]string{
	webRel: "# the base domain\nBASE_HOST=example.org\n# made by the setup\nCOOKIE_SECRET=\n" +
		"# NEEDED FOR: off-site backups. Get it: the storage provider, API tokens.\nBACKUP_ACCESS_KEY=\n# NEEDED FOR: off-site backups. The secret of that token.\nBACKUP_SECRET_KEY=\n" +
		"WIDGET_SITE_KEY=\nWIDGET_SECRET=x # secret\nWIDGET_ALT_SITE_KEY=\nFOURTH=4\n",
	"apps/api.env":        "API_NAME=demo\n",
	"net/dns.env":         "DNS_API_TOKEN=\nDNS_ACCOUNT_ID=\n",
	"cloud/aws-login.env": "LOGIN_ACCESS_KEY_ID=\nLOGIN_SECRET_ACCESS_KEY=\nLOGIN_ZONE=\n",
	"cloud/aws-site.env":  "POOL_NAME=\nZONE=\n",
	"cloud/gcp-site.env":  "POOL_NAME=\nZONE=\n",
	"apps/worker.env":     "WORKER_TOKEN=\n",
}

var projCache *Project

func proj() *Project {
	if projCache == nil {
		d, err := project.Parse([]byte(testDescription))
		if err != nil {
			panic(err)
		}
		projCache = NewProject(d, testTemplates)
	}
	return projCache
}

type row struct{ path, title, pw, notes string }

const own = "managed-by=owner\nvisibility=plain"

func snapOf(t *testing.T, rows ...row) *model.Snapshot {
	t.Helper()
	s := model.NewSnapshot()
	for _, r := range rows {
		parts := strings.Split(r.path, "/")
		for i := 1; i <= len(parts); i++ {
			s.AddGroup(model.Group + "/" + strings.Join(parts[:i], "/"))
		}
		if err := s.Ingest(model.RawEntry{Path: parts, Title: r.title, Notes: r.notes, Password: r.pw}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func eq(t *testing.T, got, want any, what string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: got %#v, want %#v", what, got, want)
	}
}

// ---------------------------------------------------------------- the rules of the description

func TestTableSettingsFilesAndOtherFiles(t *testing.T) {
	p := proj()
	for _, rel := range []string{webRel, "apps/api.env", "cloud/aws-login.env", "cloud/gcp-site.env", "apps/worker.env", "base.env"} {
		if k, _ := p.Classify(rel); k != "env" {
			t.Errorf("%s: %q", rel, k)
		}
	}
	for _, rel := range []string{"made/aws/keys/signing/k1.key", "made/aws/keys/signing/CURRENT", "made/google/keys/session-secret", "made/aws/account/credentials",
		"made/google/account/credentials.json", "made/google/kubeconfig.yaml", "made/web/enroll.env"} {
		if k, _ := p.Classify(rel); k != "file" {
			t.Errorf("%s: %q", rel, k)
		}
	}
	if k, _ := p.Classify("apps/unknown.env"); k != "" {
		t.Error("a settings file the description does not have is not kept")
	}
}

func TestTableKeyRing(t *testing.T) {
	p := proj()
	for rel, name := range map[string]string{"made/aws/keys/ring/order": "key ring order", "made/aws/keys/ring/key1.key": "key ring", "made/aws/keys/ring/retired/key1.key": "key ring"} {
		k, r := p.Classify(rel)
		if r == nil {
			t.Fatalf("%s not classified", rel)
		}
		eq(t, []any{k, r.Name, r.Managed, r.Mode}, []any{"file", name, "system", 0o600}, rel)
	}
	if !p.RetireFile("made/aws/keys/ring/key1.key") || !p.RetireFile("made/aws/keys/ring/retired/key1.key") || p.RetireFile("made/aws/keys/ring/order") {
		t.Error("retire rule for the ring")
	}
	if p.RetireFile("made/aws/keys/signing/CURRENT") || !p.RetireFile("made/aws/keys/signing/k1.key") || p.RetireFile("made/aws/kubeconfig.yaml") {
		t.Error("retire rule for the signing keys")
	}
	if !strings.Contains(p.NeededUntil("made/aws/keys/ring/key1.key"), "ring backup") || !strings.Contains(p.NeededUntil("made/aws/keys/signing/k1.key"), "signed") {
		t.Error("needed until")
	}
}

func TestTableModes(t *testing.T) {
	p := proj()
	_, signing := p.Classify("made/aws/keys/signing/k1.key")
	_, other := p.Classify("made/aws/keys/session-secret")
	eq(t, []int{signing.Mode, other.Mode}, []int{0o400, 0o600}, "modes")
	eq(t, []string{signing.Managed, p.FileRule("made/aws/account/credentials").Managed}, []string{"system", "owner"}, "managed")
}

func TestTableLeftOut(t *testing.T) {
	p := proj()
	for _, rel := range []string{"made/aws/tf-data/x", "dumps/2026/db.tar", "vault/t.kdbx", "vault/t.kdbx.info.json"} {
		if k, _ := p.Classify(rel); k != "" {
			t.Errorf("%s must not be kept", rel)
		}
		if !p.Excluded(rel) {
			t.Errorf("%s must be excluded", rel)
		}
	}
}

func TestStemsRoundTrip(t *testing.T) {
	p := proj()
	for _, rel := range []string{webRel, "apps/api.env", "net/dns.env", "cloud/gcp-site.env", "apps/worker.env", "base.env", "cloud/aws-login.env"} {
		eq(t, p.RelOfStem(StemOf(rel)), rel, rel)
	}
	eq(t, StemOf("net/dns.env"), "net-dns", "stem")
	eq(t, StemOf("base.env"), "base", "stem of a file without a folder")
	eq(t, StemOf("apps/web.env"), "apps-web", "stem of a folder file")
	eq(t, p.RelOfStem("nodash"), "", "no stem")
}

func TestTreeFiles(t *testing.T) {
	cov, skipped, unknown := proj().TreeFiles([]string{webRel, "made/aws/kubeconfig.yaml", "made/aws/tf-data/x", "stray.txt", "cloud/gcp-site.env"}, nil)
	keys := []string{}
	for k := range cov {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	eq(t, keys, []string{webRel, "cloud/gcp-site.env", "made/aws/kubeconfig.yaml"}, "covered")
	eq(t, skipped, []string{"made/aws/tf-data/x"}, "skipped")
	eq(t, unknown, []string{"stray.txt"}, "unknown")
}

func TestSiteBound(t *testing.T) {
	p := proj()
	for rel, want := range map[string]bool{"made/aws/kubeconfig.yaml": true, "made/aws/keys/signing/k1.key": false, "made/web/enroll.env": false,
		"made/aws/keys/ring/k": true, webRel: false} {
		if p.SiteBound(rel) != want {
			t.Errorf("SiteBound(%s) != %v", rel, want)
		}
	}
}

// Which files an environment uses: the used-when and partly-used conditions over its settings, with the defaults of the description.
func TestUses(t *testing.T) {
	p := proj()
	type c struct {
		settings map[string]string
		file     string
		want     string
	}
	for _, x := range []c{
		{map[string]string{"HOSTING": "aws"}, "cloud/aws-login.env", ""},
		{map[string]string{"HOSTING": "google"}, "cloud/aws-login.env", Unused},
		{map[string]string{"HOSTING": "google"}, "net/dns.env", ""},
		{map[string]string{"HOSTING": "local"}, "net/dns.env", Unused},
		{map[string]string{"HOSTING": "aws"}, "apps/api.env", ""},                       // API defaults to cluster
		{map[string]string{"HOSTING": "aws", "API": "compose"}, "apps/api.env", Unused}, // not on a cloud cluster
		{map[string]string{"HOSTING": "local"}, "apps/api.env", UnusedPartly},
		{map[string]string{"HOSTING": "local", "WEB": "external:staging"}, webRel, Unused}, // the word before ':'
		{map[string]string{"HOSTING": "aws", "WEB": "compose"}, webRel, ""},                // the api on a cloud cluster reads it
		{map[string]string{"HOSTING": "aws"}, "apps/worker.env", Unused},                   // WORKER defaults to none
		{map[string]string{"HOSTING": "aws", "WORKER": "host"}, "apps/worker.env", ""},
		{map[string]string{"HOSTING": "aws", "WORKER": "cluster"}, "apps/worker.env", ""},
		{map[string]string{}, "cloud/aws-login.env", ""}, // nothing known: nothing is unused
	} {
		eq(t, p.UsesFrom(x.settings).FileUnused(x.file), x.want, x.file+" "+strings.Join(sortedKV(x.settings), ","))
	}
	u := p.UsesFrom(map[string]string{"HOSTING": "local"})
	eq(t, []string{u.KeyUnused("apps/api.env", "API_NAME"), u.KeyUnused("apps/api.env", "API_CHART")}, []string{"", UnusedPartly}, "partly-used keys")
	eq(t, p.RequiredNow("apps/worker.env", "QUEUE_URL", func(k string) string { return map[string]string{"WORKER": "cluster"}[k] }), true, "required-when holds")
	eq(t, p.RequiredNow("apps/worker.env", "QUEUE_URL", func(k string) string { return map[string]string{"WORKER": "host"}[k] }), false, "required-when does not")
}

func sortedKV(m map[string]string) []string {
	var out []string
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func TestPairSite(t *testing.T) {
	mk := func(groups ...[2]string) *model.Snapshot {
		rows := []row{{"environments/prod", ".item", "", "state=active"}, {"environments/prod/web", "BASE_HOST", "${{ shared.HOST }}", own}, {"global/main/net", "HOST", "example.org", own}}
		for _, g := range groups {
			rows = append(rows, row{"environments/prod/" + g[0], ".group", "", "state=active\nonly-sites=" + g[1]}, row{"environments/prod/" + g[0], "K_" + strings.ToUpper(g[0]), "v", own})
		}
		return snapOf(t, rows...)
	}
	pick := func(s *model.Snapshot, site string) (string, error) { return PickSite(s, "prod", site) }
	if got, err := pick(mk(), ""); got != "" || err != nil {
		t.Errorf("no sites: %q %v", got, err)
	}
	one := mk([2]string{"c1", "aws-main"})
	for _, site := range []string{"", "aws-main"} {
		if got, err := pick(one, site); got != "aws-main" || err != nil {
			t.Errorf("one site %q: %q %v", site, got, err)
		}
	}
	two := mk([2]string{"c1", "aws-main"}, [2]string{"c2", "aws-eu"})
	if _, err := pick(two, ""); err == nil || !strings.Contains(err.Error(), "aws-eu, aws-main") || !strings.Contains(err.Error(), "--site") {
		t.Errorf("two sites: %v", err)
	}
	if got, err := pick(two, "aws-eu"); got != "aws-eu" || err != nil {
		t.Error("named site")
	}
	if _, err := pick(two, "gcp-1"); err == nil {
		t.Error("a site with no settings is refused")
	}
	if _, err := pick(two, "Bad Name"); err == nil {
		t.Error("a bad site name is refused")
	}
	// test_the_session_directory_is_one_per_pair
	eq(t, proj().SessionDirName(501, "prod", ""), "icevault-501-prod", "session dir")
	eq(t, proj().SessionDirName(501, "prod", "aws-main"), "icevault-501-prod-aws-main", "session dir with a site")
	// test_the_view_of_a_pair_has_the_site_groups_and_stops_on_a_broken_reference
	d, err := proj().View(two, "prod", "aws-main")
	if err != nil || len(d.Errors) != 0 {
		t.Errorf("view of a pair: %v %v", err, d.Errors)
	}
	broken := snapOf(t, row{"environments/prod", ".item", "", "state=active"}, row{"environments/prod/web", "X", "${{ shared.NOPE }}", own})
	bv, _ := proj().View(broken, "prod", "")
	if err := RequireResolved(bv); err == nil || !strings.Contains(err.Error(), "environments/prod/web/X") || !strings.Contains(err.Error(), "shared.NOPE") {
		t.Errorf("require resolved: %v", err)
	}
	if _, err := proj().Render(broken, "prod", "", true); err == nil {
		t.Error("a broken reference stops every render")
	}
	// test_the_checklist_lists_a_reference_that_does_not_resolve
	c, _ := proj().Checklist(broken, "prod", "")
	var br *ChecklistRow
	needed := 0
	for i, r := range c.Rows {
		if r.State == "broken" {
			br = &c.Rows[i]
		}
		if r.Required && r.State != "present" {
			needed++
		}
	}
	if br == nil || br.Key != "X" || !br.Required || br.GroupIn != "web" || !strings.Contains(br.Hint, "shared.NOPE") {
		t.Fatalf("broken row: %#v", br)
	}
	eq(t, c.Needed, needed, "needed counts the broken one")
	eq(t, len(c.Warnings), 0, "no second banner")
}

// ---------------------------------------------------------------- Homes

func TestLabelsAndEntryRels(t *testing.T) {
	p := proj()
	eq(t, LabelsFor("apps/web.env"), []string{"file:apps/web.env"}, "labels for")
	mk := func(key, vis string, labels ...string) *model.Entry {
		e := model.NewEntry(key, "v", "g", "p")
		e.Vis, e.Labels = vis, labels
		return e
	}
	eq(t, p.EntryRel(mk("K", "secret", "x", "file:apps/worker.env")), "apps/worker.env", "file label")
	eq(t, p.EntryRel(mk("HOSTING", "secret")), "base.env", "unlabelled key the manifest has once")
	eq(t, p.EntryRel(mk("MY_OWN_THING", "secret")), "", "unknown key")
	every := p.EntryRels(mk("ZONE", "secret"), nil)
	eq(t, every, []string{"cloud/aws-site.env", "cloud/gcp-site.env"}, "in several files")
	eq(t, p.EntryRels(mk("ZONE", "secret", "file:cloud/aws-site.env"), nil), []string{"cloud/aws-site.env"}, "label narrows")
	eq(t, len(p.EntryRels(mk("MY_OWN_THING", "secret"), nil)), 0, "stored only")
	eq(t, p.EntryRels(mk("ZONE", "secret"), map[string]bool{"cloud/aws-site.env": true}), []string{"cloud/aws-site.env"}, "have narrows")
	eq(t, p.EntryScope(mk("ZONE", "secret", "file:cloud/aws-site.env")), "block", "scope block")
	eq(t, p.EntryScope(mk("HOSTING", "secret", "file:base.env")), "environment", "scope env")
}

func TestManifestAndVisibility(t *testing.T) {
	p := proj()
	keys := func(rel string) []string {
		var out []string
		for _, r := range p.Manifest(rel) {
			out = append(out, r.Key)
		}
		return out
	}
	for rel, key := range map[string]string{"base.env": "HOSTING", "apps/web.env": "BASE_HOST", "net/dns.env": "DNS_API_TOKEN", "cloud/aws-site.env": "POOL_NAME", "apps/worker.env": "WORKER_TOKEN"} {
		if !contains(keys(rel), key) {
			t.Errorf("%s lacks %s", rel, key)
		}
	}
	var provider, access Row
	for _, r := range p.Manifest("apps/web.env") {
		if r.Key == "BASE_HOST" {
			provider = r // required by the description
		}
	}
	for _, r := range p.Manifest("apps/web.env") {
		if r.Key == "BACKUP_ACCESS_KEY" {
			access = r
		}
	}
	if !provider.Required || access.Required || !access.NeededFor || !strings.Contains(access.Comment, "NEEDED FOR: off-site backups") {
		t.Errorf("rows: %#v %#v", provider, access)
	}
	// test_visibility_defaults
	eq(t, p.DefaultVisibility("apps/web.env", "BASE_HOST", "owner"), "plain", "domain")
	eq(t, p.DefaultVisibility("apps/web.env", "BACKUP_SECRET_KEY", "owner"), "secret", "secret key")
	eq(t, p.DefaultVisibility("apps/web.env", "COOKIE_SECRET", "system"), "sealed", "system")
	eq(t, p.DefaultVisibility("apps/web.env", "A_NAME_NOBODY_KNOWS", "owner"), "plain", "unknown")
	eq(t, p.IsSecret("net/dns.env", "DNS_API_TOKEN"), true, "cf token")
	// system variables come from the templates
	eq(t, []string{p.VarManaged("COOKIE_SECRET"), p.VarManaged("WORKER_TOKEN"), p.VarManaged("QUEUE_KEYS"), p.VarManaged("BASE_HOST")}, []string{"system", "system", "system", "owner"}, "managed")
	// test_the_name_rule_of_the_visibility
	for _, n := range []string{"API_TOKEN", "DB_PASSWORD", "PREVIEW_SECRET", "COOKIE_SECRET", "SSH_PRIVATE_KEY", "HASH_SALT", "SMTP_CREDENTIALS", "CHAT_BOT_TOKEN",
		"BACKUP_SECRET_KEY", "LOGIN_ACCESS_KEY_ID", "STRIPE_KEY", "APIKEY"} {
		if !LooksSecret(n) {
			t.Errorf("%s should look secret", n)
		}
	}
	for _, n := range []string{"WIDGET_SITE_KEY", "WIDGET_ALT_SITE_KEY", "PUBLIC_KEY", "SSH_KEY_ID", "SIGNING_KEY_NAME", "KEY_PATH", "KEYCLOAK_URL", "MONKEY_COUNT", "BASE_HOST",
		"TOKENIZER_MODEL", "PASSWORDLESS", "SECRETARY"} {
		if LooksSecret(n) {
			t.Errorf("%s should not look secret", n)
		}
	}
	eq(t, p.ProposedVisibility("WIDGET_SITE_KEY"), "plain", "site key")
	eq(t, p.ProposedVisibility("WIDGET_ALT_SITE_KEY"), "plain", "recaptcha site key")
	eq(t, p.ProposedVisibility("WIDGET_SECRET"), "secret", "template marks it")
	eq(t, p.ProposedVisibility("SOMETHING_UNKNOWN"), "plain", "unknown")
	eq(t, p.LegacyVisibility("WIDGET_SITE_KEY"), "secret", "legacy: SECRET_NAME? no, KEY_ -> unknown rule")
	eq(t, p.LegacyVisibility("SOMETHING_UNKNOWN"), "secret", "legacy unknown")
	eq(t, p.LegacyVisibility("BASE_HOST"), "plain", "legacy domain")
	eq(t, p.ManifestKey("BASE_HOST", "  the   base domain "), "apps/web.env:BASE_HOST", "manifest key")
	eq(t, p.ManifestKey("BASE_HOST", "mine"), "", "owner-written")
}

func TestLabelRules(t *testing.T) {
	eq(t, StoredValue("CHANGE-ME", "owner"), "", "placeholder")
	eq(t, StoredValue("<fill in>", "owner"), "", "placeholder 2")
	eq(t, StoredValue("  ", "owner"), "", "blank")
	eq(t, StoredValue("CHANGE-ME", "system"), "CHANGE-ME", "system keeps it")
	eq(t, StoredValue("real", "owner"), "real", "real")
}

// ---------------------------------------------------------------- EnvFiles

func TestEnvRoundTripByteForByte(t *testing.T) {
	for _, text := range []string{webEnv, apiEnv, dnsEnv, "", "A=1", "A=1\n\n\n", "# only comments\n", "  INDENTED=1\n", "A=1\nA=2\n", "A=x   # tail comment\nB=  spaced\n",
		"A=1   \n", "export=1\n", "A=\"x\" # c\n", "A=\"\"\n"} {
		layout, vars, err := ParseEnvChecked("shop/x.env", text)
		if err != nil {
			t.Errorf("%q: %v", text, err)
			continue
		}
		eq(t, RenderEnv(layout, VarsOf(vars)), text, text)
		// and through the stored JSON form
		back, err := ParseLayoutJSON([]byte(CanonJSON(layout)))
		if err != nil {
			t.Fatal(err)
		}
		eq(t, RenderEnv(back, VarsOf(vars)), text, "via JSON "+text)
	}
}

func TestEnvVariablesValuesAndNotes(t *testing.T) {
	layout, vars := ParseEnv(webEnv)
	got := map[string][2]string{}
	for _, v := range vars {
		got[v.Name] = [2]string{v.Value, v.Notes}
	}
	eq(t, got["BASE_HOST"], [2]string{"example.org", "the base domain; every host derives from it"}, "domain")
	eq(t, got["OWNER_EMAIL"], [2]string{"owner@example.org", "REQUIRED: replace"}, "admin")
	eq(t, got["NAME_WITH_SPACE"][0], "two words", "quoted")
	eq(t, got["OTHER"][0], "single quoted", "single")
	eq(t, got["EMPTY_ONE"][0], "", "empty")
	if _, ok := got["COMMENTED_OUT"]; ok {
		t.Error("a commented variable is not one")
	}
	if strings.Contains(CanonJSON(layout), value) {
		t.Error("the layout holds no values")
	}
}

func TestEnvLastOfRepeatedKey(t *testing.T) {
	layout, vars := ParseEnv("A=1\nA=2\n")
	eq(t, vars, []Var{{"A", "2", ""}}, "variables")
	eq(t, layout.Lines[0], LayoutLine{Lit: "A=1", IsLit: true}, "first stays literal")
}

func TestEnvUnusualLineKeepsExactText(t *testing.T) {
	layout, _ := ParseEnv("A=1   \nB=2\n")
	set := func(a, b string) *Vars { v := NewVars(); v.Set("A", a); v.Set("B", b); return v }
	eq(t, RenderEnv(layout, set("1", "2")), "A=1   \nB=2\n", "unchanged")
	eq(t, RenderEnv(layout, set("9", "2")), "A=9\nB=2\n", "changed")
}

func TestEnvOneChangedValueChangesOneLine(t *testing.T) {
	layout, vars := ParseEnv(webEnv)
	v := VarsOf(vars)
	v.Set("BASE_HOST", "other.example")
	newL, oldL := strings.Split(RenderEnv(layout, v), "\n"), strings.Split(webEnv, "\n")
	var diff [][2]string
	for i := range oldL {
		if oldL[i] != newL[i] {
			diff = append(diff, [2]string{oldL[i], newL[i]})
		}
	}
	eq(t, len(oldL), len(newL), "same number of lines")
	eq(t, diff, [][2]string{{"BASE_HOST=example.org", "BASE_HOST=other.example"}}, "one line")
}

func TestEnvQuoting(t *testing.T) {
	layout, _ := ParseEnv("A=1\nB=2\n")
	v := NewVars()
	v.Set("A", "has space")
	v.Set("B", "")
	eq(t, RenderEnv(layout, v), "A=\"has space\"\nB=\"\"\n", "quoted")
	for in, want := range map[string]string{"plain": "plain", "": `""`, "a#b": `"a#b"`, "it's": `"it's"`, `say "x"`: `'say "x"'`, "a$b": `'a$b'`, "a=b": "a=b", "x|y": `"x|y"`, "back\\slash": `'back\slash'`} {
		eq(t, QuoteEnv(in), want, in)
	}
}

func TestEnvAddedAppendedRemovedDropped(t *testing.T) {
	layout, _ := ParseEnv("A=1\nB=2\n")
	v := NewVars()
	v.Set("A", "1")
	v.Set("C", "3")
	out := RenderEnv(layout, v)
	if !strings.Contains(out, "A=1") || strings.Contains(out, "B=2") || !strings.HasSuffix(strings.TrimRight(out, "\n"), "C=3") || !strings.Contains(out, "# ---- added in the vault ----") {
		t.Errorf("render: %q", out)
	}
}

func TestEnvLineBreakRefusedWithoutShowingIt(t *testing.T) {
	err := CheckSingleLine("shop/x.env", []Var{{"A", "x\ny" + value, ""}})
	if err == nil || strings.Contains(err.Error(), value) {
		t.Errorf("err: %v", err)
	}
}

func TestParseValue(t *testing.T) {
	for in, want := range map[string][2]string{
		`"a b" # c`: {"a b", " # c"}, `'x'`: {"x", ""}, "# only": {"", " # only"}, "v   # tail": {"v", "   # tail"}, "  spaced ": {"spaced", ""}, `"unterminated`: {`"unterminated`, ""},
	} {
		v, tail := ParseValue(in)
		eq(t, [2]string{v, tail}, want, in)
	}
}

func TestCanonJSONIsPythonsDumps(t *testing.T) {
	// json.dumps({"v": 1, "lines": ["# é", {"k": "A", "i": "", "l": "", "t": "", "s": "a"}]}, sort_keys=True)
	l := Layout{V: 1, Lines: []LayoutLine{{Lit: "# é \"q\" \\ \t", IsLit: true}, {K: "A", S: "a"}, {K: "B", S: "r", Raw: "x", Line: "B=x  "}}}
	want := `{"lines": ["# \u00e9 \"q\" \\ \t", {"i": "", "k": "A", "l": "", "s": "a", "t": ""}, {"i": "", "k": "B", "l": "", "line": "B=x  ", "raw": "x", "s": "r", "t": ""}], "v": 1}`
	eq(t, CanonJSON(l), want, "canonical json")
	back, err := ParseLayoutJSON([]byte(want))
	eq(t, err, nil, "parse")
	eq(t, back, l, "round trip")
	eq(t, strings.Contains(pyString("😀"), `\ud83d\ude00`), true, "surrogates")
}

// ---------------------------------------------------------------- Views

func TestViewLaysOutPerSettingsFileByLabelOrKey(t *testing.T) {
	snap := snapOf(t,
		row{"environments/staging", ".item", "", "uses=mine/aws\nstate=active"},
		row{"environments/staging/environment", "HOSTING", "aws", "managed-by=owner"},
		row{"environments/staging/c-aws", "ZONE", "eu", "managed-by=owner\nlabels=file:cloud/aws-site.env"},
		row{"environments/staging/c-google", "ZONE", "ew", "managed-by=owner\nlabels=file:cloud/gcp-site.env"},
		row{"environments/staging/notes", "MINE", "stored-only", "managed-by=owner\nvisibility=plain"},
		row{"mine/aws", ".item", "", "state=active"},
		row{"mine/aws/account", "DNS_API_TOKEN", "eu-w", "managed-by=owner\nlabels=file:net/dns.env"})
	p := proj()
	v, err := p.View(snap, "staging", "")
	eq(t, err, nil, "view")
	eq(t, v.Rels(), []string{"base.env", "cloud/aws-site.env", "cloud/gcp-site.env", "net/dns.env"}, "files")
	eq(t, v.Env["base.env"].Variables.M, map[string]string{"HOSTING": "aws"}, "conf")
	eq(t, v.Env["cloud/aws-site.env"].Variables.M, map[string]string{"ZONE": "eu"}, "aws: the label decides")
	eq(t, v.Env["cloud/gcp-site.env"].Variables.M, map[string]string{"ZONE": "ew"}, "google")
	eq(t, v.Env["apps/web.env"] == nil, true, "MINE is stored only")
	_, src, _ := p.Effective(snap, "staging", "net/dns.env", "")
	eq(t, src, map[string]string{"DNS_API_TOKEN": "mine/aws"}, "source")
	s, _ := p.Settings(snap, "staging", "")
	eq(t, s, map[string]string{"HOSTING": "aws"}, "settings")
	all, _ := p.AllSettings(snap)
	eq(t, all, map[string]map[string]string{"staging": {"HOSTING": "aws"}}, "all settings")
	nv, _ := p.View(snap, "nowhere", "")
	eq(t, []int{len(nv.Env), len(nv.Files), len(nv.Errors)}, []int{0, 0, 0}, "unknown environment")
}

func TestKeyInSeveralManifestFilesRendersIntoEach(t *testing.T) {
	snap := snapOf(t, row{"environments/e/c", "ZONE", "r1", "managed-by=owner"}, row{"environments/e/c", "POOL_NAME", "n", "managed-by=owner\nlabels=file:cloud/aws-site.env"})
	v, _ := proj().View(snap, "e", "")
	eq(t, v.Env["cloud/aws-site.env"].Variables.M, map[string]string{"ZONE": "r1", "POOL_NAME": "n"}, "aws")
	eq(t, v.Env["cloud/gcp-site.env"].Variables.M, map[string]string{"ZONE": "r1"}, "google")
}

func TestFirstLinkedItemWinsAndEmptyNeverShadows(t *testing.T) {
	snapWith := func(uses string) *model.Snapshot {
		return snapOf(t,
			row{"environments/e", ".item", "", "uses=" + uses + "\nstate=active"},
			row{"mine/a", ".item", "", "state=active"}, row{"mine/b", ".item", "", "state=active"},
			row{"mine/a/web", "BASE_HOST", "from-a", own}, row{"mine/b/web", "BASE_HOST", "from-b", own},
			row{"environments/e/lab", "API_NAME", "", "managed-by=owner\\nlabels=file:apps/api.env"}, row{"mine/b/lab", "API_NAME", "from-b", "managed-by=owner\\nlabels=file:apps/api.env"})
	}
	p := proj()
	vals, _, _ := p.Effective(snapWith("mine/a,mine/b"), "e", webRel, "")
	eq(t, vals.M["BASE_HOST"], "from-a", "a first")
	vals, _, _ = p.Effective(snapWith("mine/b,mine/a"), "e", webRel, "")
	eq(t, vals.M["BASE_HOST"], "from-b", "b first")
	lab, _, _ := p.Effective(snapWith("mine/b,mine/a"), "e", "apps/api.env", "")
	eq(t, lab.M["API_NAME"], "from-b", "an empty own entry never beats a filled one")
}

func TestOwnBlockBeatsEnvironmentWideBeatsLinked(t *testing.T) {
	snap := snapOf(t,
		row{"environments/e", ".item", "", "uses=mine/a\nstate=active"},
		row{"environments/e/c1", "ZONE", "wide", own},
		row{"environments/e/c2", "ZONE", "block", "managed-by=owner\nlabels=file:cloud/aws-site.env"},
		row{"mine/a", ".item", "", "state=active"}, row{"mine/a/c", "ZONE", "linked", own})
	v, _ := proj().View(snap, "e", "")
	eq(t, v.Env["cloud/aws-site.env"].Variables.M["ZONE"], "block", "block wins in its file")
	eq(t, v.Env["cloud/gcp-site.env"].Variables.M["ZONE"], "wide", "wide wins elsewhere")
}

func TestPositionedPutsLinkedKeyAtTheManifestPlace(t *testing.T) {
	p := proj()
	rows := p.Manifest("apps/web.env")
	k0, k1, k2, k3 := rows[0].Key, rows[1].Key, rows[2].Key, rows[3].Key
	pl := func(k string) LayoutLine { return LayoutLine{K: k, S: "p"} }
	layout := Layout{V: 1, Lines: []LayoutLine{pl(k0), {Lit: "# a comment", IsLit: true}, pl(k2)}}
	v := NewVars()
	v.Set(k0, "a")
	v.Set(k1, "b")
	v.Set(k2, "c")
	v.Set("NOT_IN_THE_MANIFEST", "z")
	lines := strings.Split(RenderEnv(p.Positioned(layout, v, "apps/web.env"), v), "\n")
	eq(t, lines[:4], []string{k0 + "=a", k1 + "=b", "# a comment", k2 + "=c"}, "positioned")
	last := strings.Join(lines[len(lines)-3:], "|")
	eq(t, strings.Contains(last, "NOT_IN_THE_MANIFEST=z"), true, "unknown keys are appended")
	onlyLater := Layout{V: 1, Lines: []LayoutLine{pl(k3)}}
	v2 := NewVars()
	v2.Set(k1, "b")
	v2.Set(k3, "d")
	eq(t, strings.Split(RenderEnv(p.Positioned(onlyLater, v2, "apps/web.env"), v2), "\n")[:2], []string{k1 + "=b", k3 + "=d"}, "before the nearest following")
}

func TestBrokenLinkIsNamed(t *testing.T) {
	snap := snapOf(t, row{"environments/e", ".item", "", "uses=mine/aws,mine/gone\nstate=active"}, row{"mine/aws", ".item", "", "state=active"})
	eq(t, snap.BrokenLinks("environments", "e"), []model.ItemKey{{Section: "mine", Name: "gone"}}, "broken")
	if err := CheckLinks(snap, "e"); err == nil || !strings.Contains(err.Error(), "links mine/gone, which does not exist") {
		t.Errorf("check links: %v", err)
	}
	eq(t, snap.Linked("environments", "e")[0].Ref(), "mine/aws", "linked")
}

func TestFieldReferenceIsResolved(t *testing.T) {
	snap := snapOf(t,
		row{"mine/box/web", "BASE_HOST", "shared.example", own},
		row{"environments/staging", ".item", "", "uses=mine/box\nstate=active"},
		row{"environments/staging/web", "BASE_HOST", "{REF:P@I:0942AA9DB72E4FB6B4D9EB4F932DEDEB}", own},
		row{"environments/staging/web", "OTHER", "{REF:P@I:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF}", own})
	snap.ResolveKeePassRefs(map[string]string{"0942AA9DB72E4FB6B4D9EB4F932DEDEB": "shared.example"})
	vals, src, _ := proj().Effective(snap, "staging", webRel, "")
	eq(t, []string{vals.M["BASE_HOST"], src["BASE_HOST"]}, []string{"shared.example", "environment"}, "own entry is a reference")
	eq(t, snap.Item("environments", "staging").Find("web", "OTHER").Value, "{REF:P@I:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF}", "dangling stays")
	eq(t, snap.Item("environments", "staging").Find("web", "BASE_HOST").Ref, true, "ref flag")
}

func TestViewRowsNamesOnlyAndMissing(t *testing.T) {
	notes := "managed-by=owner\nvisibility=plain\nNEEDED FOR: off-site backups. Get it: the storage provider, API tokens."
	snap := snapOf(t,
		row{"environments/staging/backup", "BACKUP_ACCESS_KEY", "", notes},
		row{"environments/staging/web", "BASE_HOST", "example.org", "managed-by=owner\nvisibility=plain\nthe domain"},
		row{"environments/staging/web", "COOKIE_SECRET", value, "managed-by=system\nvisibility=plain"})
	rows, err := proj().ViewRows(snap, "staging", nil, "")
	eq(t, err, nil, "rows")
	by := map[string]ViewRow{}
	var missing []string
	for _, r := range rows {
		by[r.Name] = r
		if r.Missing() {
			missing = append(missing, r.File+" "+r.Name)
		}
	}
	eq(t, [3]string{by["BACKUP_ACCESS_KEY"].State, by["BACKUP_ACCESS_KEY"].Managed, by["BACKUP_ACCESS_KEY"].Source}, [3]string{"empty", "owner", "environment"}, "empty row")
	eq(t, [2]string{by["COOKIE_SECRET"].State, by["COOKIE_SECRET"].Managed}, [2]string{"set", "system"}, "system row")
	eq(t, missing, []string(nil), "NEEDED FOR: the feature is not in use, nothing is missing")
	inUse := snapOf(t,
		row{"environments/staging/backup", "BACKUP_ACCESS_KEY", "", notes},
		row{"environments/staging/backup", "BACKUP_SECRET_KEY", "s", "managed-by=owner\nvisibility=secret\nlabels=file:apps/web.env"})
	rows2, _ := proj().ViewRows(inUse, "staging", nil, "")
	missing = nil
	for _, r := range rows2 {
		if r.Missing() {
			missing = append(missing, r.File+" "+r.Name)
		}
	}
	eq(t, missing, []string{"apps/web.env BACKUP_ACCESS_KEY"}, "a sibling of the feature is set: missing")
	eq(t, model.HintOf(by["BACKUP_ACCESS_KEY"].Notes), "NEEDED FOR: off-site backups. Get it: the storage provider, API tokens.", "hint")
	item := model.ItemKey{Section: "environments", Name: "staging"}
	irows, _ := proj().ViewRows(snap, "", &item, "")
	eq(t, len(irows), 3, "item rows")
	if !sort.SliceIsSorted(irows, func(i, j int) bool { return irows[i].File+irows[i].Name < irows[j].File+irows[j].Name }) {
		t.Error("item rows are sorted")
	}
}

func TestRenderTreeModes(t *testing.T) {
	snap := model.NewSnapshot()
	env := snap.Make("environments", "e")
	env.HasMeta = true
	env.Blobs["apps-web"] = []byte(CanonJSON(mustLayout("A=1\n# c\nB=2\n")))
	env.Entries = []*model.Entry{entry("A", "x y", "g", "apps/web.env"), entry("B", "2", "g", "apps/web.env")}
	env.Files["made/aws/keys/signing/k1.key"] = &model.FileEntry{Data: []byte("k"), Mode: 0o600, Sha: model.SHA256([]byte("k"))}
	files, err := proj().Render(snap, "e", "", false)
	eq(t, err, nil, "render")
	eq(t, len(files), 2, "two files")
	eq(t, []any{files[0].Rel, files[0].Mode, string(files[0].Data)}, []any{"apps/web.env", 0o600, "A=\"x y\"\n# c\nB=2\n"}, "settings file")
	eq(t, []any{files[1].Rel, files[1].Mode}, []any{"made/aws/keys/signing/k1.key", 0o400}, "the rule's mode wins")
	// drift
	changed, missing, extra := Drift(files, map[string]string{"apps/web.env": "deadbeef", "stray": "x"})
	eq(t, [][]string{changed, missing, extra}, [][]string{{"apps/web.env"}, {"made/aws/keys/signing/k1.key"}, {"stray"}}, "drift")
}

func mustLayout(text string) Layout { l, _ := ParseEnv(text); return l }

func entry(key, val, group, rel string) *model.Entry {
	e := model.NewEntry(key, val, group, "p/"+key)
	e.Labels = []string{LabelFile + rel}
	return e
}

func TestAppFiles(t *testing.T) {
	snap := snapOf(t, row{"environments/e/web", "BASE_HOST", "example.org", own}, row{"environments/e/web", "SITE", "s", own},
		row{"environments/e/web", "WIDGET_ALT_SITE_KEY", "rk", own})
	p := proj()
	example := "PUBLIC_BASE_HOST=\n# PUBLIC_UNUSED=x\nPUBLIC_WIDGET_SITE_KEY=\nPUBLIC_BASE_HOST=dup\nHTTP_PORT=8080\nDEV_ORIGINS=http://localhost\nPUBLIC_ACTIVE=dflt\n"
	app := &project.App{Name: "store", From: webRel, Prefix: "PUBLIC_", Plain: []string{"DEV_ORIGINS"}, Aliases: map[string][]string{"PUBLIC_WIDGET_SITE_KEY": {"WIDGET_SITE_KEY", "WIDGET_ALT_SITE_KEY"}}}
	vars := AppVariables(app, example)
	eq(t, len(vars), 5, "app variables (listeners and duplicates left out)")
	eq(t, vars[1], AppVar{"PUBLIC_UNUSED", false, "x"}, "commented row")
	text, report, err := p.AppFileText(snap, "e", app, example, "")
	eq(t, err, nil, "app text")
	eq(t, text, "PUBLIC_BASE_HOST=example.org\nPUBLIC_WIDGET_SITE_KEY=rk\nDEV_ORIGINS=http://localhost\nPUBLIC_ACTIVE=dflt\n", "app file")
	eq(t, report[1], AppReport{"PUBLIC_WIDGET_SITE_KEY", "vault WIDGET_ALT_SITE_KEY"}, "alias source")
	eq(t, report[2], AppReport{"DEV_ORIGINS", "example value"}, "example source")
	dtext, _, _ := p.AppFileText(snap, "e", &project.App{Name: "jobs", From: webRel, All: true}, "", "")
	eq(t, dtext, "BASE_HOST=example.org\nWIDGET_ALT_SITE_KEY=rk\n", "daemon file only has values (SITE is not in the manifest, so not rendered)")
}

func TestVisibilityAudit(t *testing.T) {
	snap := snapOf(t,
		row{"environments/e", ".item", "", "state=active"},
		row{"environments/e/g", "BASE_HOST", "d", "managed-by=owner\nvisibility=secret"},       // legacy secret? BASE_HOST is known: legacy plain -> kept-differs
		row{"environments/e/g", "WIDGET_SITE_KEY", "k", "managed-by=owner\nvisibility=secret"}, // legacy: unknown-to-name rule... change
		row{"environments/e/g", "WIDGET_ALT_SITE_KEY", "k", "managed-by=owner\nvisibility=secret\nvis-by=owner"},
		row{"environments/e/g", "FOURTH", "1", "managed-by=owner\nvisibility=sealed"},
		row{"environments/e/g", "SYS", "1", "managed-by=system\nvisibility=sealed"})
	rows, err := proj().VisibilityRows(snap, "e")
	eq(t, err, nil, "audit")
	got := map[string]string{}
	for _, r := range rows {
		got[r.Key] = r.Verdict
	}
	eq(t, got["WIDGET_ALT_SITE_KEY"], "kept-owner", "owner's choice")
	eq(t, got["FOURTH"], "kept-sealed", "never unsealed")
	if _, ok := got["SYS"]; ok {
		t.Error("system entries are not audited")
	}
	if _, err := proj().VisibilityRows(snap, "nope"); err == nil {
		t.Error("unknown environment")
	}
	eq(t, got["BASE_HOST"], "kept-differs", "legacy plain, now secret by hand")
	eq(t, got["WIDGET_SITE_KEY"], "change", "the old rule made it secret (name ends in _KEY); the new one says plain")
}

func TestStatusOf(t *testing.T) {
	snap := snapOf(t,
		row{"environments/e", ".item", "", "uses=mine/a,mine/gone\nstate=active"},
		row{"environments/e/web", "BASE_HOST", "own", own}, row{"environments/e/web", "FOURTH", "", own},
		row{"mine/a", ".item", "", "state=active"}, row{"mine/a/web", "BASE_HOST", "other", own}, row{"mine/a/web", "API_NAME", "x", "managed-by=owner\nlabels=file:apps/web.env"})
	st, err := proj().StatusOf(snap, "e", "")
	eq(t, err, nil, "status")
	eq(t, []any{st.Settings, st.Variables, st.Uses, st.BrokenLinks}, []any{1, 3, []string{"mine/a"}, []string{"mine/gone"}}, "counts")
	eq(t, len(st.Shadowed), 1, "shadowed")
	f := st.Files[0]
	eq(t, []any{f.Rel, f.Variables, f.FromLinks, f.Empty}, []any{"apps/web.env", 3, 1, []string{"FOURTH"}}, "file")
}

func TestPrecedenceOrderInTheVaultDoesNotDecide(t *testing.T) {
	blkRow := row{"environments/e1/c-aws", "POOL_NAME", "blk", "managed-by=owner\nvisibility=plain\nlabels=file:cloud/aws-site.env"}
	wideRow := row{"environments/e1/cluster", "POOL_NAME", "wide", own}
	head := row{"environments/e1", ".item", "", "state=active"}
	for _, rows := range [][]row{{head, blkRow, wideRow}, {head, wideRow, blkRow}} {
		snap := snapOf(t, rows...)
		aws, _, _ := proj().Effective(snap, "e1", "cloud/aws-site.env", "")
		google, _, _ := proj().Effective(snap, "e1", "cloud/gcp-site.env", "")
		eq(t, aws.M["POOL_NAME"], "blk", "block in its file")
		eq(t, google.M["POOL_NAME"], "wide", "wide elsewhere")
	}
}

func TestEnvironmentWideEntryFeedsOnlyFilesWithALayout(t *testing.T) {
	snap := snapOf(t, row{"environments/e1", ".item", "", "state=active"}, row{"environments/e1/cluster", "POOL_NAME", "wide", own})
	has := func() []string {
		v, _ := proj().View(snap, "e1", "")
		var out []string
		for _, r := range v.Rels() {
			if v.Env[r].Variables.M["POOL_NAME"] != "" {
				out = append(out, r)
			}
		}
		return out
	}
	eq(t, has(), []string{"cloud/aws-site.env", "cloud/gcp-site.env"}, "no layouts: every manifest file")
	snap.Item("environments", "e1").Blobs[StemOf("cloud/aws-site.env")] = []byte(`{"v": 1, "lines": []}`)
	v, _ := proj().View(snap, "e1", "")
	eq(t, v.Rels(), []string{"cloud/aws-site.env"}, "one layout: that file only")
}

func TestChecklistRowsSayPresentEmptyOrMissingWithTheHint(t *testing.T) {
	snap := snapOf(t,
		row{"environments/staging", ".item", "", "state=active"},
		row{"environments/staging/environment", "HOSTING", "aws", "managed-by=owner\nvisibility=plain"},
		row{"environments/staging/backup", "BACKUP_ACCESS_KEY", "", "managed-by=owner\nvisibility=secret\nlabels=file:apps/web.env"},
		row{"environments/staging/web", "BASE_HOST", "example.org", "managed-by=owner\nvisibility=plain"})
	c, err := proj().Checklist(snap, "staging", "")
	eq(t, err, nil, "checklist")
	eq(t, c.Provider, "aws", "provider")
	by := map[string]ChecklistRow{}
	for _, r := range c.Rows {
		by[r.File+" "+r.Key] = r
	}
	eq(t, by["base.env HOSTING"].State, "present", "present")
	eq(t, by["apps/web.env BACKUP_ACCESS_KEY"].State, "empty", "empty")
	eq(t, by["apps/web.env BACKUP_ACCESS_KEY"].Required, false, "NEEDED FOR, the feature not in use: not required")
	eq(t, strings.Contains(by["apps/web.env BACKUP_ACCESS_KEY"].Hint, "NEEDED FOR: off-site backups"), true, "hint")
	miss := by["apps/web.env BACKUP_SECRET_KEY"]
	eq(t, []any{miss.State, miss.Create != nil, miss.Create.Visibility, miss.Create.Labels}, []any{"missing", true, "secret", []string{"file:apps/web.env"}}, "missing: creatable")
	sys := by["apps/web.env COOKIE_SECRET"]
	eq(t, []any{sys.State, sys.Create == nil, sys.Required, sys.Managed}, []any{"missing", true, false, "system"}, "a system key is never created or required")
	// the rows depend on the provider: aws files are listed, google ones are not
	files := map[string]bool{}
	for _, r := range c.Rows {
		files[r.File] = true
	}
	eq(t, []bool{files["cloud/aws-site.env"], files["cloud/gcp-site.env"]}, []bool{true, false}, "provider files")
	// the count
	n := 0
	for _, r := range c.Rows {
		if r.Required && r.State != "present" {
			n++
		}
	}
	eq(t, c.Needed, n, "needed")
}
