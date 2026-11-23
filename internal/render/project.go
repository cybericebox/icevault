package render

import (
	"regexp"
	"strings"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
)

// Names shared by the rules of the project consumer.
const (
	KindEnv  = "env"  // a settings file (one entry per variable)
	KindFile = "file" // any other kept file (an attachment)

	// SourceEnvironment is the source label of a value that lives in the environment item itself.
	SourceEnvironment = "environment"
)

var (
	secretWords  = map[string]bool{"TOKEN": true, "PASSWORD": true, "PASSWD": true, "SECRET": true, "SIGNATURE": true, "CREDENTIAL": true, "CREDENTIALS": true, "PRIVATE": true, "SALT": true, "APIKEY": true}
	keyNotSecret = map[string]bool{"ID": true, "NAME": true, "PATH": true, "FILE": true, "TYPE": true, "SIZE": true, "LENGTH": true, "VERSION": true, "PREFIX": true, "URL": true, "FORMAT": true}
)

// LooksSecret: a name that reads as a secret: one of the words token,
// password, secret, signature, credential, private, salt, or KEY (whole words,
// so KEYCLOAK and MONKEY are not hits). KEY is public in SITE_KEY and
// PUBLIC_KEY, and a name or an id in KEY_ID, KEY_NAME, KEY_PATH...;
// ACCESS_KEY_ID stays secret.
func LooksSecret(name string) bool {
	words := strings.Split(strings.ToUpper(name), "_")
	for i, w := range words {
		if secretWords[w] {
			return true
		}
		if w == "KEY" || w == "KEYS" {
			prev, next := "", ""
			if i > 0 {
				prev = words[i-1]
			}
			if i+1 < len(words) {
				next = words[i+1]
			}
			if prev == "SITE" || prev == "PUBLIC" || (keyNotSecret[next] && prev != "ACCESS") {
				continue
			}
			return true
		}
	}
	return false
}

// GroupOf is the group a variable of a settings file is shown in when the model gives it none: the file's stem.
func GroupOf(rel string) string { return StemOf(rel) }

// LabelsFor is the label that narrows an entry to a settings file.
func LabelsFor(rel string) []string { return []string{LabelFile + rel} }

// Row is a row of the manifest: a key of a settings file with its comment.
// Required: the template comment says "REQUIRED:" or the description marks the variable required. NeededFor: the comment says
// "NEEDED FOR: <feature>": needed only once the feature is in use, i.e. a sibling key of the same feature is set (Project.NeededNow).
type Row struct {
	Key       string
	Comment   string
	Required  bool
	Secret    bool
	NeededFor bool
}

// Project is the consumer of the generic store: the project description and the manifest (the keys of every settings file: the sample files of
// the checkout where it has them, else the variables the description gives the file) and what is derived from them.
type Project struct {
	D        *project.Description
	manifest map[string][]Row
	rels     []string
	explicit map[string]bool              // names a template marks "# secret"
	feature  map[string]map[string]string // settings file -> "NEEDED FOR:" key -> its feature (the template section it sits in)
	keymap   map[string][]string
	i18n     map[string]map[string]string // lang -> "<settings file>:<KEY>" -> text
}

// NewProject builds the consumer from the description and the text of the sample settings files (key: the path below the templates folder, as
// "shop/web.env"; nil when the project has none). The settings files are in the order of the description's files.
func NewProject(d *project.Description, templates map[string]string) *Project {
	p := &Project{D: d, manifest: map[string][]Row{}, explicit: map[string]bool{}, keymap: map[string][]string{}, feature: map[string]map[string]string{}}
	rels := append(append([]string(nil), d.Files...), d.RetiredFiles...)
	for _, rel := range rels {
		text, ok := templates[rel]
		if !ok {
			p.manifest[rel] = p.describedRows(rel)
			p.rels = append(p.rels, rel)
			continue
		}
		p.feature[rel] = featuresOf(text)
		_, vars := ParseEnv(text)
		secretRows := map[string]bool{}
		for _, ln := range strings.Split(text, "\n") {
			if strings.Contains(ln, "# secret") {
				if m := keyLineRE.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
					secretRows[m[1]] = true
				}
			}
		}
		var rows []Row
		for _, v := range vars {
			req := strings.Contains(v.Notes, "REQUIRED:") || p.describedRequired(rel, v.Name)
			rows = append(rows, Row{v.Name, v.Notes, req, secretRows[v.Name] || p.describedSecret(rel, v.Name) || LooksSecret(v.Name), strings.Contains(v.Notes, "NEEDED FOR:")})
			if secretRows[v.Name] {
				p.explicit[v.Name] = true
			}
		}
		p.manifest[rel] = rows
		p.rels = append(p.rels, rel)
	}
	for _, rel := range p.rels {
		for _, r := range p.manifest[rel] {
			p.keymap[r.Key] = append(p.keymap[r.Key], rel)
		}
	}
	return p
}

// describedRows are the rows of a file the checkout has no sample of: the variables the description gives it, in its order, and in the
// general file the derived and the place variables after them.
func (p *Project) describedRows(rel string) []Row {
	var rows []Row
	seen := map[string]bool{}
	add := func(name, help string, required, secret bool) {
		if seen[name] {
			return
		}
		seen[name] = true
		rows = append(rows, Row{Key: name, Comment: help, Required: required, Secret: secret || LooksSecret(name)})
	}
	p.D.Walk(func(h project.Home) {
		if h.File == rel {
			add(h.Var.Name, h.Var.Help["en"], h.Var.Required, h.Var.Secret)
		}
	})
	if rel == p.D.GeneralFile() {
		for _, x := range p.D.Derived {
			add(x.Name, "", false, false)
		}
		for _, pr := range p.D.Products {
			if pr.PlaceVariable != "" {
				add(pr.PlaceVariable, "", false, false)
			}
		}
	}
	return rows
}

func (p *Project) describedRequired(rel, name string) bool {
	for _, h := range p.D.Homes(rel, name) {
		if h.Var.Required {
			return true
		}
	}
	return false
}

func (p *Project) describedSecret(rel, name string) bool {
	for _, h := range p.D.Homes(rel, name) {
		if h.Var.Secret {
			return true
		}
	}
	return false
}

// RequiredNow says whether the description requires the variable of a file for an environment with these settings (required, or
// required-when holds).
func (p *Project) RequiredNow(rel, name string, get func(string) string) bool {
	for _, h := range p.D.Homes(rel, name) {
		if h.Var.Required {
			return true
		}
		if h.Var.RequiredWhen != "" {
			if c, err := project.ParseWhen(h.Var.RequiredWhen); err == nil && c.Holds(p.D.Getter(get)) {
				return true
			}
		}
	}
	return false
}

// Conf is the general settings file of an environment (the description's general file).
func (p *Project) Conf() string { return p.D.GeneralFile() }

// Manifest is the rows of one settings file.
func (p *Project) Manifest(rel string) []Row { return p.manifest[rel] }

// ManifestFiles lists the settings files of the manifest in order.
func (p *Project) ManifestFiles() []string { return append([]string(nil), p.rels...) }

// VarManaged: model.ManagedSystem for a variable the description marks as written by the project's scripts in some file, else
// model.ManagedOwner.
func (p *Project) VarManaged(name string) string {
	sys := false
	p.D.Walk(func(h project.Home) { sys = sys || (h.Var.Name == name && h.Var.System()) })
	if sys {
		return model.ManagedSystem
	}
	return model.ManagedOwner
}

// VarManagedIn is who manages the variable name of the settings file rel: system when the description marks it so in that file (managed:
// system or generated), else owner. rel "" (the file is not known): system when it is so in any file.
func (p *Project) VarManagedIn(rel, name string) string {
	if rel == "" {
		return p.VarManaged(name)
	}
	if p.D.SystemVar(rel, name) {
		return model.ManagedSystem
	}
	return model.ManagedOwner
}

// IsSecret: the template mark of a name in a file, else the description, else the name rule.
func (p *Project) IsSecret(rel, name string) bool {
	for _, r := range p.manifest[rel] {
		if r.Key == name {
			return r.Secret
		}
	}
	return p.describedSecret(rel, name) || LooksSecret(name)
}

// DefaultVisibility: plain | secret | sealed for a new variable.
func (p *Project) DefaultVisibility(rel, name, managed string) string {
	if managed == model.ManagedSystem && p.D.GeneratedVar(name) { // a generated secret; a value a script fills in (a path, a bucket name) follows the name rule
		return model.VisSealed
	}
	if p.IsSecret(rel, name) {
		return model.VisSecret
	}
	return model.VisPlain
}

// ProposedVisibility is the visibility the rule gives an owner variable by its key: secret when a sample file marks it "# secret" or the
// description marks it secret in any file, or its name looks secret, else plain.
func (p *Project) ProposedVisibility(key string) string {
	found, anySecret := false, false
	for _, rel := range p.rels {
		for _, r := range p.manifest[rel] {
			if r.Key == key {
				found = true
				anySecret = anySecret || r.Secret
			}
		}
	}
	if (found && anySecret) || (!found && LooksSecret(key)) {
		return model.VisSecret
	}
	return model.VisPlain
}

// EntryRels: the settings files an entry renders into: its file: labels, else every file of the manifest that has its key, else none (stored
// only). have = the settings files the environment has a stored layout for: an entry without a narrowing label then feeds only those. nil = no
// such knowledge.
func (p *Project) EntryRels(e *model.Entry, have map[string]bool) []string {
	var labelled []string
	for _, l := range e.Labels {
		if strings.HasPrefix(l, LabelFile) {
			labelled = append(labelled, l[len(LabelFile):])
		}
	}
	if len(labelled) > 0 {
		return labelled
	}
	rels := p.keymap[e.Key]
	if len(have) == 0 {
		return append([]string(nil), rels...)
	}
	var out []string
	for _, r := range rels {
		if have[r] {
			out = append(out, r)
		}
	}
	return out
}

// EntryScope is "block" when the entry is narrowed to settings files AND the narrowing means something (the key is listed by other than
// exactly one settings file); "environment" otherwise.
func (p *Project) EntryScope(e *model.Entry) string {
	narrowed := false
	for _, l := range e.Labels {
		narrowed = narrowed || strings.HasPrefix(l, LabelFile)
	}
	if narrowed && len(p.keymap[e.Key]) != 1 {
		return "block"
	}
	return "environment"
}

// EntryRel is the first file an entry renders into, or "".
func (p *Project) EntryRel(e *model.Entry) string {
	if r := p.EntryRels(e, nil); len(r) > 0 {
		return r[0]
	}
	return ""
}

// KeyFiles lists the settings files that list a key.
func (p *Project) KeyFiles(key string) []string { return append([]string(nil), p.keymap[key]...) }

// ManifestKey is "<file>:<KEY>" when description is the manifest's own comment of that key, else "".
func (p *Project) ManifestKey(key, description string) string {
	norm := strings.Join(strings.Fields(description), " ")
	for _, rel := range p.rels {
		for _, r := range p.manifest[rel] {
			if r.Key == key && r.Comment != "" && strings.Join(strings.Fields(r.Comment), " ") == norm {
				return rel + ":" + key
			}
		}
	}
	return ""
}

// StripBlock removes the file: labels.
func StripBlock(labels []string) []string {
	var out []string
	for _, l := range labels {
		if !strings.HasPrefix(l, LabelFile) {
			out = append(out, l)
		}
	}
	return out
}

// I18NLangs are the languages of the manifest translations (English is the text of the files).
func I18NLangs() []string {
	var out []string
	for _, l := range project.Languages {
		if l != "en" {
			out = append(out, l)
		}
	}
	return out
}

// SetI18N sets the translations of the manifest comments: <templates>/i18n/<lang>.json = {"<settings file>": {"<KEY>": text}}, given per
// language as parsed.
func (p *Project) SetI18N(data map[string]map[string]map[string]string) {
	p.i18n = map[string]map[string]string{}
	for _, lang := range I18NLangs() {
		flat := map[string]string{}
		for rel, rows := range data[lang] {
			for k, text := range rows {
				flat[rel+":"+k] = text
			}
		}
		p.i18n[lang] = flat
	}
}

// AddTranslation gives a manifest text of a language that the translation tables do not have (the help of the project description); a text
// the tables have stays.
func (p *Project) AddTranslation(lang, key, text string) {
	if text == "" || !contains(I18NLangs(), lang) {
		return
	}
	if p.i18n == nil {
		p.i18n = map[string]map[string]string{}
	}
	if p.i18n[lang] == nil {
		p.i18n[lang] = map[string]string{}
	}
	if _, ok := p.i18n[lang][key]; !ok {
		p.i18n[lang][key] = text
	}
}

// Translations is {lang: {"<settings file>:<KEY>": text}} (every language present, maybe empty).
func (p *Project) Translations() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, lang := range I18NLangs() {
		out[lang] = map[string]string{}
		for k, v := range p.i18n[lang] {
			out[lang][k] = v
		}
	}
	return out
}

// ProviderName is the provider word of the environment's site (the derived variable from site.provider), "" when none.
func (p *Project) ProviderName(snap *model.Snapshot, env string) string {
	s, err := p.Settings(snap, env, "")
	if err != nil {
		return ""
	}
	for _, x := range p.D.Derived {
		if x.From == "site.provider" {
			return s[x.Name]
		}
	}
	return ""
}

func contains(list []string, x string) bool {
	for _, l := range list {
		if l == x {
			return true
		}
	}
	return false
}

var secretNameRE = regexp.MustCompile(`(?i)SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|CREDENTIAL|API_KEY|ACCESS_KEY|_KEY$|SIGNATURE|SALT`)

// LegacyVisibility is what an import of an earlier version gave an owner variable (a key the manifest does not know was secret, and so was a
// name with a secret-like part): the visibility audit leaves a value that differs from it as the owner set it.
func (p *Project) LegacyVisibility(key string) string {
	known := len(p.keymap[key]) > 0
	if !known || secretNameRE.MatchString(key) || p.explicit[key] {
		return model.VisSecret
	}
	return model.VisPlain
}
