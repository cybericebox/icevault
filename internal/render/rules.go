package render

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
)

// Rule is one row of the table of kept files.
type Rule struct {
	Name    string
	Pattern string // over the path below the environment's private directory, "/" separators
	Mode    int
	Why     string
	Managed string // files: owner (a person changes it) or system (commands generate it)
}

// EnvRule is the rule of a settings file of the description (its files and its retired files), nil for any other path.
func (p *Project) EnvRule(rel string) *Rule {
	if !contains(p.D.Files, rel) && !p.D.Retired(rel) {
		return nil
	}
	return &Rule{Name: "settings file", Pattern: regexp.QuoteMeta(rel), Mode: 0o600, Why: "a settings file of the project", Managed: model.ManagedOwner}
}

// FileRule is the rule of kept-files that covers a path (the first that matches), nil when none does.
func (p *Project) FileRule(rel string) *Rule {
	k := p.D.Kept(rel)
	if k == nil {
		return nil
	}
	mode, _ := project.ParseMode(k.Mode)
	managed := k.Managed
	if managed == "" {
		managed = model.ManagedSystem
	}
	return &Rule{Name: k.Name, Pattern: k.Pattern, Mode: mode, Why: k.Why, Managed: managed}
}

// Classify is ("env"|"file", rule), or ("", nil) when the path is not kept.
func (p *Project) Classify(rel string) (string, *Rule) {
	if r := p.EnvRule(rel); r != nil {
		return KindEnv, r
	}
	if r := p.FileRule(rel); r != nil {
		return KindFile, r
	}
	return "", nil
}

// Excluded reports whether the path is on the left-out list.
func (p *Project) Excluded(rel string) bool { return p.D.LeftOutWhy(rel) != "" }

const (
	LabelFile = "file:"
)

// StemOf: services/portal.env -> services-portal; a file without a folder -> its name without the extension (core.env -> core).
func StemOf(rel string) string {
	if !strings.Contains(rel, "/") {
		if i := strings.LastIndex(rel, "."); i > 0 {
			return rel[:i]
		}
		return rel
	}
	return strings.ReplaceAll(strings.TrimSuffix(rel, ".env"), "/", "-")
}

// RelOfStem is the inverse of StemOf for the files of the description; "" when the stem is not one.
func (p *Project) RelOfStem(stem string) string {
	for _, rel := range append(append([]string(nil), p.D.Files...), p.D.RetiredFiles...) {
		if StemOf(rel) == stem {
			return rel
		}
	}
	return ""
}

// NeededUntil says how long a retired file must be kept.
func (p *Project) NeededUntil(rel string) string {
	if k := p.D.Kept(rel); k != nil && k.NeededUntil != "" {
		return k.NeededUntil
	}
	return "nothing needs it any more"
}

// RetireFile: a changed or removed file of a rule with keep-retired is kept as retired.
func (p *Project) RetireFile(rel string) bool {
	k := p.D.Kept(rel)
	return k != nil && k.KeepRetired
}

// SiteBound: the files that belong to ONE site of an environment (the rules marked site-bound).
func (p *Project) SiteBound(rel string) bool {
	k := p.D.Kept(rel)
	return k != nil && k.SiteBound
}

var placeholderRE = regexp.MustCompile(`CHANGE-ME|<[A-Za-z_ ]+>`)

// StoredValue is what goes into an entry: an owner placeholder (empty,
// CHANGE-ME, <fill in>) is an EMPTY password.
func StoredValue(value, managed string) string {
	if managed == model.ManagedOwner && (strings.TrimSpace(value) == "" || placeholderRE.MatchString(value)) {
		return ""
	}
	return value
}

// Needed: an empty entry whose own notes say REQUIRED: (a key the manifest does not list; for the manifest's keys see Project.NeededNow, where
// NEEDED FOR: counts only once the feature is in use).
func Needed(notes, value string) bool {
	return value == "" && strings.Contains(notes, "REQUIRED:")
}

// ---- the pair (environment, site)

// SessionDirName is the name of the session directory of a pair (a fixed name: paths end up in Terraform state):
// <prefix>-<uid>-<env>[-<site>]. The caller joins it to the temp directory.
func (p *Project) SessionDirName(uid int, env, site string) string {
	n := fmt.Sprintf("%s-%d-%s", p.D.SessionPrefix(), uid, env)
	if site != "" {
		n += "-" + site
	}
	return n
}

// PickSite is the site of the pair a command works on. Never stored, never
// guessed: --site S names it; it may be left out only when the environment has
// settings for exactly one site; with two or more the command stops and lists
// them. "" when the environment has no site-limited settings at all.
func PickSite(snap *model.Snapshot, env, site string) (string, error) {
	known := snap.SitesOf(env)
	if site != "" {
		if !model.NameRE.MatchString(site) {
			return "", &model.StoreError{Msg: fmt.Sprintf("'%s' is not a site name (lower case letters, digits, - and _)", site)}
		}
		if len(known) > 0 && !contains(known, site) {
			return "", &model.StoreError{Msg: fmt.Sprintf("'%s' has no settings on site '%s' (it has: %s); to add a site, limit a group to it in the screen", env, site, strings.Join(known, ", "))}
		}
		return site, nil
	}
	if len(known) > 1 {
		return "", &model.StoreError{Msg: fmt.Sprintf("'%s' has settings on %s: add --site to name the one this command is for", env, strings.Join(known, ", "))}
	}
	if len(known) == 1 {
		return known[0], nil
	}
	return "", nil
}

// CheckLinks: a link to an item that is gone stops a run.
func CheckLinks(snap *model.Snapshot, env string) error {
	for _, l := range snap.BrokenLinks(model.SecEnvs, env) {
		return &model.StoreError{Msg: fmt.Sprintf("environment '%s' links %s/%s, which does not exist (any more): remove the link in the screen (`icevault ui`)", env, l.Section, l.Name)}
	}
	return nil
}

// ---- classification of a private tree and of foreign files (import)

// TreeFiles classifies the relative paths of a private tree (plus extra
// single files that live elsewhere): the kept files with their kind and rule,
// the left-out names and the not-covered ones.
func (p *Project) TreeFiles(rels, extra []string) (covered map[string]Covered, skipped, unknown []string) {
	covered = map[string]Covered{}
	for _, rel := range extra {
		k, r := p.Classify(rel)
		covered[rel] = Covered{k, r}
	}
	sorted := append([]string(nil), rels...)
	sort.Strings(sorted)
	for _, rel := range sorted {
		if k, r := p.Classify(rel); r != nil {
			covered[rel] = Covered{k, r}
		} else if p.Excluded(rel) {
			skipped = append(skipped, rel)
		} else {
			unknown = append(unknown, rel)
		}
	}
	return
}

// Covered is a kept file: "env" or "file" and its rule (nil for an extra file no rule knows).
type Covered struct {
	Kind string
	Rule *Rule
}
