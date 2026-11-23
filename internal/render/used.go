package render

import (
	"regexp"
	"strings"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/project"
)

// Which settings files an environment uses: the used-when and partly-used conditions of the description's files, over the settings of the
// environment's general file (with the defaults of the description). A file the environment does not use is "unused": its keys never count in
// "needed for deploy". It is still stored and rendered into its own file: nothing here moves or deletes an entry.

// The reasons a file or a key is not used.
const (
	UnusedPartly = "partly" // only the keys of partly-used are read
	Unused       = "unused" // the file is not read
)

// Uses is how one environment uses the settings files.
type Uses struct {
	d     *project.Description
	get   func(string) string
	known bool
}

// UsesFrom is the use of the files by an environment with these settings of its general file. No settings at all: nothing is called unused.
func (p *Project) UsesFrom(settings map[string]string) Uses {
	return Uses{d: p.D, get: func(k string) string { return settings[k] }, known: len(settings) > 0}
}

// UsesOf is the use of the files by an environment of the vault (nothing is unused when its settings cannot be read).
func (p *Project) UsesOf(snap *model.Snapshot, env string) Uses {
	s, err := p.Settings(snap, env, "")
	if err != nil {
		return Uses{d: p.D}
	}
	return p.UsesFrom(s)
}

// FileUnused is why the environment does not read the settings file rel whole: "" when it does, UnusedPartly when it reads some keys of it,
// Unused when none.
func (u Uses) FileUnused(rel string) string {
	if !u.known || u.d == nil {
		return ""
	}
	switch u.d.FileUse(rel, u.get) {
	case project.UsePartly:
		return UnusedPartly
	case project.UseNone:
		return Unused
	}
	return ""
}

// KeyUnused is why the environment does not read the key of the settings file rel, "" when it does.
func (u Uses) KeyUnused(rel, key string) string {
	r := u.FileUnused(rel)
	if r == UnusedPartly && contains(u.d.PartlyKeys(rel), key) {
		return ""
	}
	return r
}

// Get is the value of a setting of the environment as conditions read it (the default applied).
func (u Uses) Get(key string) string {
	if u.d == nil || u.get == nil {
		return ""
	}
	return u.d.Getter(u.get)(key)
}

// ---- "needed for deploy"

var sectionHeadRE = regexp.MustCompile(`^#\s*={3,}\s*(.*?)\s*={3,}\s*$`)

// featuresOf maps each key of a template that carries "NEEDED FOR:" to its feature: the section header (# ===== Backups =====) it sits under.
// The NEEDED FOR texts themselves may differ from key to key, the section does not.
func featuresOf(text string) map[string]string {
	out := map[string]string{}
	section, comment := "", ""
	for _, ln := range strings.Split(text, "\n") {
		s := strings.TrimSpace(ln)
		if m := sectionHeadRE.FindStringSubmatch(s); m != nil {
			section, comment = m[1], ""
			continue
		}
		if s == "" {
			comment = ""
			continue
		}
		if strings.HasPrefix(s, "#") {
			comment += s + "\n"
			continue
		}
		if m := keyLineRE.FindStringSubmatch(s); m != nil {
			if strings.Contains(comment+m[2], "NEEDED FOR:") {
				out[m[1]] = section
			}
			comment = ""
		}
	}
	return out
}

// NeededNow says whether deploy needs the key of the settings file rel: the template says "REQUIRED:" (or the description required:), or it
// says "NEEDED FOR:" and another key of the same feature is set (isSet), so the feature is in use. A key the manifest does not list is never
// needed.
func (p *Project) NeededNow(rel, key string, isSet func(key string) bool) bool {
	for _, r := range p.manifest[rel] {
		if r.Key != key {
			continue
		}
		if r.Required {
			return true
		}
		if !r.NeededFor {
			return false
		}
		f, ok := p.feature[rel][key]
		if !ok {
			return false
		}
		for k2, f2 := range p.feature[rel] {
			if k2 != key && f2 == f && isSet(k2) {
				return true
			}
		}
		return false
	}
	return false
}
