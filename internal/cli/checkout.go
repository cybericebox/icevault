package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
)

// The project checkout: the folder of the project description (icevault-project.yaml). Every other path of the project is the description's
// (checkout: templates, environments, plaintext, vault), relative to that folder. The checkout is ICEVAULT_ROOT, else the nearest folder above the
// working directory that holds a description, else the place `where --remember` saved.

// findRoot is the project checkout of this process ("" when none is found).
func findRoot(getenv func(string) string) string {
	if r := getenv("ICEVAULT_ROOT"); r != "" {
		a, _ := filepath.Abs(r)
		return a
	}
	if wd, err := os.Getwd(); err == nil {
		if r := CheckoutAbove(wd); r != "" {
			return r
		}
	}
	// A program started from Finder has no shell environment and "/" as its directory: the place `where --remember` saved is the answer then.
	return savedRoot(getenv)
}

// CheckoutAbove is the nearest folder at or above dir that holds a project description ("" when none, up to the root of the disk).
func CheckoutAbove(dir string) string {
	dir = filepath.Clean(dir)
	for i := 0; i < 64; i++ {
		if isFile(filepath.Join(dir, project.FileName)) {
			return dir
		}
		up := filepath.Dir(dir)
		if up == dir {
			return ""
		}
		dir = up
	}
	return ""
}

// ValidRoot says whether dir is a project checkout: an absolute folder with a project description.
func ValidRoot(dir string) bool {
	return filepath.IsAbs(dir) && isFile(filepath.Join(dir, project.FileName))
}

// description loads the project description of the checkout (once per Env): the file in the checkout, else ICEVAULT_PROJECT, else the path the
// window was given.
func (e *Env) description() (*project.Description, error) {
	if e.desc != nil || e.descErr != nil {
		return e.desc, e.descErr
	}
	p := project.Find(e.Getenv, e.Root, SavedProject(e.Getenv))
	if p == "" {
		where := "(no project checkout found: ICEVAULT_ROOT names it)"
		if e.Root != "" {
			where = filepath.Join(e.Root, project.FileName)
		}
		e.descErr = fail("no project description: none at %s, ICEVAULT_PROJECT is not set and none is remembered", where)
		return nil, e.descErr
	}
	d, err := project.Load(p)
	if err != nil {
		e.descErr = fail("%v", err)
		return nil, e.descErr
	}
	e.desc = d
	return d, nil
}

// checkoutDir is the folder the paths of the description are relative to: the folder of the description.
func checkoutDir(d *project.Description) string {
	if d.Path == "" {
		return ""
	}
	a, _ := filepath.Abs(filepath.Dir(d.Path))
	return a
}

// plaintextRoot is <checkout>/<plaintext>, the folder of the plaintext trees.
func plaintextRoot(d *project.Description) string {
	return filepath.Join(checkoutDir(d), filepath.FromSlash(d.Checkout.Plaintext))
}

// committedSettings is <checkout>/<environments>/<env>/<general file>: the committed settings of an environment.
func committedSettings(d *project.Description, env string) string { return d.CommittedFile(env) }

// LoadProject reads the project description of the checkout root (or the one ICEVAULT_PROJECT names when root has none) and the sample
// settings files of its templates folder, and builds the project consumer.
func LoadProject(root string) (*render.Project, error) {
	p := filepath.Join(root, project.FileName)
	if root == "" || !isFile(p) {
		return nil, fail("no project description at %q (ICEVAULT_ROOT names the checkout)", p)
	}
	d, err := project.Load(p)
	if err != nil {
		return nil, fail("%v", err)
	}
	return projectOf(d)
}

// projectOf builds the consumer of a loaded description: the sample settings files and their translations from its templates folder.
func projectOf(d *project.Description) (*render.Project, error) {
	templates := map[string]string{}
	i18n := map[string]map[string]map[string]string{}
	if d.Checkout.Templates != "" {
		dir := filepath.Join(checkoutDir(d), filepath.FromSlash(d.Checkout.Templates))
		if real, err := filepath.EvalSymlinks(dir); err == nil { // WalkDir does not enter a root that is a link
			dir = real
		}
		for _, rel := range append(append([]string(nil), d.Files...), d.RetiredFiles...) {
			if data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel))); err == nil { // #nosec G304 -- a sample file of the checkout
				templates[rel] = string(data)
			}
		}
		for _, lang := range render.I18NLangs() {
			data, err := os.ReadFile(filepath.Join(dir, "i18n", lang+".json")) // #nosec G304 -- the translations of the samples
			if err != nil {
				continue
			}
			var m map[string]map[string]string
			if json.Unmarshal(data, &m) == nil {
				i18n[lang] = m
			}
		}
	}
	p := render.NewProject(d, templates)
	p.SetI18N(i18n)
	d.Walk(func(h project.Home) {
		for _, lang := range render.I18NLangs() {
			p.AddTranslation(lang, h.File+":"+h.Var.Name, h.Var.Help[lang])
		}
	})
	return p, nil
}

// loadProject is the consumer of this process's description.
func loadProject(e *Env) (*render.Project, error) {
	d, err := e.description()
	if err != nil {
		return nil, err
	}
	return projectOf(d)
}

// checkoutOfVault is the project checkout of a vault file: the nearest folder above it with a description; else saved when it is a checkout;
// else "" (the window asks for the folder).
func checkoutOfVault(vaultFile, saved string) string {
	if r := CheckoutAbove(filepath.Dir(filepath.Clean(vaultFile))); r != "" {
		return r
	}
	if saved != "" && ValidRoot(saved) {
		return filepath.Clean(saved)
	}
	return ""
}

func isUnder(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// DefaultVaultPath is the vault file the project description of the checkout root names (`checkout: vault`, relative to the checkout): the place
// init-vault makes it at. A description that names none gives IceVault.kdbx in the checkout. The window offers it for a new vault.
func DefaultVaultPath(root string) (string, error) {
	if !ValidRoot(root) {
		return "", fail("no project description at %q", filepath.Join(root, project.FileName))
	}
	d, err := project.Load(filepath.Join(root, project.FileName))
	if err != nil {
		return "", fail("%v", err)
	}
	if d.Checkout.Vault == "" {
		return filepath.Join(checkoutDir(d), "IceVault.kdbx"), nil
	}
	return filepath.Join(checkoutDir(d), filepath.FromSlash(d.Checkout.Vault)), nil
}
