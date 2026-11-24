package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cybericebox/icevault/internal/project"
	"github.com/cybericebox/icevault/internal/render"
)

// cmdProject: check | used --env E. Both read only the description and the committed settings of the checkout: no vault, no password.
// keyFiles is the key of the file lists in the JSON the commands print.
const keyFiles = "files"

func cmdProject(args []string, e *Env) error {
	if len(args) == 0 || (args[0] != "check" && args[0] != "used" && args[0] != "envs") {
		return &parseErr{msg: "project needs check, used or envs"}
	}
	sub := args[0]
	var env string
	if _, err := parse("project "+sub, args[1:], e, 0, func(fs *flag.FlagSet) {
		fs.StringVar(&env, "env", "", "the environment")
	}); err != nil {
		return err
	}
	d, err := e.description()
	if err != nil {
		return err
	}
	if sub == "envs" {
		for _, n := range envNames(d) {
			fmt.Fprintln(e.Out, n)
		}
		return nil
	}
	if sub == "check" {
		return printJSON(e.Out, map[string]any{"description": d.Path, "name": d.Name, "format": d.Format, keyFiles: d.Files, "problems": []string{}, "warnings": d.Warnings()})
	}
	if env == "" {
		return &parseErr{msg: "project used needs --env E"}
	}
	if !envNameRE.MatchString(env) {
		return fail("%q is not an environment name (lower case letters, digits and dashes)", env)
	}
	p := committedSettings(d, env)
	settings, err := readSettings(p)
	if err != nil {
		return fail("%s cannot be read: %v", p, err)
	}
	return printJSON(e.Out, fileUses(d, settings))
}

// fileUses is how an environment with these settings reads each file of the description: {"files": {file: "whole"|"partly"|"unused"},
// "partly": {file: [keys]}}.
func fileUses(d *project.Description, settings map[string]string) map[string]any {
	plat := render.NewProject(d, nil)
	u := plat.UsesFrom(settings)
	files := map[string]string{}
	partly := map[string][]string{}
	for _, f := range d.Files {
		switch u.FileUnused(f) {
		case "":
			files[f] = "whole"
		case render.UnusedPartly:
			files[f] = "partly"
			partly[f] = d.PartlyKeys(f)
		default:
			files[f] = "unused"
		}
	}
	return map[string]any{keyFiles: files, "partly": partly}
}

// readSettings reads KEY=value lines of a settings file (render.ReadSettings).
func readSettings(p string) (map[string]string, error) { return render.ReadSettings(p) }

// envNames are the environments of the checkout: the folders of its committed settings and of its plaintext trees, sorted.
func envNames(d *project.Description) []string {
	set := map[string]bool{}
	for _, dir := range []string{filepath.Join(checkoutDir(d), filepath.FromSlash(d.Checkout.Environments)), plaintextRoot(d)} {
		ents, _ := os.ReadDir(dir)
		for _, en := range ents {
			if en.IsDir() && envNameRE.MatchString(en.Name()) {
				set[en.Name()] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
