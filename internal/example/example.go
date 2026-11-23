// Package example is Lumen Notes, the made-up project of the tests and the demo: a whole project checkout (the description, the sample settings
// files, the committed settings of three environments, the plaintext trees of two of them and the checkouts of two apps) that uses every
// feature of the project description. All values are made up.
package example

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed all:checkout
var tree embed.FS

// Write puts the checkout into dir (made when missing; files of mode 0600, scripts 0700).
func Write(dir string) error {
	return fs.WalkDir(tree, "checkout", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("checkout", filepath.FromSlash(p))
		data, err := tree.ReadFile(p)
		if err != nil {
			return err
		}
		dest := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if filepath.Ext(rel) == ".sh" {
			mode = 0o700
		}
		return os.WriteFile(dest, data, mode)
	})
}

// Description is the text of the example's project description.
func Description() []byte {
	b, _ := tree.ReadFile("checkout/icevault-project.yaml")
	return b
}

// Environments are the environments of the example with a plaintext tree.
var Environments = []string{"prod", "staging"}
