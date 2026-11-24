// Package example is Lumen Notes, the made-up project of the tests and the demo: a whole project checkout (the description, the sample settings
// files, the committed settings of three environments, the plaintext trees of two of them and the checkouts of two apps) that uses every
// feature of the project description. All values are made up.
package example

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// DescriptionDeclaringKind is the example's description in the shape a project takes after it declares a connection kind of its own (format 3): the
// portal's ANALYTICS_ID and BILLING_ACCOUNT come from a connection of the declared kind "stats" (a made-up service), not from values of their own.
func DescriptionDeclaringKind() []byte {
	s := string(Description())
	s = strings.Replace(s, "format: 2", "format: 3", 1)
	s = strings.Replace(s, "      - {name: ANALYTICS_ID, label: {en: Analytics id}}\n", "", 1)
	s = strings.Replace(s, "      - {name: BILLING_ACCOUNT, label: {en: Billing account}, secret: true}\n", "", 1)
	s = strings.Replace(s, "products:\n", `connection-kinds:
  - id: stats
    title: {en: Stats service, uk: Сервіс статистики}
    help: {en: Page statistics of the portal.}
    fields:
      - {name: site_id, label: {en: Site id, uk: Ідентифікатор сайту}}
      - {name: token, label: {en: Token}, secret: true}
products:
`, 1)
	s = strings.Replace(s, "    connections:\n      - kind: s3\n        name: Blob store", `    connections:
      - kind: stats
        name: Stats
        optional: true
        file: services/portal.env
        variables:
          - {name: ANALYTICS_ID, field: site_id}
          - {name: BILLING_ACCOUNT, field: token, secret: true}
      - kind: s3
        name: Blob store`, 1)
	return []byte(s)
}
