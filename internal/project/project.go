// Package project reads the project description file: what a project deploys with the tool (its products, the variables of each product, of each
// site kind it supports and of General, the connections they need and under which variable names their fields are exported, the files its scripts
// read). Format is the version of the format this tool reads. The tool knows the concepts (internal/kinds); a project names its own things here.
package project

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cybericebox/icevault/internal/kinds"
)

// Format is the newest version of the description format this tool reads; MinFormat is the oldest. Format 3 adds connection-kinds (a
// description that declares kinds says format: 3, so an older tool refuses it by the format number).
const (
	Format    = 3
	MinFormat = 2
)

// FileName is the name of the description in the root of a project checkout.
const FileName = "icevault-project.yaml"

// Languages are the languages of labels and help texts.
var Languages = []string{"en", "uk", "ru"}

// Text is a text per language (en, uk, ru); a missing language falls back to en.
type Text map[string]string

// In returns the text in lang, else in English, else "".
func (t Text) In(lang string) string {
	if s := t[lang]; s != "" {
		return s
	}
	return t["en"]
}

// Variable is a variable of the project.
type Variable struct {
	Name string `yaml:"name"`
	// File is the project file the variable is exported into (default: the file of what holds it).
	File  string `yaml:"file,omitempty"`
	Label Text   `yaml:"label,omitempty"`
	Help  Text   `yaml:"help,omitempty"`
	// Secret: masked in the window, a secret entry in the vault. Default: plain.
	Secret   bool `yaml:"secret,omitempty"`
	Required bool `yaml:"required,omitempty"`
	// RequiredWhen: required only while this condition holds (KEY=value ..., see cond.go); required: true is required always.
	RequiredWhen string `yaml:"required-when,omitempty"`
	// When is the condition under which the variable is used (the language of cond.go). The window shows a variable whose condition is false
	// only on request.
	When string `yaml:"when,omitempty"`
	// WhenOff says whether a stored value whose condition is false is still kept as data (keep, the default) or read by nothing (drop).
	WhenOff string `yaml:"when-off,omitempty"`
	// Managed: owner (default) or system: written by the project's scripts, never edited by hand.
	Managed string `yaml:"managed,omitempty"`
	// Generated: a secret the scripts generate once (managed by the system; sealed in the window).
	Generated bool `yaml:"generated,omitempty"`
	// Temporary: needed only for a first setup; flagged for removal.
	Temporary bool `yaml:"temporary,omitempty"`
	// Field is the field of the connection kind this variable carries (connection uses only).
	Field string `yaml:"field,omitempty"`
	// Expires: the value is a token with a lifetime; the window asks for the date it expires (optional, "never" is allowed) and the tool warns
	// when it has expired or is about to.
	Expires bool `yaml:"expires,omitempty"`
	// Type is what a filled value must be: string (the default, free text), bool (true or false), int, email, url, domain or enum (one of Choices).
	// A value that is a reference (${{ ... }}) is checked after it resolves.
	Type    string   `yaml:"type,omitempty"`
	Choices []string `yaml:"choices,omitempty"`
	// Pattern is a regular expression (Go syntax) the whole value must match; for a string variable only.
	Pattern string `yaml:"pattern,omitempty"`
	// FileDefault (connection fields only): a path pattern (path.Match, relative, no ..) of a file a site that uses the connection keeps. While the
	// field is empty and such a file exists, the window says that the file is used instead of showing the field as not set. Names a file only, never
	// reads it.
	FileDefault string `yaml:"file-default,omitempty"`
	// Min and Max bound an int (inclusive); either may be left out.
	Min *int64 `yaml:"min,omitempty"`
	Max *int64 `yaml:"max,omitempty"`
}

// System reports whether the variable is managed by the system.
func (v Variable) System() bool { return v.Managed == "system" || v.Generated }

// ConnectionUse is a connection that a site kind, a product or the vault itself needs, and the names its fields are exported under.
type ConnectionUse struct {
	Kind string `yaml:"kind"`
	// Name is the name the migration gives a connection it makes for this use ("" = the title of the kind).
	Name string `yaml:"name,omitempty"`
	// Role says what for (dns, backups, state ...): shown next to the choice.
	Role string `yaml:"role,omitempty"`
	// File is the default project file of its variables.
	File     string `yaml:"file,omitempty"`
	Optional bool   `yaml:"optional,omitempty"`
	// ServeAs is the name a program asks `icevault external serve` for this connection under (its variables are the keys it reads and writes).
	ServeAs   string     `yaml:"serve-as,omitempty"`
	Variables []Variable `yaml:"variables"`
}

// SiteKind is what the project does with a site kind of the tool.
type SiteKind struct {
	// Provider is the word the project's files use for the kind (the value of a derived site.provider).
	Provider   string         `yaml:"provider"`
	File       string         `yaml:"file,omitempty"`
	Connection *ConnectionUse `yaml:"connection,omitempty"`
	State      *ConnectionUse `yaml:"state,omitempty"`
	Variables  []Variable     `yaml:"variables,omitempty"`
}

// Product is a product of the project.
type Product struct {
	Name  string `yaml:"name"`
	Title Text   `yaml:"title,omitempty"`
	Help  Text   `yaml:"help,omitempty"`
	// HelpOnSiteKind replaces Help where the product runs on a site of that kind (the text follows the placement: cluster, host, ...).
	HelpOnSiteKind map[string]Text `yaml:"help-on-site-kind,omitempty"`
	File           string          `yaml:"file,omitempty"`
	// PlaceVariable is the variable of the project's files that says where the product runs (cluster, compose, host, none, ...): written from
	// the product's place on export.
	PlaceVariable string                `yaml:"place-variable,omitempty"`
	Connections   []ConnectionUse       `yaml:"connections,omitempty"`
	Variables     []Variable            `yaml:"variables,omitempty"`
	OnSiteKind    map[string][]Variable `yaml:"on-site-kind,omitempty"`
}

// Group is the General group.
type Group struct {
	File      string     `yaml:"file,omitempty"`
	Variables []Variable `yaml:"variables"`
}

// Derived is a variable of the project's files that the tool writes from the model, never stored.
type Derived struct {
	Name string `yaml:"name"`
	File string `yaml:"file"`
	// From: site.provider (the Provider word of the kind of the site) or site.state-backend (the state backend word kept on the site).
	From string `yaml:"from"`
}

// Checkout says where the project keeps things in its checkout: paths relative to the folder of the description.
type Checkout struct {
	// Templates is the folder of the sample settings files (their keys, order and comments are the manifest); "" = none.
	Templates string `yaml:"templates,omitempty"`
	// Environments is the folder of the committed settings: <environments>/<env>/<the general file> (no secrets).
	Environments string `yaml:"environments"`
	// Plaintext is the folder of the plaintext trees: <plaintext>/<env>/ is what import reads and purge-plaintext deletes.
	Plaintext string `yaml:"plaintext"`
	// Vault is the vault file when none is named.
	Vault string `yaml:"vault"`
}

// Conditions tune how conditions read the settings of an environment.
type Conditions struct {
	// Defaults are the values of keys an environment does not set.
	Defaults map[string]string `yaml:"defaults,omitempty"`
	// WordBefore: a value is compared by its part before this text ("external:staging" is "external" with ":").
	WordBefore string `yaml:"word-before,omitempty"`
}

// FileSpec is a file of the project with the condition under which an environment reads it.
type FileSpec struct {
	Path string `yaml:"path"`
	// UsedWhen: the environment reads the file only while this holds ("" = always).
	UsedWhen string `yaml:"used-when,omitempty"`
	// Partly: while its condition holds (and UsedWhen does not), the environment reads only the keys listed.
	Partly *Partly `yaml:"partly-used,omitempty"`
}

// Partly is a partial use of a file.
type Partly struct {
	When string   `yaml:"when"`
	Keys []string `yaml:"keys"`
}

// UnmarshalYAML takes a file as a bare path or as a mapping.
func (f *FileSpec) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		f.Path = n.Value
		return nil
	}
	type plain FileSpec
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*f = FileSpec(p)
	return nil
}

// KeptFile is a rule of the plaintext tree: the files it matches (other than the settings files) are kept in the vault, one entry each.
type KeptFile struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"` // a regular expression over the path below <plaintext>/<env>/, matched whole
	Mode    string `yaml:"mode"`    // the file mode it is written with, octal ("0600")
	Why     string `yaml:"why,omitempty"`
	Managed string `yaml:"managed,omitempty"` // owner or system (default)
	// KeepRetired: a changed or removed file of this rule is kept in the vault as retired (key material a backup may still need).
	KeepRetired bool `yaml:"keep-retired,omitempty"`
	// NeededUntil says how long a retired file must be kept.
	NeededUntil string `yaml:"needed-until,omitempty"`
	// SiteBound: the file belongs to one site of the environment (cluster keys, kubeconfig), not to the whole environment.
	SiteBound bool `yaml:"site-bound,omitempty"`
	// Guard is the word of `icevault guard <word> --dir DIR`: the info file records whether the vault holds a file of this rule, so a script
	// asks without the password before it makes a new one. A guarded pattern ends with "/.+" (the directory the script names).
	Guard string `yaml:"guard,omitempty"`
}

// LeftOut is a path of the plaintext tree that is never kept, with the reason.
type LeftOut struct {
	Pattern string `yaml:"pattern"`
	Why     string `yaml:"why"`
}

// Session is what a session (a run of the project's scripts on the files of the vault) needs.
type Session struct {
	// Prefix names the session directories: <prefix>-<uid>-<env>[-<site>], and <prefix>-tf-... for the Terraform credentials.
	Prefix string `yaml:"prefix,omitempty"`
	// Persist are folders of <plaintext>/<env>/ linked into the session instead of copied: scripts keep non-secret state there.
	Persist []string `yaml:"persist,omitempty"`
	// Variables are the names of the variables a session gives the scripts it runs.
	Variables SessionVariables `yaml:"variables,omitempty"`
}

// SessionVariables are the names of the variables of a session ("" = the default ICEVAULT_ name).
type SessionVariables struct {
	Marker       string `yaml:"marker,omitempty"`        // "1" inside a session (ICEVAULT_SESSION)
	Environment  string `yaml:"environment,omitempty"`   // the environment (ICEVAULT_ENV)
	Site         string `yaml:"site,omitempty"`          // the site, when one is named (ICEVAULT_SITE)
	Tree         string `yaml:"tree,omitempty"`          // the session's tree of the project's files (ICEVAULT_TREE)
	SettingsFile string `yaml:"settings-file,omitempty"` // the JSON of the settings of the environments (ICEVAULT_SETTINGS_FILE)
	TokenFile    string `yaml:"token-file,omitempty"`    // the Terraform credentials file of the state connection (ICEVAULT_TF_TOKEN_FILE)
}

// WithDefaults fills the names left empty.
func (s SessionVariables) WithDefaults() SessionVariables {
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&s.Marker, "ICEVAULT_SESSION")
	def(&s.Environment, "ICEVAULT_ENV")
	def(&s.Site, "ICEVAULT_SITE")
	def(&s.Tree, "ICEVAULT_TREE")
	def(&s.SettingsFile, "ICEVAULT_SETTINGS_FILE")
	def(&s.TokenFile, "ICEVAULT_TF_TOKEN_FILE")
	return s
}

func (s SessionVariables) list() []string {
	return []string{s.Marker, s.Environment, s.Site, s.Tree, s.SettingsFile, s.TokenFile}
}

// App is an app whose local development settings file export-app writes.
type App struct {
	Name string `yaml:"name"`
	// Dir is the app's checkout, relative to the project checkout (default ../<name>).
	Dir string `yaml:"dir,omitempty"`
	// From is the project file whose values feed it.
	From string `yaml:"from"`
	// Example is the example file of the app that names its variables (default .env.example); with all: true none is read.
	Example string `yaml:"example,omitempty"`
	// All: every set variable of From, as it is.
	All bool `yaml:"all,omitempty"`
	// Prefix: a variable <prefix><KEY> of the example takes KEY of From.
	Prefix string `yaml:"prefix,omitempty"`
	// Plain are variables of the example taken under their own name.
	Plain []string `yaml:"plain,omitempty"`
	// Aliases: a variable of the example that takes the first set of other keys.
	Aliases map[string][]string `yaml:"aliases,omitempty"`
}

// RequiredCheck is a script of the checkout that status runs on a materialised tree of an environment: it prints the required values that still
// hold a placeholder as rows "  FILE KEY" after a line that starts with Heading. It runs as <interpreter> <script> <args...> in the checkout, with
// no shell: in the arguments {tree} is the tree, {provider} the provider word of the site and {env} the environment, each argument one word. It
// runs only while the user trusts the description (icevault trust).
type RequiredCheck struct {
	Script      string   `yaml:"script"`      // a path inside the checkout
	Interpreter string   `yaml:"interpreter"` // one of Interpreters
	Args        []string `yaml:"args,omitempty"`
	When        string   `yaml:"when,omitempty"`
	Heading     string   `yaml:"heading"`
}

// Interpreters are the programs a required-check script may run with.
var Interpreters = []string{"sh", "bash", "python3"}

// Description is a project description file.
type Description struct {
	Format     int        `yaml:"format"`
	Name       string     `yaml:"name"`
	Checkout   Checkout   `yaml:"checkout"`
	Conditions Conditions `yaml:"conditions,omitempty"`
	// FileSpecs are the files the project's scripts read, in the order an export writes them; the first is the general file of an environment.
	FileSpecs []FileSpec `yaml:"files"`
	// Files are the paths of FileSpecs.
	Files     []string   `yaml:"-"`
	KeptFiles []KeptFile `yaml:"kept-files,omitempty"`
	LeftOut   []LeftOut  `yaml:"left-out,omitempty"`
	Session   Session    `yaml:"session,omitempty"`
	Apps      []App      `yaml:"apps,omitempty"`
	// RequiredCheck is a script of the project that names the required values still to fill (status prints them).
	RequiredCheck *RequiredCheck      `yaml:"required-check,omitempty"`
	General       Group               `yaml:"general"`
	SiteKinds     map[string]SiteKind `yaml:"site-kinds"`
	Products      []Product           `yaml:"products"`
	// ConnectionKinds are the kinds of connections (an access to one outside service) the project declares besides the built-in ones.
	ConnectionKinds []ConnectionKind `yaml:"connection-kinds,omitempty"`
	// VaultConnections are connections the project uses outside any environment (CI tokens, say).
	VaultConnections []ConnectionUse `yaml:"vault-connections,omitempty"`
	Derived          []Derived       `yaml:"derived,omitempty"`
	// RetiredFiles are files the project no longer reads: the migration drops what only they hold.
	RetiredFiles []string `yaml:"retired-files,omitempty"`

	Path string `yaml:"-"`

	kept    []*regexp.Regexp
	leftOut []*regexp.Regexp
	raw     []byte // the bytes it was parsed from (Raw)
}

// Load reads and validates a description. Every problem is reported at once.
func Load(p string) (*Description, error) {
	data, err := os.ReadFile(p) // #nosec G304 -- the project description the owner names
	if err != nil {
		return nil, fmt.Errorf("the project description %s: %w", p, err)
	}
	d, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("the project description %s: %w", p, err)
	}
	d.Path = p
	return d, nil
}

// Raw is the exact bytes the description was parsed from: what a trust record hashes, so the settings a run uses are the ones that were trusted.
func (d *Description) Raw() []byte { return append([]byte(nil), d.raw...) }

// Parse reads and validates a description from its bytes. Unknown keys are an error (a typo never passes silently).
func Parse(data []byte) (*Description, error) {
	var d Description
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("not a valid description: %w", err)
	}
	for _, f := range d.FileSpecs {
		d.Files = append(d.Files, f.Path)
	}
	d.inheritFieldTypes()
	if errs := d.Validate(); len(errs) > 0 {
		return nil, &Errors{errs}
	}
	d.raw = append([]byte(nil), data...)
	return &d, nil
}

// Errors are the problems of a description.
type Errors struct{ List []string }

func (e *Errors) Error() string {
	more := ""
	list := e.List
	if len(list) > 12 {
		more = fmt.Sprintf(" (and %d more)", len(list)-12)
		list = list[:12]
	}
	return fmt.Sprintf("%d problem(s): %s%s", len(e.List), strings.Join(list, "; "), more)
}

var (
	nameRE    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,99}$`)
	productRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

func validFile(f string) bool {
	return f != "" && !strings.HasPrefix(f, "/") && path.Clean(f) == f && !strings.HasPrefix(f, "../") && f != ".."
}

// Validate lists every problem of the description.
func (d *Description) Validate() []string {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if d.Format < MinFormat || d.Format > Format {
		add("format is %d, this tool reads formats %d to %d (a newer description needs a newer IceVault)", d.Format, MinFormat, Format)
	}
	if len(d.ConnectionKinds) > 0 && d.Format < 3 {
		add("connection-kinds needs format 3 (IceVault 0.8 or newer)")
	}
	kindSet := d.validateKinds(add)
	if strings.TrimSpace(d.Name) == "" {
		add("name is empty")
	}
	files := map[string]bool{}
	for _, f := range d.Files {
		if !validFile(f) {
			add("files: %q is not a relative path", f)
		}
		if files[f] {
			add("files: %s twice", f)
		}
		files[f] = true
	}
	for _, f := range d.RetiredFiles {
		if !validFile(f) {
			add("retired-files: %q is not a relative path", f)
		}
		if files[f] {
			add("retired-files: %s is also in files", f)
		}
	}
	checkText := func(where string, t Text) {
		for l := range t {
			if !contains(Languages, l) {
				add("%s: language %q (en, uk, ru)", where, l)
			}
		}
	}
	allNames := map[string]bool{}
	d.Walk(func(h Home) { allNames[h.Var.Name] = true })
	for _, x := range d.Derived {
		allNames[x.Name] = true
	}
	for _, p := range d.Products {
		if p.PlaceVariable != "" {
			allNames[p.PlaceVariable] = true
		}
	}
	for k := range d.Conditions.Defaults {
		if !nameRE.MatchString(k) {
			add("conditions defaults: %q is not a variable name", k)
		}
		allNames[k] = true
	}
	checkCond := func(where, s string) {
		c, err := ParseWhen(s)
		if err != nil {
			add("%s: %v", where, err)
			return
		}
		for _, k := range c.Keys() {
			if !allNames[k] {
				add("%s: the condition names %s, which the description does not have", where, k)
			}
		}
	}
	d.validateCheckout(add)
	checkVars := func(where, deflt string, vs []Variable, conn *kinds.Connection, needFile bool) {
		seen := map[string]bool{}
		for _, v := range vs {
			w := where + " " + v.Name
			if !nameRE.MatchString(v.Name) {
				add("%s: %q is not a variable name (upper case letters, digits, _)", where, v.Name)
			}
			if seen[v.Name] {
				add("%s: twice", w)
			}
			seen[v.Name] = true
			f := v.File
			if f == "" {
				f = deflt
			}
			if f == "" && needFile {
				add("%s: no file (neither its own nor the default of %s)", w, where)
			} else if f != "" && !files[f] {
				add("%s: file %s is not in files", w, f)
			}
			checkText(w+" label", v.Label)
			checkText(w+" help", v.Help)
			checkCond(w+": when", v.When)
			checkCond(w+": required-when", v.RequiredWhen)
			if v.Required && v.RequiredWhen != "" {
				add("%s: required and required-when (one of them)", w)
			}
			if v.WhenOff != "" && v.WhenOff != "keep" && v.WhenOff != "drop" {
				add("%s: when-off is keep or drop", w)
			}
			if v.WhenOff != "" && v.When == "" {
				add("%s: when-off without when", w)
			}
			if v.Managed != "" && v.Managed != "owner" && v.Managed != "system" {
				add("%s: managed is owner or system", w)
			}
			v.validateType(w, add)
			if v.FileDefault != "" {
				if conn == nil {
					add("%s: file-default: only in a connection", w)
				} else if _, err := path.Match(v.FileDefault, "x"); err != nil || path.IsAbs(v.FileDefault) || path.Clean(v.FileDefault) != v.FileDefault || v.FileDefault == ".." || strings.HasPrefix(v.FileDefault, "../") {
					add("%s: file-default %q is not a clean relative path pattern", w, v.FileDefault)
				}
			}
			if conn != nil {
				if v.Field == "" || !kinds.FieldRE.MatchString(v.Field) {
					add("%s: a variable of a connection names its field (field:)", w)
				}
			} else if v.Field != "" {
				add("%s: field: only in a connection", w)
			}
		}
	}
	checkConn := func(where string, c *ConnectionUse, wantKind string, needFile bool) {
		k, ok := kindSet.Kind(c.Kind)
		if !ok {
			add("%s: connection kind %q is neither built in nor declared in connection-kinds (%s)", where, c.Kind, strings.Join(kindSet.SortedIDs(), ", "))
			return
		}
		if wantKind != "" && c.Kind != wantKind {
			add("%s: the connection is of kind %s, the site kind needs %s", where, c.Kind, wantKind)
		}
		fields := map[string]bool{}
		for _, v := range c.Variables {
			if fields[v.Field] && v.Field != "" {
				add("%s: field %s twice", where, v.Field)
			}
			fields[v.Field] = true
		}
		if k.Declared {
			for _, v := range c.Variables {
				if v.Field != "" && k.Field(v.Field) == nil {
					add("%s: field %s is not a field of the declared kind %s", where, v.Field, k.ID)
				}
			}
		}
		checkVars(where+" connection "+c.Kind, c.File, c.Variables, &k, needFile)
	}
	if d.General.File == "" || !files[d.General.File] {
		add("general: file names the general file of an environment, one of files")
	}
	checkVars("general", d.General.File, d.General.Variables, nil, true)
	if len(d.SiteKinds) == 0 {
		add("site-kinds: none (a project supports at least one site kind)")
	}
	providers := map[string]string{}
	for _, id := range sortedKeys(d.SiteKinds) {
		sk := d.SiteKinds[id]
		tk, ok := kinds.SiteKind(id)
		where := "site kind " + id
		if !ok {
			add("%s: not a site kind the tool knows (%s)", where, strings.Join(kinds.SiteIDs(), ", "))
			continue
		}
		if sk.Provider == "" {
			add("%s: provider is empty", where)
		} else if other, dup := providers[sk.Provider]; dup {
			add("%s: provider %s is also the provider of %s", where, sk.Provider, other)
		}
		providers[sk.Provider] = id
		checkVars(where, sk.File, sk.Variables, nil, true)
		if sk.Connection != nil {
			if tk.Connection == "" {
				add("%s: a local kind has no connection", where)
			} else {
				checkConn(where, sk.Connection, tk.Connection, true)
			}
		}
		if sk.State != nil {
			if !tk.State {
				add("%s: only a cloud kind keeps its state in a connection", where)
			} else {
				checkConn(where+" state", sk.State, kinds.HCP, true)
			}
		}
	}
	pnames := map[string]bool{}
	for _, p := range d.Products {
		where := "product " + p.Name
		if !productRE.MatchString(p.Name) {
			add("product %q: a name is lower case letters, digits and dashes", p.Name)
		}
		if pnames[p.Name] {
			add("%s: twice", where)
		}
		pnames[p.Name] = true
		checkText(where+" title", p.Title)
		checkText(where+" help", p.Help)
		if p.PlaceVariable != "" && !nameRE.MatchString(p.PlaceVariable) {
			add("%s: place-variable %q is not a variable name", where, p.PlaceVariable)
		}
		checkVars(where, p.File, p.Variables, nil, true)
		for i := range p.Connections {
			checkConn(where, &p.Connections[i], "", true)
		}
		for _, sk := range sortedKeys(p.OnSiteKind) {
			if _, ok := d.SiteKinds[sk]; !ok {
				add("%s on-site-kind %s: the description has no such site kind", where, sk)
			}
			checkVars(where+" on "+sk, p.File, p.OnSiteKind[sk], nil, true)
		}
	}
	for i := range d.VaultConnections {
		checkConn("vault-connections", &d.VaultConnections[i], "", false) // a vault connection is exported to no file of an environment
	}
	for _, x := range d.Derived {
		if !nameRE.MatchString(x.Name) || !files[x.File] {
			add("derived %s: a variable name and a file of files", x.Name)
		}
		if x.From != "site.provider" && x.From != "site.state-backend" {
			add("derived %s: from is site.provider or site.state-backend", x.Name)
		}
	}
	d.validateFiles(add, checkCond)
	if d.RequiredCheck != nil {
		checkCond("required-check when", d.RequiredCheck.When)
	}
	d.validateRest(add, files)
	// one (file, variable) has one home in a scope: General, a product, a site kind (several site kinds may share a file only if they share names
	// on purpose, as aws.env and google.env do not)
	type fk struct{ file, name string }
	seen := map[fk]Home{}
	d.Walk(func(h Home) {
		k := fk{h.File, h.Var.Name}
		prev, ok := seen[k]
		if !ok {
			seen[k] = h
			return
		}
		if !sameMeaning(prev, h) {
			add("%s of %s in %s: also in %s", h.Var.Name, h.File, h.Scope(), prev.Scope())
		}
	})
	// one name has one type wherever it appears (the window and the checks look a variable up by its name)
	first := map[string]Home{}
	d.Walk(func(h Home) {
		prev, ok := first[h.Var.Name]
		if !ok {
			first[h.Var.Name] = h
			return
		}
		if !prev.Var.sameType(h.Var) {
			add("%s in %s: its type, choices or pattern differ from %s", h.Var.Name, h.Scope(), prev.Scope())
		}
	})
	return errs
}

func contains(list []string, x string) bool {
	for _, l := range list {
		if l == x {
			return true
		}
	}
	return false
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sameMeaning: two homes of one variable of one file may coexist when they cannot both apply to one environment (two site kinds, two site-kind
// subgroups) or when they are the same field of the same connection kind (two products that use one DNS account).
func sameMeaning(a, b Home) bool {
	isConn := func(h Home) bool {
		return h.Kind == HomeSiteConnection || h.Kind == HomeSiteState || h.Kind == HomeProductConnection || h.Kind == HomeVaultConnection
	}
	if isConn(a) && isConn(b) {
		return a.Conn.Kind == b.Conn.Kind && a.Var.Field == b.Var.Field
	}
	siteBound := func(h Home) bool { return h.Kind == HomeSite || h.Kind == HomeProductSub }
	return siteBound(a) && siteBound(b) && a.SiteKind != b.SiteKind
}

// HomeKind says what holds a variable.
type HomeKind int

// The homes of a variable.
const (
	HomeGeneral HomeKind = iota
	HomeSite
	HomeSiteConnection
	HomeSiteState
	HomeProduct
	HomeProductSub
	HomeProductConnection
	HomeVaultConnection
)

// Home is where a variable of the description lives in the model.
type Home struct {
	Kind     HomeKind
	SiteKind string // HomeSite, HomeSiteConnection, HomeSiteState, HomeProductSub
	Product  string // HomeProduct, HomeProductSub, HomeProductConnection
	Conn     *ConnectionUse
	Var      Variable
	File     string // the effective file
}

// Scope names the home for messages.
func (h Home) Scope() string {
	switch h.Kind {
	case HomeGeneral:
		return "general"
	case HomeSite:
		return "site kind " + h.SiteKind
	case HomeSiteConnection:
		return "site kind " + h.SiteKind + " connection"
	case HomeSiteState:
		return "site kind " + h.SiteKind + " state"
	case HomeProduct:
		return "product " + h.Product
	case HomeProductSub:
		return "product " + h.Product + " on " + h.SiteKind
	case HomeProductConnection:
		return "product " + h.Product + " connection " + h.Conn.Kind
	}
	return "vault connection " + h.Conn.Kind
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Walk calls fn for every variable of the description with its home, in the order of the file (site kinds sorted by id).
func (d *Description) Walk(fn func(Home)) {
	for _, v := range d.General.Variables {
		fn(Home{Kind: HomeGeneral, Var: v, File: or(v.File, d.General.File)})
	}
	for _, id := range sortedKeys(d.SiteKinds) {
		sk := d.SiteKinds[id]
		for _, v := range sk.Variables {
			fn(Home{Kind: HomeSite, SiteKind: id, Var: v, File: or(v.File, sk.File)})
		}
		if c := sk.Connection; c != nil {
			for _, v := range c.Variables {
				fn(Home{Kind: HomeSiteConnection, SiteKind: id, Conn: c, Var: v, File: or(v.File, c.File)})
			}
		}
		if c := sk.State; c != nil {
			for _, v := range c.Variables {
				fn(Home{Kind: HomeSiteState, SiteKind: id, Conn: c, Var: v, File: or(v.File, c.File)})
			}
		}
	}
	for pi := range d.Products {
		p := &d.Products[pi]
		for _, v := range p.Variables {
			fn(Home{Kind: HomeProduct, Product: p.Name, Var: v, File: or(v.File, p.File)})
		}
		for _, sk := range sortedKeys(p.OnSiteKind) {
			for _, v := range p.OnSiteKind[sk] {
				fn(Home{Kind: HomeProductSub, Product: p.Name, SiteKind: sk, Var: v, File: or(v.File, p.File)})
			}
		}
		for ci := range p.Connections {
			c := &p.Connections[ci]
			for _, v := range c.Variables {
				fn(Home{Kind: HomeProductConnection, Product: p.Name, Conn: c, Var: v, File: or(v.File, c.File)})
			}
		}
	}
	for ci := range d.VaultConnections {
		c := &d.VaultConnections[ci]
		for _, v := range c.Variables {
			fn(Home{Kind: HomeVaultConnection, Conn: c, Var: v, File: or(v.File, c.File)})
		}
	}
}

// Homes lists the homes of a variable of a file.
func (d *Description) Homes(file, name string) []Home {
	var out []Home
	d.Walk(func(h Home) {
		if h.File == file && h.Var.Name == name {
			out = append(out, h)
		}
	})
	return out
}

// Product returns a product by name, or nil.
func (d *Description) Product(name string) *Product {
	for i := range d.Products {
		if d.Products[i].Name == name {
			return &d.Products[i]
		}
	}
	return nil
}

// ProductByPlace returns the product whose place-variable is name, or nil.
func (d *Description) ProductByPlace(name string) *Product {
	for i := range d.Products {
		if d.Products[i].PlaceVariable == name && name != "" {
			return &d.Products[i]
		}
	}
	return nil
}

// SiteKindOf returns the site kind whose provider word is provider ("" when none).
func (d *Description) SiteKindOf(provider string) string {
	for id, sk := range d.SiteKinds {
		if sk.Provider == provider && provider != "" {
			return id
		}
	}
	return ""
}

// DerivedOf returns the derived variable of a file, or nil.
func (d *Description) DerivedOf(file, name string) *Derived {
	for i := range d.Derived {
		if d.Derived[i].File == file && d.Derived[i].Name == name {
			return &d.Derived[i]
		}
	}
	return nil
}

// Retired reports whether a file is retired.
func (d *Description) Retired(file string) bool { return contains(d.RetiredFiles, file) }

// FileIndex is the position of a file in Files (len(Files) when it is not there).
func (d *Description) FileIndex(file string) int {
	for i, f := range d.Files {
		if f == file {
			return i
		}
	}
	return len(d.Files)
}

// Find looks for the description of a project: FileName in the project checkout (root: ICEVAULT_ROOT or the place 'where --remember'
// saved), else the path in ICEVAULT_PROJECT, else remembered (a path the window was given). "" when there is none.
func Find(getenv func(string) string, root, remembered string) string {
	if root != "" {
		p := path.Join(root, FileName)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p := getenv("ICEVAULT_PROJECT"); p != "" {
		return p
	}
	return remembered
}

var (
	guardRE        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	prefixRE       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}$`)
	serveRE        = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
	reservedGuards = []string{"sealed", "token-file", "plaintext"}
)

func (d *Description) validateCheckout(add func(string, ...any)) {
	c := d.Checkout
	for _, x := range []struct{ key, val string }{{"environments", c.Environments}, {"plaintext", c.Plaintext}, {"vault", c.Vault}} {
		if !validFile(x.val) {
			add("checkout: %s is a relative path inside the checkout (%q)", x.key, x.val)
		}
	}
	if c.Templates != "" && !validFile(c.Templates) {
		add("checkout: templates is a relative path inside the checkout (%q)", c.Templates)
	}
	if c.Vault != "" && !strings.HasSuffix(c.Vault, ".kdbx") {
		add("checkout: vault is a .kdbx file")
	}
}

func (d *Description) validateFiles(add func(string, ...any), checkCond func(string, string)) {
	for _, f := range d.FileSpecs {
		where := "file " + f.Path
		checkCond(where+" used-when", f.UsedWhen)
		if f.Partly == nil {
			continue
		}
		if f.UsedWhen == "" {
			add("%s: partly-used without used-when (a file read always is read whole)", where)
		}
		if strings.TrimSpace(f.Partly.When) == "" || len(f.Partly.Keys) == 0 {
			add("%s: partly-used needs when and keys", where)
		}
		checkCond(where+" partly-used", f.Partly.When)
		seen := map[string]bool{}
		for _, k := range f.Partly.Keys {
			// a key of the file's template that the description does not list is allowed: the template names the keys of a file
			if !nameRE.MatchString(k) {
				add("%s: partly-used key %q is not a variable name", where, k)
			}
			if seen[k] {
				add("%s: partly-used key %s twice", where, k)
			}
			seen[k] = true
		}
	}
}

func (d *Description) validateRest(add func(string, ...any), files map[string]bool) {
	guards := map[string]bool{}
	d.kept = nil
	for i, k := range d.KeptFiles {
		where := fmt.Sprintf("kept-files %d (%s)", i+1, k.Name)
		if strings.TrimSpace(k.Name) == "" {
			add("%s: name is empty", where)
		}
		re, err := regexp.Compile("^(?:" + k.Pattern + ")$")
		if err != nil || k.Pattern == "" {
			add("%s: pattern is not a regular expression", where)
			re = nil
		}
		d.kept = append(d.kept, re)
		if m, err := ParseMode(k.Mode); err != nil {
			add("%s: mode is octal, as \"0600\"", where)
		} else if m&0o077 != 0 {
			add("%s: mode %s gives the group or others access: a kept file is for its owner only (0600, 0400, 0700)", where, k.Mode)
		}
		if k.Managed != "" && k.Managed != "owner" && k.Managed != "system" {
			add("%s: managed is owner or system", where)
		}
		if k.NeededUntil != "" && !k.KeepRetired {
			add("%s: needed-until without keep-retired", where)
		}
		if k.Guard != "" {
			if !guardRE.MatchString(k.Guard) || contains(reservedGuards, k.Guard) {
				add("%s: guard %q is a word of lower case letters, digits and dashes, not one of %s", where, k.Guard, strings.Join(reservedGuards, ", "))
			}
			if guards[k.Guard] {
				add("%s: guard %s twice", where, k.Guard)
			}
			guards[k.Guard] = true
			if !strings.HasSuffix(k.Pattern, "/.+") {
				add("%s: a guarded pattern ends with /.+ (the directory a script names)", where)
			}
		}
	}
	d.leftOut = nil
	for i, l := range d.LeftOut {
		re, err := regexp.Compile("^(?:" + l.Pattern + ")$")
		if err != nil || l.Pattern == "" {
			add("left-out %d: pattern is not a regular expression", i+1)
			re = nil
		}
		if strings.TrimSpace(l.Why) == "" {
			add("left-out %d: why is empty", i+1)
		}
		d.leftOut = append(d.leftOut, re)
	}
	if d.Session.Prefix != "" && !prefixRE.MatchString(d.Session.Prefix) {
		add("session: prefix is lower case letters, digits and dashes, up to 16")
	}
	seenVar := map[string]bool{}
	for _, n := range d.Session.Variables.WithDefaults().list() {
		if !nameRE.MatchString(n) {
			add("session: variables: %q is not a variable name", n)
		}
		if seenVar[n] {
			add("session: variables: %s twice", n)
		}
		seenVar[n] = true
	}
	for _, p := range d.Session.Persist {
		if !validFile(p) {
			add("session: persist %q is not a relative path", p)
		}
	}
	if rc := d.RequiredCheck; rc != nil {
		if !validFile(rc.Script) {
			add("required-check: script is a relative path inside the checkout")
		}
		if !contains(Interpreters, rc.Interpreter) {
			add("required-check: interpreter is one of %s", strings.Join(Interpreters, ", "))
		}
		if strings.TrimSpace(rc.Heading) == "" {
			add("required-check: heading is empty")
		}
	}
	apps := map[string]bool{}
	for _, a := range d.Apps {
		where := "app " + a.Name
		if !productRE.MatchString(a.Name) {
			add("app %q: a name is lower case letters, digits and dashes", a.Name)
		}
		if apps[a.Name] {
			add("%s: twice", where)
		}
		apps[a.Name] = true
		if !files[a.From] {
			add("%s: from is one of files", where)
		}
		if a.Dir != "" && (strings.HasPrefix(a.Dir, "/") || path.Clean(a.Dir) != a.Dir) {
			add("%s: dir is a clean relative path", where)
		}
		if a.Example != "" && !validFile(a.Example) {
			add("%s: example is a file of the app's folder (a relative path, no ..)", where)
		}
		if a.All && (a.Prefix != "" || len(a.Plain) > 0 || len(a.Aliases) > 0 || a.Example != "") {
			add("%s: all takes every variable; prefix, plain, aliases and example are for an app with an example file", where)
		}
		if !a.All && a.Prefix == "" && len(a.Plain) == 0 && len(a.Aliases) == 0 {
			add("%s: name what the app takes (all, prefix, plain or aliases)", where)
		}
	}
	serve := map[string]bool{}
	d.Walk(func(h Home) {
		if h.Conn == nil || h.Conn.ServeAs == "" {
			return
		}
		if !serveRE.MatchString(h.Conn.ServeAs) {
			add("%s: serve-as is lower case letters, digits, _ and -", h.Scope())
		}
		if h.Conn.ServeAs == "self" { // the word of a reference to the environment's own variables
			add("%s: serve-as cannot be 'self' (references use it for the environment itself)", h.Scope())
		}
		serve[h.Conn.ServeAs] = true
	})
}

// ParseMode reads an octal file mode ("0600").
func ParseMode(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("no mode")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, fmt.Errorf("not octal")
		}
		n = n*8 + int(c-'0')
	}
	if n == 0 || n > 0o777 {
		return 0, fmt.Errorf("not a file mode")
	}
	return n, nil
}

// CommittedFile is the committed settings file of an environment in the checkout of the description ("" when the description has no path).
func (d *Description) CommittedFile(env string) string {
	if d.Path == "" {
		return ""
	}
	dir, err := filepath.Abs(filepath.Dir(d.Path))
	if err != nil {
		return ""
	}
	return filepath.Join(dir, filepath.FromSlash(d.Checkout.Environments), env, filepath.FromSlash(d.GeneralFile()))
}

// GeneralFile is the general file of an environment: its own settings (the file the derived and the place variables are written into).
func (d *Description) GeneralFile() string { return d.General.File }

// Getter answers the value of a key for conditions: the setting, else its default; with word-before, the part of the value before it.
func (d *Description) Getter(get func(string) string) func(string) string {
	return func(k string) string {
		v := strings.TrimSpace(get(k))
		if v == "" {
			v = d.Conditions.Defaults[k]
		}
		if w := d.Conditions.WordBefore; w != "" {
			if i := strings.Index(v, w); i >= 0 {
				v = v[:i]
			}
		}
		return v
	}
}

// Spec returns the file spec of a path, or nil.
func (d *Description) Spec(p string) *FileSpec {
	for i := range d.FileSpecs {
		if d.FileSpecs[i].Path == p {
			return &d.FileSpecs[i]
		}
	}
	return nil
}

// Use is how an environment reads a file.
type Use int

// The uses of a file.
const (
	UseWhole  Use = iota // read whole (or a file the description does not know)
	UsePartly            // only the keys of partly-used
	UseNone              // not read
)

// FileUse is how an environment with these settings (get, raw: the defaults are applied here) reads the file p.
func (d *Description) FileUse(p string, get func(string) string) Use {
	s := d.Spec(p)
	if s == nil || s.UsedWhen == "" {
		return UseWhole
	}
	g := d.Getter(get)
	if c, err := ParseWhen(s.UsedWhen); err == nil && c.Holds(g) {
		return UseWhole
	}
	if s.Partly != nil {
		if c, err := ParseWhen(s.Partly.When); err == nil && c.Holds(g) {
			return UsePartly
		}
	}
	return UseNone
}

// KeyUsed says whether an environment with these settings reads the key of the file p.
func (d *Description) KeyUsed(p, key string, get func(string) string) bool {
	switch d.FileUse(p, get) {
	case UseWhole:
		return true
	case UsePartly:
		return contains(d.Spec(p).Partly.Keys, key)
	}
	return false
}

// PartlyKeys are the keys of partly-used of a file (nil when none).
func (d *Description) PartlyKeys(p string) []string {
	if s := d.Spec(p); s != nil && s.Partly != nil {
		return s.Partly.Keys
	}
	return nil
}

// SystemVar says whether the description marks the variable of a file as written by the project's scripts (managed: system or generated).
func (d *Description) SystemVar(file, name string) bool {
	for _, h := range d.Homes(file, name) {
		if h.Var.System() {
			return true
		}
	}
	return false
}

// GeneratedVar says whether the variable is a generated secret in some file.
func (d *Description) GeneratedVar(name string) bool {
	g := false
	d.Walk(func(h Home) { g = g || (h.Var.Name == name && h.Var.Generated) })
	return g
}

// Kept is the rule of kept-files that covers a path of the plaintext tree (the first that matches), or nil.
func (d *Description) Kept(rel string) *KeptFile {
	for i, re := range d.kept {
		if re != nil && re.MatchString(rel) {
			return &d.KeptFiles[i]
		}
	}
	return nil
}

// LeftOutWhy is the reason a path of the plaintext tree is never kept ("" when it is not left out).
func (d *Description) LeftOutWhy(rel string) string {
	for i, re := range d.leftOut {
		if re != nil && re.MatchString(rel) {
			return d.LeftOut[i].Why
		}
	}
	return ""
}

// Guarded is the rule with that guard word, or nil.
func (d *Description) Guarded(word string) *KeptFile {
	for i := range d.KeptFiles {
		if d.KeptFiles[i].Guard == word && word != "" {
			return &d.KeptFiles[i]
		}
	}
	return nil
}

// SessionVars are the names of the session's variables.
func (d *Description) SessionVars() SessionVariables { return d.Session.Variables.WithDefaults() }

// SessionPrefix is the prefix of the session directories ("icevault" when the description names none).
func (d *Description) SessionPrefix() string {
	if d.Session.Prefix != "" {
		return d.Session.Prefix
	}
	return "icevault"
}

// App returns an app by name, or nil.
func (d *Description) App(name string) *App {
	for i := range d.Apps {
		if d.Apps[i].Name == name {
			return &d.Apps[i]
		}
	}
	return nil
}

// AppNames lists the apps.
func (d *Description) AppNames() []string {
	out := make([]string, 0, len(d.Apps))
	for _, a := range d.Apps {
		out = append(out, a.Name)
	}
	return out
}

// Served is the connection use a program reaches through external serve under that name, or nil.
func (d *Description) Served(name string) *ConnectionUse {
	var out *ConnectionUse
	d.Walk(func(h Home) {
		if out == nil && h.Conn != nil && h.Conn.ServeAs == name && name != "" {
			out = h.Conn
		}
	})
	return out
}
