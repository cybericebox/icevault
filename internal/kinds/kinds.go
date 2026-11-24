// Package kinds is what the tool itself knows about the things a vault describes: the kinds of connections (an access to an outside service) with
// their fields, and the kinds of sites (where products run). A project description refers to them by id; it never adds a kind.
package kinds

import (
	"regexp"
	"sort"
)

// Text is a text per language (en, uk, ru).
type Text map[string]string

// In returns the text in lang, else in English, else "".
func (t Text) In(lang string) string {
	if s := t[lang]; s != "" {
		return s
	}
	return t["en"]
}

// Field is a field of a connection kind.
type Field struct {
	Name   string
	Title  string
	Secret bool
	// The rest is set only for a field a project description declares (a built-in field has none of it).
	Label     Text
	Help      Text
	Required  bool
	Type      string
	Choices   []string
	Pattern   string
	Multiline bool
}

// Connection is a kind of connection.
type Connection struct {
	ID     string
	Title  string
	Fields []Field
	// Free: the kind has no fields of its own; every field is named by the owner or the project (kind "other").
	Free bool
	// Declared: the kind comes from a project description, not from the tool.
	Declared  bool
	TitleText Text
	Help      Text
}

// TitleIn is the title of the kind in lang (a declared kind has one per language; a built-in one has the English title).
func (c Connection) TitleIn(lang string) string {
	if s := c.TitleText.In(lang); s != "" {
		return s
	}
	return c.Title
}

// Field returns the field of the kind with that name, or nil. A name the kind does not list is a free extra field (allowed on every kind).
func (c Connection) Field(name string) *Field {
	for i := range c.Fields {
		if c.Fields[i].Name == name {
			return &c.Fields[i]
		}
	}
	return nil
}

// The connection kinds: AWS, Google Cloud, Cloudflare, Docker Hub, HCP Terraform, S3-compatible storage, Other.
const (
	AWS        = "aws"
	Google     = "google"
	Cloudflare = "cloudflare"
	DockerHub  = "dockerhub"
	HCP        = "hcp"
	S3         = "s3"
	Other      = "other"
)

var connections = []Connection{
	{ID: AWS, Title: "AWS", Fields: []Field{{Name: "access_key_id", Title: "Access key id", Secret: true}, {Name: "secret_access_key", Title: "Secret access key", Secret: true}, {Name: "region", Title: "Region", Secret: false}, {Name: "account_id", Title: "Account id", Secret: false}}},
	{ID: Google, Title: "Google Cloud", Fields: []Field{{Name: "project", Title: "Project id", Secret: false}, {Name: "credentials", Title: "Service account key file", Secret: true}}},
	{ID: Cloudflare, Title: "Cloudflare", Fields: []Field{{Name: "api_token", Title: "API token", Secret: true}, {Name: "account_id", Title: "Account id", Secret: false}, {Name: "zone_id", Title: "Zone id", Secret: false}}},
	{ID: DockerHub, Title: "Docker Hub", Fields: []Field{{Name: "username", Title: "User name", Secret: false}, {Name: "token", Title: "Access token", Secret: true}}},
	{ID: HCP, Title: "HCP Terraform", Fields: []Field{{Name: "organization", Title: "Organization", Secret: false}, {Name: "token", Title: "API token", Secret: true}}},
	{ID: S3, Title: "S3-compatible storage", Fields: []Field{{Name: "bucket", Title: "Bucket", Secret: false}, {Name: "endpoint", Title: "Endpoint", Secret: false}, {Name: "region", Title: "Region", Secret: false}, {Name: "prefix", Title: "Prefix", Secret: false},
		{Name: "access_key_id", Title: "Access key id", Secret: true}, {Name: "secret_access_key", Title: "Secret access key", Secret: true}}},
	{ID: Other, Title: "Other", Free: true},
}

// Set is the connection kinds a vault is read with: the built-in ones plus the ones the project description declares. The zero Set has the
// built-in kinds only (a vault opened without a project). It is the one lookup everything uses.
type Set struct{ declared []Connection }

// With is the built-in kinds plus the declared ones (the caller has checked that no declared id is a built-in one).
func With(declared []Connection) Set { return Set{declared: append([]Connection(nil), declared...)} }

// Builtin returns the built-in kinds only.
func Builtin() Set { return Set{} }

// IsBuiltin says whether id is a kind of the tool.
func IsBuiltin(id string) bool {
	for _, c := range connections {
		if c.ID == id {
			return true
		}
	}
	return false
}

// Kind returns a connection kind by id.
func (s Set) Kind(id string) (Connection, bool) {
	for _, c := range connections {
		if c.ID == id {
			return c, true
		}
	}
	for _, c := range s.declared {
		if c.ID == id {
			return c, true
		}
	}
	return Connection{}, false
}

// Kinds lists the connection kinds in the order the window shows them: the built-in ones (Other last among them), then the declared ones.
func (s Set) Kinds() []Connection {
	out := append([]Connection(nil), connections...)
	return append(out, s.declared...)
}

// IDs lists the ids of the kinds in the order the window shows them.
func (s Set) IDs() []string {
	var out []string
	for _, c := range s.Kinds() {
		out = append(out, c.ID)
	}
	return out
}

// SortedIDs lists the ids of the kinds, sorted (for messages).
func (s Set) SortedIDs() []string {
	out := s.IDs()
	sort.Strings(out)
	return out
}

// ConnectionKind returns a built-in connection kind by id.
func ConnectionKind(id string) (Connection, bool) { return Builtin().Kind(id) }

// Site is a kind of site.
type Site struct {
	ID    string
	Title string
	// Connection is the connection kind a site of this kind runs on ("" for a local kind: no connection).
	Connection string
	// State: the Terraform state of a site of this kind can live in a connection of kind HCP Terraform (cloud kinds).
	State bool
}

// The site kinds.
const (
	AWSCluster    = "aws-cluster"
	GoogleCluster = "google-cluster"
	Local         = "local"
	Compose       = "compose"
	Host          = "host"
)

var sites = []Site{
	{AWSCluster, "AWS cluster", AWS, true},
	{GoogleCluster, "Google Cloud cluster", Google, true},
	{Local, "This machine", "", false},
	{Compose, "Compose", "", false},
	{Host, "A single host", "", false},
}

// SiteKind returns a site kind by id.
func SiteKind(id string) (Site, bool) {
	for _, s := range sites {
		if s.ID == id {
			return s, true
		}
	}
	return Site{}, false
}

// SiteKinds lists the site kinds.
func SiteKinds() []Site { return append([]Site(nil), sites...) }

// FieldRE is the form of a field name: lower case letters, digits and _, or a variable-like name (letters, digits, _), up to 64.
var FieldRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// SiteIDs lists the ids of the site kinds, sorted (for messages).
func SiteIDs() []string {
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		out = append(out, s.ID)
	}
	sort.Strings(out)
	return out
}
