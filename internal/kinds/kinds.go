// Package kinds is what the tool itself knows about the things a vault describes: the kinds of connections (an access to an outside service) with
// their fields, and the kinds of sites (where products run). A project description refers to them by id; it never adds a kind.
package kinds

import (
	"regexp"
	"sort"
)

// Field is a field of a connection kind.
type Field struct {
	Name   string
	Title  string
	Secret bool
}

// Connection is a kind of connection.
type Connection struct {
	ID     string
	Title  string
	Fields []Field
	// Free: the kind has no fields of its own; every field is named by the owner or the project (kind "other").
	Free bool
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
	{ID: AWS, Title: "AWS", Fields: []Field{{"access_key_id", "Access key id", true}, {"secret_access_key", "Secret access key", true}, {"region", "Region", false}, {"account_id", "Account id", false}}},
	{ID: Google, Title: "Google Cloud", Fields: []Field{{"project", "Project id", false}, {"credentials", "Service account key file", true}}},
	{ID: Cloudflare, Title: "Cloudflare", Fields: []Field{{"api_token", "API token", true}, {"account_id", "Account id", false}, {"zone_id", "Zone id", false}}},
	{ID: DockerHub, Title: "Docker Hub", Fields: []Field{{"username", "User name", false}, {"token", "Access token", true}}},
	{ID: HCP, Title: "HCP Terraform", Fields: []Field{{"organization", "Organization", false}, {"token", "API token", true}}},
	{ID: S3, Title: "S3-compatible storage", Fields: []Field{{"bucket", "Bucket", false}, {"endpoint", "Endpoint", false}, {"region", "Region", false}, {"prefix", "Prefix", false},
		{"access_key_id", "Access key id", true}, {"secret_access_key", "Secret access key", true}}},
	{ID: Other, Title: "Other", Free: true},
}

// ConnectionKind returns a connection kind by id.
func ConnectionKind(id string) (Connection, bool) {
	for _, c := range connections {
		if c.ID == id {
			return c, true
		}
	}
	return Connection{}, false
}

// ConnectionKinds lists the connection kinds in the order the window shows them.
func ConnectionKinds() []Connection { return append([]Connection(nil), connections...) }

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

// KindIDs lists the ids of the connection kinds, sorted (for messages).
func KindIDs() []string {
	out := make([]string, 0, len(connections))
	for _, c := range connections {
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}

// ConnectionKindsIDs lists the ids of the connection kinds in the order the window shows them.
func ConnectionKindsIDs() []string {
	out := make([]string, 0, len(connections))
	for _, c := range connections {
		out = append(out, c.ID)
	}
	return out
}

// SiteIDs lists the ids of the site kinds, sorted (for messages).
func SiteIDs() []string {
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		out = append(out, s.ID)
	}
	sort.Strings(out)
	return out
}
