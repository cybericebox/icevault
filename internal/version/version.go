// Package version holds the version of the build. A release build sets it from the tag: -ldflags "-X github.com/cybericebox/icevault/internal/version.Version=v1.2.3".
// The command line and the window of one build carry the same text.
package version

// Version is "dev" for a plain `go build`.
var Version = "dev"
