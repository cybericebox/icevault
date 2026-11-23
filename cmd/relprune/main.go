// Command relprune applies the release retention policy of the workspace to this repository. Nothing here talks to GitHub; the release workflow feeds it
// lists and acts on what it prints.
//
//	relprune                 stdin: the JSON of `gh release list --json tagName,isDraft`; prints the tags whose release (page and assets) must be deleted
//	relprune -newest vX.Y.Z  stdin: the same JSON; prints true when vX.Y.Z is the newest final release (it is then marked as the latest), else false
//	relprune -rc-tags        stdin: tag names, one per line; prints the release candidate tags whose final exists (the policy deletes them)
//
// The tags of final releases are kept forever.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cybericebox/icevault/internal/retention"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "relprune:", err)
		os.Exit(1)
	}
}

func run(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("relprune", flag.ContinueOnError)
	newest := fs.String("newest", "", "print whether this tag is the newest final release")
	rcTags := fs.Bool("rc-tags", false, "read tag names and print the release candidate tags to delete")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rcTags {
		var tags []string
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			if t := strings.TrimSpace(sc.Text()); t != "" {
				tags = append(tags, t)
			}
		}
		if err := sc.Err(); err != nil {
			return err
		}
		return lines(out, retention.CandidateTags(tags))
	}
	var list []struct {
		TagName string `json:"tagName"`
		IsDraft bool   `json:"isDraft"`
	}
	if err := json.NewDecoder(in).Decode(&list); err != nil {
		return fmt.Errorf("standard input is not the JSON of gh release list: %w", err)
	}
	var tags []string
	for _, r := range list {
		if !r.IsDraft { // a draft is a release being made: never pruned, never compared
			tags = append(tags, r.TagName)
		}
	}
	if *newest != "" {
		_, err := fmt.Fprintln(out, retention.Newest(tags, *newest))
		return err
	}
	return lines(out, retention.Delete(tags, retention.PreviousMinors))
}

func lines(out io.Writer, tags []string) error {
	for _, t := range tags {
		if _, err := fmt.Fprintln(out, t); err != nil {
			return err
		}
	}
	return nil
}
