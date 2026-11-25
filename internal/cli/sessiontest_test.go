package cli

import (
	"flag"
	"fmt"

	"github.com/cybericebox/icevault/internal/render"
)

// The commands "session open" and "session close" are gone from the program (only "session run" is left). The tests of the write-back, of "recover" and of
// the session directory still need a session left behind or closed by hand, so they open and close one through the same functions "session run" uses.
func runTestSession(sub string, args []string, e *Env) int {
	if err := testSession(sub, args, e); err != nil {
		if pe, isParse := err.(*parseErr); isParse {
			e.reportUsage("session", pe)
			return 2
		}
		e.report(err)
		return 1
	}
	return 0
}

func testSession(sub string, args []string, e *Env) error {
	var base string
	env, site, err := envFlags("session "+sub, args, e, func(fs *flag.FlagSet) {
		fs.StringVar(&base, "base", "", "the folder of the session directory")
	})
	if err != nil {
		return err
	}
	ec, err := envContext(e, env)
	if err != nil {
		return err
	}
	o, err := openModel(e, false)
	if err != nil {
		return err
	}
	defer o.close()
	if !render.Holds(o.snap, ec.name) {
		return fail("the vault holds nothing for '%s'", ec.name)
	}
	s0, err := render.PickSite(o.snap, ec.name, site)
	if err != nil {
		return fail("%v", err)
	}
	if sub == "open" {
		s, err := openSession(e, o, ec.name, s0, base)
		if err != nil {
			return err
		}
		return printJSON(e.Out, s)
	}
	s := &session{Env: ec.name, Site: s0, Path: sessionDir(e, base, ec.name, s0), base: base}
	if err := ownSessionDir(s.Path); err != nil {
		return err
	}
	return closeSession(e, o, s)
}

var _ = fmt.Sprint
