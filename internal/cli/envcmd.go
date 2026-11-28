package cli

import (
	"flag"
	"io"

	"github.com/cybericebox/icevault/internal/render"
	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

// env adopt-connections: the owner's tidy-up of an environment of the vault model against the project description (vmodel.AdoptConnections).
// Making an environment and filling in what it lacks are done in the window and through the agent API, not here.

const (
	cmdEnv   = "env"
	envAdopt = "adopt-connections"
)

type envArgs struct {
	sub, env string
	dryRun   bool
}

func parseEnvArgs(e *Env, args []string) (envArgs, error) {
	var a envArgs
	if len(args) == 0 || args[0] != envAdopt {
		return a, &parseErr{msg: "env needs adopt-connections (an environment is made and filled in in the window)"}
	}
	a.sub = args[0]
	if _, err := parse("env "+a.sub, args[1:], e, 0, func(fs *flag.FlagSet) {
		fs.StringVar(&a.env, "env", "", "")
		fs.BoolVar(&a.dryRun, "dry-run", false, "")
	}); err != nil {
		return a, err
	}
	if a.env == "" {
		return a, &parseErr{msg: "env " + a.sub + " needs --env E"}
	}
	return a, nil
}

// checkEnv refuses before the password what the arguments and the description can refuse.
func checkEnv(e *Env, args []string) (int, bool, error) {
	a, err := parseEnvArgs(e, args)
	if err != nil {
		return 2, true, err
	}
	if _, err := envContext(e, a.env); err != nil {
		return 1, true, err
	}
	if _, err := e.description(); err != nil {
		return 1, true, err
	}
	return 0, false, nil
}

// runEnv is env adopt-connections on an unlocked vault of the vault model.
func runEnv(e *Env, args []string, out io.Writer, v *vault.Vault, plat *render.Project) (int, error) {
	a, err := parseEnvArgs(e, args)
	if err != nil {
		return 2, err
	}
	m, err := vmodel.Load(v)
	if err != nil {
		return 1, fail("%v", err)
	}
	return runAdopt(e, a, out, v, plat, m)
}
