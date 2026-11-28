package cli

import (
	"os"
	"strings"

	"github.com/cybericebox/icevault/internal/model"
)

// Nothing that the arguments, the files or the info file alone can refuse or answer may ask for the vault password first. Check runs before the unlock of
// every command of the settings model and settles what it can: a wrong command line (exit 2), an unknown environment, a missing directory, an unknown app,
// a target that is not empty. It reads no vault and asks nothing.

// checker is an optional part of a Model: Check runs before NeedsUnlock. done says the command is finished (rc), err is a refusal.
type checker interface {
	Check(e *Env, cmd string, args []string) (rc int, done bool, err error)
}

// flagOn is the value flagVals gives a switch that is on.
const flagOn = "true"

// flagVals reads the flags of cmd from args by the table of help.go: a switch is "true", a flag with a value gets it (--name VALUE or --name=VALUE).
func flagVals(cmd string, args []string) map[string]string {
	table := specs[cmd].flagTable()
	vals := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		takes, known := table[name]
		switch {
		case !known:
		case !takes:
			vals[name] = flagOn
		case hasValue:
			vals[name] = value
		case i+1 < len(args):
			vals[name] = args[i+1]
			i++
		default:
			vals[name] = ""
		}
	}
	return vals
}

func (defaultModel) Check(e *Env, cmd string, args []string) (int, bool, error) {
	v := flagVals(cmd, args)
	switch cmd {
	case cmdView:
		if item := v["item"]; item != "" {
			if _, ok := model.SplitRef(item); !ok {
				return 1, true, fail("--item is SECTION/ITEM, for example external/registry")
			}
			return 0, false, nil
		}
		_, err := envContext(e, v["env"])
		return 1, err != nil, err
	case cmdExport:
		return checkExport(e, v)
	case cmdStatus, cmdVisibility, cmdRecover:
		_, err := envContext(e, v["env"])
		return 1, err != nil, err
	case cmdExpiring:
		if _, err := expiringDays(args); err != nil {
			return 2, true, err
		}
		return 0, false, nil
	case cmdEnv:
		return checkEnv(e, args)
	case cmdSet:
		return checkSet(e, args)
	case cmdImportHCP:
		path, token, err := hcpCredentials(e)
		herr := hcpError(path, token, err)
		return 1, herr != nil, herr
	}
	return 0, false, nil
}

func checkExport(e *Env, v map[string]string) (int, bool, error) {
	if v["to"] == "" {
		return 2, true, &parseErr{msg: "export needs --to DIR"}
	}
	if v["file"] != "" {
		return 0, false, nil // the vault says whether it holds that file
	}
	if _, err := envContext(e, v["env"]); err != nil {
		return 1, true, err
	}
	if ents, err := os.ReadDir(v["to"]); err == nil && len(ents) > 0 {
		return 1, true, fail("%s is not empty", v["to"])
	}
	return 0, false, nil
}
