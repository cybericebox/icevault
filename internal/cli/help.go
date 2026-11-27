package cli

import (
	"fmt"
	"io"
	"strings"
)

// One table drives everything a person or a program learns about the commands: the usage that --help prints, the check of flags before a command runs,
// the overview, and the usage spec (KDL) that mise reads for shell completion (usagespec.go; `icevault usage-spec`, committed as usage/icevault.usage.kdl, a test
// fails when the file and the table differ). A new subcommand is one entry here.
//
// Every subcommand answers --help, -h and "help" with its usage on stdout and exit 0, before anything else: no vault is opened, no password is asked, nothing is
// read from the network or the terminal. An unknown flag prints the usage on stderr and exits 2.

// Completers of a value: what the shell offers after a flag or at a positional place.
const (
	completeNone = "none" // nothing is offered
	completeEnv  = "env"  // the environments of the project checkout
	completePath = phPath // files and directories
	completeDir  = "dir"  // directories
)

const phPath = "path" // the placeholder and the completer of a path

type flagSpec struct {
	Name     string // without dashes
	Value    string // the placeholder of its value ("" for a switch)
	Help     string
	Complete string
}

type argSpec struct {
	Name     string
	Optional bool
	Rest     bool // the arguments that follow a "--" (the command of session run)
	Help     string
	Complete string
}

type actionSpec struct {
	Name string
	Help string
	Args []argSpec
}

type cmdSpec struct {
	Summary string // one line
	Usage   string // what --help prints
	Flags   []flagSpec
	Args    []argSpec    // positional arguments of a command with no actions
	Actions []actionSpec // the words after the command (touchid enable, ...)
}

func sw(name, help string) flagSpec { return flagSpec{Name: name, Help: help} }
func val(name, value, help, complete string) flagSpec {
	return flagSpec{Name: name, Value: value, Help: help, Complete: complete}
}
func envFlag() flagSpec  { return val("env", "env", "the environment", completeEnv) }
func siteFlag() flagSpec { return val("site", "site", "the site of the environment", completeNone) }

var specs = map[string]cmdSpec{
	"init-vault": {Summary: "Make the vault (KDBX 4, Argon2d)", Usage: "init-vault [--generate] [--no-project --vault PATH] [--decryption-time MS]\n  Make the vault (KDBX 4, Argon2d, 64 MiB). ICEVAULT_KEYFILE adds a key file. Asks the new password twice. The password has at least 12 characters and\n  is refused when it is easy to guess (dictionary words, keyboard walks, repeats, dates), however long; an empty password is allowed only with a key file.\n  --generate: makes a random passphrase of six words instead, shows it once on the terminal and asks for it to be typed back; it is never written anywhere.\n  --no-project: a vault without a project, anywhere (--vault PATH names the file): it has no environments, only shared secrets, connections and other secrets; commands that need environments say so.",
		Flags: []flagSpec{sw("generate", "a random six-word passphrase, shown once and typed back"), sw("no-project", "a vault without a project (--vault PATH names the file)"), val("decryption-time", "ms", "key derivation time in ms, 100 to 5000", completeNone)}},
	"change-password": {Summary: "Change the master password of the vault", Usage: "change-password [--generate] [--refresh-copies]\n  Change the master password of the vault: asks the current one (typed, never the one behind Touch ID), then the new one twice under the policy of init-vault (12 or more characters, hard to guess), or --generate for a random six-word passphrase shown once and typed back. The vault file is re-encrypted in place (atomic, the key derivation settings and the key file stay). The Touch ID binding is removed (touchid enable stores the new password). Copies made before still open with the OLD password: they are listed and never deleted; --refresh-copies writes the new file to the standing destinations now.",
		Flags: []flagSpec{sw("generate", "a random six-word passphrase, shown once and typed back"), sw("refresh-copies", "write the new file to the standing copy destinations now")}},
	"ui": {Summary: "Open the settings window (IceVault.app)", Usage: "ui [--env E] [--demo]\n  Start the settings window: the application IceVault.app next to this program (or this program inside it). Everything is typed in the window. --demo: a throwaway in-memory vault, password demo.",
		Flags: []flagSpec{envFlag(), sw("demo", "a throwaway in-memory vault (password demo)")}},
	"keyfile": {Summary: "Make a KeePass key file", Usage: "keyfile new PATH\n  Make a KeePass key file (XML v2, mode 0600) for ICEVAULT_KEYFILE. It never overwrites.",
		Actions: []actionSpec{{"new", "make a key file", []argSpec{{Name: phPath, Help: "the new file", Complete: completePath}}}}},
	"where": {Summary: "Where the vault is (JSON); --remember saves the checkout", Usage: "where [--remember]\n  Print where the vault is (JSON). --remember saves the project checkout for programs with no shell environment (the window opened from Finder).",
		Flags: []flagSpec{sw("remember", "save the project checkout for the window opened from Finder")}},
	"project": {Summary: "Check the project description; which files an environment uses", Usage: "project check | project used --env E | project envs\n  check: read the project description and list its problems. used: which settings files the environment reads (JSON: file -> whole,\n  partly with the keys, or unused), from its committed settings. envs: the environments of the checkout. Asks no password.",
		Flags:   []flagSpec{envFlag()},
		Actions: []actionSpec{{"check", "read the description and list its problems", nil}, {"used", "the files an environment reads (JSON)", nil}, {"envs", "the environments of the checkout", nil}}},
	cmdEnv: {Summary: "Create an environment, or add what it lacks, from the project description (empty entries)", Usage: "env create --env E (--site KIND --products a,b[=PLACE] | --from-checkout) | env fill-missing --env E | env adopt-connections --env E [--dry-run]\n  create: a new environment with one site of the site kind KIND and the products named (the others are made switched off), and every\n  variable the project description says it needs and the owner fills in, as an empty entry with its hint; connections it needs are linked\n  (the one of the description's name, else the only one of the kind) or made empty. --from-checkout takes the site kind and the products\n  from the committed settings of E. fill-missing: the same for an existing environment, adding only what is missing (it asks the password first: the info file\n  does not list an environment that holds nothing yet, so whether E exists is known only after the unlock). No value is ever\n  written and no entry is changed; what the system makes (managed: system, generated) stays for the project's init.\n  adopt-connections: values E holds as its own that the project description now takes from a connection move into that connection (made if\n  need be; a reference stays a reference), the product selects it and the own value is removed; a value the connection already holds differently\n  stays where it is. --dry-run lists the names and changes nothing. No value is printed. Asks the password.",
		Flags:   []flagSpec{envFlag(), val("site", "kind", "the site kind of the new environment", completeNone), val(flagProduct, "list", "the products: a,b or a=PLACE", completeNone), sw(flagFromCO, "take the site kind and the products from the committed settings"), sw("dry-run", "list what would move and change nothing")},
		Actions: []actionSpec{{envCreate, "make the environment with its site and products", nil}, {envFill, "add the entries an environment lacks", nil}, {envAdopt, "move own values into the connections the description now gives them", nil}}},
	cmdSet: {Summary: "Set plain values of the vault directly, without the window", Usage: "set --env E [--scope SCOPE] [--dry-run] KEY=VALUE [KEY=VALUE ...]\n  The command-line twin of the window's edit of a plain value: sets (or creates) plain variables of the vault model in the vault file (asks the password, like session).\n  SCOPE is shared, env/E/general, env/E/site/NAME, env/E/product/NAME or env/E/product/NAME/SITEKIND (E is the --env environment). Without --scope a key that\n  the environment holds in exactly one scope is set there; a key in several scopes is refused (the scopes are listed); a key imported from the shared\n  variables needs --scope shared; a key the vault does not hold yet is created where the project description places it, and a key the description does not\n  know needs --scope. KEY= clears a value.\n  Refused (exit 1, nothing written, one line per key): a secret variable, a system-managed or generated one, a value that holds a reference (the double-brace\n  mark), a value that breaks the type of the description, a vault in a newer format. All keys are checked first: one refusal and nothing is written.\n  Prints one line per key: SCOPE KEY: OLD -> NEW (plain values only, never a secret). --dry-run prints the same lines and writes nothing.\n  A value is a command argument: it shows in the process list, so a secret never goes here (secrets are refused).",
		Flags: []flagSpec{envFlag(), val("scope", "scope", "where the keys live (default: the one scope that holds the key, else where the description places it)", completeNone), sw("dry-run", "print the lines, write nothing")},
		Args:  []argSpec{{Name: "KEY=VALUE", Help: "a plain variable and its new value (KEY= clears it); one or more", Complete: completeNone}}},
	"agent": {Summary: "Ask the unlocked window to read the vault or to apply a batch of changes (JSON, never a secret value)", Usage: "agent OP [JSON | -] [--no-wait] [--timeout SECONDS] [--as NAME]\n  The agent API: talk, over its local socket, to the unlocked IceVault window. Reads (help, structure, batch-status) answer at once. A change is never made at once:\n  batch-begin {\"title\":T} answers an id and a token (the token is the key to that batch: keep it, it is not shown anywhere else); every write op (var-create, set-value, copy-value, connection-create, site-create, ...; \"agent help\" lists them) takes\n  \"batch\":ID and \"token\":TOKEN and is checked and recorded; batch-submit {\"id\":ID,\"token\":TOKEN} sends the whole batch to the window, which shows it in one dialog (Apply batch or Reject), and waits\n  for the answer: applied, rejected, expired or failed (nothing is saved unless every item passes; --no-wait answers pending at once and batch-status {\"id\":ID,\"token\":TOKEN}\n  asks later). The answer is one JSON line. It asks no password and unlocks nothing: with the window locked or closed there is no socket (code no_window, exit 1).\n  No answer carries a secret value. A value is never an argument: \"value_file\" (a path) or \"value_stdin\" (true) in the JSON says where it is read from.\n  Exit: 0 done, 1 refused, 2 usage, 3 not applied or timed out.",
		Flags: []flagSpec{sw("no-wait", "answer pending at once, do not wait for the person"), val("timeout", "seconds", "how long to wait for the person (default 600)", completeNone), val("as", "name", "the name shown in the dialog", completeNone)},
		Args:  []argSpec{{Name: "op", Help: "the operation (agent help lists them)", Complete: completeNone}, {Name: "json", Optional: true, Help: "its arguments as a JSON object, or - to read them from the standard input", Complete: completeNone}}},
	"trust": {Summary: "Trust the project description (its required-check may run)", Usage: "trust [--forget]\n  Record the SHA-256 of the project description of the checkout as trusted by this user: only then does status run its required-check\n  script. A changed description is not trusted until this runs again. --forget removes the record. Asks no password.",
		Flags: []flagSpec{sw("forget", "remove the record")}},
	"guard": {Summary: "The checks the scripts ask before they make secrets", Usage: "guard sealed|WORD|token-file|plaintext [--private DIR] [--dir DIR] [--what TEXT] [--env E] [PATH]\n  The checks the project's scripts ask before they make or read secrets; WORD is a guard word of the description's kept-files. Asks no password.",
		Flags: []flagSpec{val("private", "dir", "the plaintext tree of an environment", completeDir), val("dir", "dir", "the directory", completeDir), val("what", "text", "what the run wanted to do", completeNone), envFlag()},
		Actions: []actionSpec{
			{"sealed", "refuse when the vault holds the environment of the directory", []argSpec{{Name: phPath, Optional: true, Complete: completePath}}},
			{"token-file", "is the token file safe to hand over", []argSpec{{Name: phPath, Optional: true, Complete: completePath}}},
			{"plaintext", "the secret-bearing plaintext files of a directory (JSON)", []argSpec{{Name: phPath, Optional: true, Complete: completePath}}}}},
	"settings": {Summary: "The settings for a run, as JSON, from the vault", Usage: "settings (--all | --env E [--site S]) --out FILE|-\n  The settings of the environments for a run, as JSON, from the vault (asks the password once). Never prints without --out -.",
		Flags: []flagSpec{sw("all", "every environment"), envFlag(), siteFlag(), val("out", "file", "the file to write; - is stdout", completePath)}},
	"session": {Summary: "Unlock once, run a command with the files of an environment", Usage: "session run --env E [--site S] [--base DIR] [--read-only] [-- COMMAND ...]\n  Unlock once, give the files of an environment to a command, write the changes back, remove them (a killed run is written back by recover).\n  A second run of an environment whose session is in progress is refused. --read-only: the files go into a directory of its own, so it runs beside any other session; nothing is written back, the command gets the read-only variable set to 1, and what it changes is dropped.",
		Flags: []flagSpec{envFlag(), siteFlag(), val("base", "dir", "the folder of the session directory", completeDir), sw("read-only", "a session of its own that is never written back (for commands that only look)")},
		Actions: []actionSpec{
			{"run", "run a command inside a session", []argSpec{{Name: "command", Optional: true, Rest: true, Help: "the command and its arguments, after --", Complete: completePath}}}}},
	"external": {Summary: "A connection of the vault as a key/value store for a program", Usage: "external serve\n  A connection the project description serves (serve-as) as a key/value store on JSON lines (stdin/stdout): one unlock, values only on the pipes. Refuses a terminal.",
		Actions: []actionSpec{{"serve", "serve JSON lines on stdin and stdout", nil}}},
	"touchid": {Summary: "Unlock with Touch ID (macOS)", Usage: "touchid enable|disable|status\n  Unlock with Touch ID (macOS: age + age-plugin-se).",
		Actions: []actionSpec{{"enable", "store the password behind Touch ID", nil}, {"disable", "remove the binding", nil}, {"status", "is it on", nil}}},
	"copies": {Summary: "Standing backup copies of the encrypted vault file", Usage: "copies add|remove|list [DIR]\n  Standing one-way backup copies of the encrypted vault file.",
		Actions: []actionSpec{{"add", "add a destination folder", []argSpec{{Name: "dir", Complete: completeDir}}}, {"remove", "remove a destination", []argSpec{{Name: "dir", Complete: completeDir}}}, {"list", "list the destinations", nil}}},
	"copy": {Summary: "One copy of the encrypted vault file now", Usage: "copy --to DIR\n  One copy of the encrypted vault file now.",
		Flags: []flagSpec{val("to", "dir", "the folder that receives the copy", completeDir)}},
	cmdView: {Summary: "Show variables without their secret values", Usage: "view (--env E [--site S] | --item SECTION/ITEM)\n  Show variables without their secret values (asks the password).",
		Flags: []flagSpec{envFlag(), siteFlag(), val("item", "section/item", "one item of the vault", completeNone)}},
	cmdExport: {Summary: "Write an environment as PLAINTEXT files", Usage: "export --env E [--site S] --to DIR [--file F]\n  Write the environment as PLAINTEXT files into a new or empty directory (asks the password).",
		Flags: []flagSpec{envFlag(), siteFlag(), val("to", "dir", "a new or empty directory: it will hold PLAINTEXT", completeDir), val("file", "file", "one extra file", completeNone)}},
	"status": {Summary: "What the vault holds for an environment", Usage: "status --env E [--site S]\n  What the vault holds for an environment and what is still missing (asks the password).",
		Flags: []flagSpec{envFlag(), siteFlag()}},
	cmdExpiring: {Summary: "Values that have expired or expire soon (never values)", Usage: "expiring [--days N]\n  List the values that have expired or expire within N days (default 14) by date: where they live and their names, never a value (asks the password).\n  A date is set in the window; status lists the ones of an environment, export and session warn on stderr about the expired ones they use.",
		Flags: []flagSpec{val("days", "N", "how many days ahead (default 14)", completeNone)}},
	cmdVisibility: {Summary: "Visibility of the variables (never values)", Usage: "visibility --env E [--apply]\n  Print variable / current / proposed visibility, never values; --apply changes the marked ones.",
		Flags: []flagSpec{envFlag(), siteFlag(), sw("apply", "change the variables marked change")}},
	cmdPurge: {Summary: "Delete the plaintext files once the vault is verified", Usage: "purge-plaintext --env E [--site S] [--yes] [--force]\n  Delete the plaintext files of the environment once the vault is verified and copied to another volume.",
		Flags: []flagSpec{envFlag(), siteFlag(), sw("yes", "really delete"), sw("force", "delete even without an up-to-date copy on another volume")}},
	"import": {Summary: "Take the plaintext tree of an environment into the vault", Usage: "import --env E [--site S] [--file F] [--dry-run]\n  Take the existing plaintext tree of the environment (the description's checkout: plaintext) into the vault. --dry-run prints what would change and does not unlock.",
		Flags: []flagSpec{envFlag(), siteFlag(), val("file", "file", "one extra file of the plaintext folder", completeNone), sw("dry-run", "print what would change, write nothing")}},
	cmdRecover: {Summary: "Write a killed session run back into the vault", Usage: "recover --env E [--site S] [--base DIR]\n  Write the files of a killed session run into the vault and remove its directory.",
		Flags: []flagSpec{envFlag(), siteFlag(), val("base", "dir", "the folder of the session directory", completeDir)}},
	cmdImportHCP: {Summary: "Take the terraform login token into the vault", Usage: "import-hcp\n  Take the token that `terraform login` wrote into the vault (the token of the connection of kind hcp). The token is never printed."},
}

// commandNames is the order of the overview and of the completion.
var commandNames = []string{"init-vault", "change-password", "keyfile", "ui", "agent", "where", "project", cmdEnv, cmdSet, "trust", "guard", "settings", "session", "external", "touchid", "copies", "copy", cmdView, cmdExport,
	cmdStatus, cmdExpiring, cmdVisibility, cmdPurge, cmdImport, cmdRecover, cmdImportHCP}

// flagTable is the checkable form of the flags of a command: name -> takes a value. --vault is taken by Run before and is accepted everywhere.
func (s cmdSpec) flagTable() map[string]bool {
	m := map[string]bool{"vault": true}
	for _, f := range s.Flags {
		m[f.Name] = f.Value != ""
	}
	return m
}

func isHelp(a string) bool { return a == "-h" || a == "--help" || a == "-help" || a == "help" }

func printCommandUsage(w io.Writer, name string) {
	if s, ok := specs[name]; ok {
		fmt.Fprintf(w, "usage: icevault %s\n(--vault PATH is accepted by every command)\n", s.Usage)
	}
}

// printOverview lists the commands, one line each, from the table.
func printOverview(w io.Writer) {
	fmt.Fprint(w, "icevault: the secrets of a project in one KeePass vault\n\ncommands:\n")
	for _, n := range commandNames {
		fmt.Fprintf(w, "  %-16s %s\n", n, specs[n].Summary)
	}
	fmt.Fprint(w, "\nicevault COMMAND --help prints the usage of one command and touches nothing.\n")
}

// checkArgs answers help and refuses unknown flags before the command runs. done is true when the answer is final.
func checkArgs(cmd string, args []string, e *Env) (rc int, done bool) {
	s, known := specs[cmd]
	if !known {
		return 0, false
	}
	for i := 0; i < len(args) && args[i] != "--"; i++ { // after -- comes the command of `session run`
		if cmd == "agent" && args[i] == "help" { // the word is the op "help" of the agent API; "icevault help agent" prints the usage
			continue
		}
		if isHelp(args[i]) { // help wins over every other flag
			printCommandUsage(e.Out, cmd)
			return 0, true
		}
	}
	table := s.flagTable()
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		name := strings.TrimLeft(a, "-")
		value := strings.Contains(name, "=")
		name, _, _ = strings.Cut(name, "=")
		takes, ok := table[name]
		if !ok {
			fmt.Fprintf(e.Err, "icevault: %s: unknown flag %s\n", cmd, a)
			printCommandUsage(e.Err, cmd)
			return 2, true
		}
		if takes && !value {
			i++ // its value
		}
	}
	return 0, false
}
