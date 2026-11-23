package cli

import (
	"os"
	"strings"
	"testing"
)

// The committed spec is exactly what the table generates: a new subcommand is one entry in help.go, and the file follows with `mise run usage-spec`.
func TestCommittedUsageSpecMatchesTheTable(t *testing.T) {
	got, err := os.ReadFile("../../usage/icevault.usage.kdl")
	if err != nil {
		t.Fatalf("usage/icevault.usage.kdl: %v (run: mise run usage-spec)", err)
	}
	if string(got) != UsageSpec() {
		t.Fatal("usage/icevault.usage.kdl differs from the table of internal/cli/help.go: run `mise run usage-spec` and commit the file")
	}
}

// Every command the program dispatches is in the table (so in the help, the flag check and the spec), and every entry of the table is dispatched.
func TestEveryDispatchedCommandIsInTheTable(t *testing.T) {
	src, err := os.ReadFile("cli.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	start := strings.Index(text, "func runCommand(")
	end := strings.Index(text[start:], "func usage(")
	body := text[start : start+end]
	for _, name := range commandNames {
		if !strings.Contains(body, "\""+name+"\"") && !modelCommands[name] {
			t.Errorf("%s is in the table but runCommand does not dispatch it", name)
		}
	}
	for name := range modelCommands {
		if _, ok := specs[name]; !ok {
			t.Errorf("model command %s is not in the table", name)
		}
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "case \"") {
			name := strings.Trim(strings.Split(strings.TrimPrefix(line, "case "), ":")[0], "\"")
			if _, ok := specs[name]; !ok && name != "usage-spec" {
				t.Errorf("runCommand dispatches %q, which is not in the table", name)
			}
		}
	}
}

func TestEveryTableCommandAppearsInTheSpec(t *testing.T) {
	spec := UsageSpec()
	for _, name := range commandNames {
		if !strings.Contains(spec, "cmd \""+name+"\" ") {
			t.Errorf("%s is missing from the spec", name)
		}
	}
	if len(commandNames) != len(specs) {
		t.Errorf("commandNames has %d entries, the table %d", len(commandNames), len(specs))
	}
}
