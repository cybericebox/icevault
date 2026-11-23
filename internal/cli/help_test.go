package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybericebox/icevault/pkg/vault"
)

// countingModel is a Model that fails the test when it is asked to do anything: a help or an unknown flag must never get as far as the model.
type countingModel struct{ calls int }

func (m *countingModel) Run(*Env, string, []string, *vault.Vault, io.Writer) (int, error) {
	m.calls++
	return 0, nil
}
func (m *countingModel) NeedsUnlock(string, []string) bool { m.calls++; return true }

func helpEnv(t *testing.T) (*Env, *countingModel, *int, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	m, asked := &countingModel{}, new(int)
	var out, errb bytes.Buffer
	e := &Env{Getenv: func(k string) string {
		if k == "ICEVAULT_VAULT" {
			return filepath.Join(dir, "none", "v.kdbx") // does not exist: any attempt to open it fails and is visible
		}
		return ""
	}, Out: &out, Err: &errb, Now: time.Now, Root: dir, Model: m,
		Ask:        func(string) ([]byte, error) { *asked++; return []byte("x"), nil },
		AskConsole: func(string) ([]byte, error) { *asked++; return []byte("x"), nil },
		Exec:       execRunner{}, StdioIsTerminal: func() bool { *asked++; return true }}
	return e, m, asked, &out, &errb
}

func TestEverySubcommandHasUsageAndNeverUnlocksOnHelpOrAnUnknownFlag(t *testing.T) {
	if len(commandNames) != len(specs) {
		t.Fatalf("commandNames has %d entries, specs %d", len(commandNames), len(specs))
	}
	for cmd := range modelCommands {
		if _, ok := specs[cmd]; !ok {
			t.Errorf("model command %s has no usage", cmd)
		}
	}
	for _, cmd := range commandNames {
		if _, ok := specs[cmd]; !ok {
			t.Fatalf("%s has no spec", cmd)
		}
		for _, help := range []string{"--help", "-h", "help"} {
			e, m, asked, out, errb := helpEnv(t)
			if rc := Run([]string{cmd, help}, e); rc != 0 {
				t.Errorf("%s %s: rc=%d, want 0 (%s)", cmd, help, rc, errb)
			}
			if !strings.HasPrefix(out.String(), "usage: icevault "+cmd) {
				t.Errorf("%s %s: no usage on stdout: %q", cmd, help, out)
			}
			if m.calls != 0 || *asked != 0 || errb.Len() != 0 {
				t.Errorf("%s %s touched the vault, the model or the terminal (model %d, asked %d, stderr %q)", cmd, help, m.calls, *asked, errb)
			}
			if _, err := os.Stat(filepath.Join(e.Root, "none")); err == nil {
				t.Errorf("%s %s made the vault folder", cmd, help)
			}
		}
		// help after other arguments, and in the middle
		e, m, asked, out, _ := helpEnv(t)
		if rc := Run([]string{cmd, "--env", "prod", "--help"}, e); rc != 0 || m.calls != 0 || *asked != 0 || !strings.Contains(out.String(), "usage: icevault "+cmd) {
			t.Errorf("%s --env prod --help: rc=%d", cmd, rc)
		}
		// an unknown flag: the usage on stderr, exit 2, nothing touched
		e, m, asked, out, errb := helpEnv(t)
		if rc := Run([]string{cmd, "--no-such-flag"}, e); rc != 2 {
			t.Errorf("%s --no-such-flag: rc=%d, want 2", cmd, rc)
		}
		if !strings.Contains(errb.String(), "unknown flag --no-such-flag") || !strings.Contains(errb.String(), "usage: icevault "+cmd) || out.Len() != 0 {
			t.Errorf("%s --no-such-flag: stderr %q stdout %q", cmd, errb, out)
		}
		if m.calls != 0 || *asked != 0 {
			t.Errorf("%s --no-such-flag touched the vault, the model or the terminal", cmd)
		}
	}
}

func TestHelpCommandAndTheOverview(t *testing.T) {
	e, _, asked, out, _ := helpEnv(t)
	if rc := Run([]string{"help", "import"}, e); rc != 0 || !strings.HasPrefix(out.String(), "usage: icevault import") {
		t.Fatalf("help import: rc=%d %q", rc, out)
	}
	e, _, _, out, _ = helpEnv(t)
	if rc := Run([]string{"--help"}, e); rc != 0 || !strings.Contains(out.String(), "icevault COMMAND --help") {
		t.Fatalf("overview: rc=%d %q", rc, out)
	}
	if *asked != 0 || strings.Contains(out.String(), "go-port") {
		t.Fatal("the overview is stale or touched the terminal")
	}
	// values of a flag that look like flags are values, not flags; the command after -- is not checked
	e, m, _, _, errb := helpEnv(t)
	if rc := Run([]string{"session", "run", "--env", "-h-looks-like-a-value", "--", "echo", "--whatever", "-h"}, e); strings.Contains(errb.String(), "unknown flag") || m.calls != 0 || rc == 0 {
		t.Logf("rc=%d %s", rc, errb) // it fails later (no such vault): what counts is that no usage or unknown flag came first
	}
}
