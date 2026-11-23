package render

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var nastyValues = []string{"plain", "with space", "p@$$word", "a$HOME", "x`id`", "$(touch PWNED)", "back\\slash", "end\\", "dq\"in", "sq'in", "hash # c", " lead", "trail ", "~/x", "~", "a:~/b", "A=~/x",
	"a;b", "a|b", "a&b", "a(b)", "a<b>", "pct%", "bang!", "uni\u00e9\u0443", "a=b", "'", "\"", "${X}", "\\\"\"", "-n", "*", "a*b?[c]", "{a,b}"}

// Every value written by QuoteEnv must give itself back when the file is sourced by bash (a value that ran a command or changed was the defect).
func TestQuoteEnvSourcedByBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	var env strings.Builder
	var script strings.Builder
	script.WriteString("cd " + dir + "; set -a; . ./v.env; set +a; ")
	for i, v := range nastyValues {
		name := "K" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		env.WriteString(name + "=" + QuoteEnv(v) + "\n")
		script.WriteString("printf '%s\\0' \"$" + name + "\"; ")
	}
	if err := os.WriteFile(filepath.Join(dir, "v.env"), []byte(env.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bash, "--noprofile", "--norc", "-c", script.String()).Output()
	if err != nil {
		t.Fatalf("source failed: %v", err)
	}
	got := strings.Split(string(out), "\x00")
	for i, v := range nastyValues {
		if got[i] != v {
			t.Errorf("value %q came back as %q (written %s)", v, got[i], QuoteEnv(v))
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "PWNED")); err == nil {
		t.Fatal("a value ran a command")
	}
}

// The quoting of values that were safe before is unchanged (byte for byte as before).
func TestQuoteEnvKeepsTheOldForms(t *testing.T) {
	for in, want := range map[string]string{"plain": "plain", "with space": `"with space"`, "a#b": `"a#b"`, `dq"in`: `'dq"in'`, "sq'in": `"sq'in"`, "": `""`, "a;b": `"a;b"`, "a=b/c+d": "a=b/c+d"} {
		if got := QuoteEnv(in); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}
