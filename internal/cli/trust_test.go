package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (h *harness) trust() {
	h.t.Helper()
	if rc := h.run("trust"); rc != 0 || !strings.Contains(h.out.String(), "trusted: ") {
		h.t.Fatalf("trust rc=%d %s %s", rc, h.out.String(), h.errb.String())
	}
}

// Without a trust record the check never runs: status says so and names the command that trusts the description.
func TestRequiredCheckNeedsTrust(t *testing.T) {
	h := newHarness(t)
	h.initVault()
	if rc := h.run("import", "--env", "prod"); rc != 0 {
		t.Fatalf("import: %s", h.errb.String())
	}
	ran := false
	oldHook := runHook
	defer func() { runHook = oldHook }()
	runHook = func(string, []string) ([]byte, int, error) { ran = true; return nil, 0, nil }
	if rc := h.run("status", "--env", "prod"); rc != 0 || ran || !strings.Contains(h.out.String(), "not trusted") || !strings.Contains(h.out.String(), "icevault trust") {
		t.Fatalf("ran=%v %s", ran, h.out.String())
	}
	h.trust()
	if rc := h.run("status", "--env", "prod"); rc != 0 || !ran {
		t.Fatalf("trusted, not run: %s", h.out.String())
	}
	// the record is the user's own: 0600 in a 0700 folder
	f := trustFile(func(k string) string { return h.env[k] })
	if st, err := os.Stat(f); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("trust file %v %v", st, err)
	}
	if st, err := os.Stat(filepath.Dir(f)); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("trust folder %v %v", st, err)
	}
	// --forget removes it
	if rc := h.run("trust", "--forget"); rc != 0 {
		t.Fatal(h.errb.String())
	}
	ran = false
	if rc := h.run("status", "--env", "prod"); rc != 0 || ran {
		t.Fatal("ran after --forget")
	}
}

// A description changed after it was trusted is not trusted.
func TestRequiredCheckChangedDescription(t *testing.T) {
	h := goldenHarness(t)
	ran := false
	oldHook := runHook
	defer func() { runHook = oldHook }()
	runHook = func(string, []string) ([]byte, int, error) { ran = true; return nil, 0, nil }
	desc := filepath.Join(h.root, "icevault-project.yaml")
	data, err := os.ReadFile(desc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(desc, append(data, []byte("# changed\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := h.run("status", "--env", "prod"); rc != 0 || ran || !strings.Contains(h.out.String(), "icevault trust") {
		t.Fatalf("ran=%v %s", ran, h.out.String())
	}
}

func checkoutWith(t *testing.T, edit func(root string)) string {
	t.Helper()
	h := newHarness(t)
	if edit != nil {
		edit(h.root)
	}
	return h.root
}

// The script must be a file inside the checkout: a path that leaves it is refused when the description is read, and again before it runs.
func TestRequiredCheckScriptOutsideCheckout(t *testing.T) {
	root := checkoutWith(t, func(root string) {
		desc := filepath.Join(root, "icevault-project.yaml")
		data, _ := os.ReadFile(desc)
		_ = os.WriteFile(desc, []byte(strings.Replace(string(data), "script: tools/check-required.sh", "script: ../outside.sh", 1)), 0o600)
	})
	if _, err := LoadProject(root); err == nil || !strings.Contains(err.Error(), "required-check: script") {
		t.Fatalf("outside script accepted: %v", err)
	}
	// a description changed in memory after the check: the run refuses too
	pd, err := LoadProject(checkoutWith(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	d := pd.D
	d.RequiredCheck.Script = "../../outside.sh"
	if _, _, err := checkScript(d); err == nil {
		t.Fatal("outside script resolved")
	}
}

// A link inside the checkout that leads to a script outside it is refused.
func TestRequiredCheckSymlinkEscape(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "evil.sh")
	if err := os.WriteFile(outside, []byte("echo evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := checkoutWith(t, func(root string) {
		p := filepath.Join(root, "tools", "check-required.sh")
		_ = os.Remove(p)
		if err := os.Symlink(outside, p); err != nil {
			t.Fatal(err)
		}
	})
	pd, err := LoadProject(root)
	if err != nil {
		t.Fatal(err)
	}
	d := pd.D
	if _, _, err := checkScript(d); err == nil || !strings.Contains(err.Error(), "outside the checkout") {
		t.Fatalf("symlink escape: %v", err)
	}
	// a link to the folder holding it is the same
	root2 := checkoutWith(t, func(root string) {
		_ = os.RemoveAll(filepath.Join(root, "tools"))
		if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "tools")); err != nil {
			t.Fatal(err)
		}
		_ = os.Rename(outside, filepath.Join(filepath.Dir(outside), "check-required.sh"))
	})
	pd2, err := LoadProject(root2)
	if err != nil {
		t.Fatal(err)
	}
	d2 := pd2.D
	if _, _, err := checkScript(d2); err == nil {
		t.Fatal("folder link escape resolved")
	}
	// the real script resolves
	pd3, err := LoadProject(checkoutWith(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	d3 := pd3.D
	if s, interp, err := checkScript(d3); err != nil || filepath.Base(s) != "check-required.sh" || filepath.Base(interp) != "sh" {
		t.Fatalf("%s %s %v", s, interp, err)
	}
}

// A placeholder whose value holds shell syntax stays one argument and is never run.
func TestRequiredCheckArgvNoShell(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	evil := "aws; touch " + marker + " $(touch " + marker + ") `touch " + marker + "` | x && y"
	argv := hookArgs([]string{"--provider={provider}", "{provider}", "{tree}"}, map[string]string{"provider": evil, "tree": dir})
	if len(argv) != 3 || argv[0] != "--provider="+evil || argv[1] != evil || argv[2] != dir {
		t.Fatalf("%q", argv)
	}
	script := filepath.Join(dir, "count.sh")
	if err := os.WriteFile(script, []byte("printf '%s\\n' \"$#\" \"$2\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(script)
	c := &checked{script: script, interp: "/bin/sh", data: data}
	out, rc, err := runChecked(dir, c, "sh", hookArgs([]string{"{provider}", "{provider}"}, map[string]string{"provider": evil}))
	if err != nil || rc != 0 || string(out) != "2\n"+evil+"\n" {
		t.Fatalf("rc=%d err=%v %q", rc, err, out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a placeholder value was run by a shell")
	}
}

// A script changed after the trust is not trusted, even with the description unchanged.
func TestRequiredCheckChangedScript(t *testing.T) {
	h := goldenHarness(t)
	ran := false
	oldHook := runHook
	defer func() { runHook = oldHook }()
	runHook = func(string, []string) ([]byte, int, error) { ran = true; return nil, 0, nil }
	p := filepath.Join(h.root, "tools", "check-required.sh")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(data, []byte("echo changed\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := h.run("status", "--env", "prod"); rc != 0 || ran || !strings.Contains(h.out.String(), "icevault trust") {
		t.Fatalf("ran=%v %s", ran, h.out.String())
	}
	h.trust()
	if rc := h.run("status", "--env", "prod"); rc != 0 || !ran {
		t.Fatalf("trusted again, not run: %s", h.out.String())
	}
}

// The script swapped on the disk between the check and the run changes nothing: the run uses the checked bytes.
func TestRequiredCheckRunsCheckedBytes(t *testing.T) {
	h := goldenHarness(t)
	p := filepath.Join(h.root, "tools", "check-required.sh")
	marker := filepath.Join(t.TempDir(), "swapped")
	oldHook := runHook
	defer func() { runHook = oldHook }()
	var ran []string
	runHook = func(dir string, argv []string) ([]byte, int, error) {
		// the swap happens after the digest was compared
		if err := os.WriteFile(p, []byte("touch "+marker+"\necho 'REQUIRED values still to fill'\necho '  services/portal.env  SWAPPED'\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ran = argv
		return oldHook(dir, argv)
	}
	if rc := h.run("status", "--env", "prod"); rc != 0 || !strings.Contains(h.out.String(), "required values: all set") {
		t.Fatalf("%s %s", h.out.String(), h.errb.String())
	}
	if _, err := os.Stat(marker); err == nil || ran == nil || ran[1] == p {
		t.Fatalf("the swapped script ran (%v)", ran)
	}
}

// python3 runs isolated.
func TestRequiredCheckPythonIsolated(t *testing.T) {
	var seen []string
	oldHook := runHook
	defer func() { runHook = oldHook }()
	runHook = func(_ string, argv []string) ([]byte, int, error) { seen = argv; return nil, 0, nil }
	c := &checked{script: "/x/check.py", interp: "/usr/bin/python3", data: []byte("print(1)\n")}
	if _, _, err := runChecked(t.TempDir(), c, "python3", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 4 || seen[1] != "-I" || filepath.Base(seen[2]) != "check.py" || seen[3] != "a" {
		t.Fatalf("%q", seen)
	}
}

// The digest covers the bytes the description was parsed from: a description changed on the disk after it was read cannot lend the run its
// interpreter or its arguments.
func TestTrustHashesTheParsedBytes(t *testing.T) {
	root := checkoutWith(t, nil)
	p, err := LoadProject(root)
	if err != nil {
		t.Fatal(err)
	}
	desc := filepath.Join(root, "icevault-project.yaml")
	orig, _ := os.ReadFile(desc)
	if err := os.WriteFile(desc, append(orig, []byte("# changed after it was read\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := readChecked(p.D)
	if err != nil {
		t.Fatal(err)
	}
	if c.digest != trustDigest(orig, c.data) {
		t.Fatal("the digest is not over the bytes that were parsed")
	}
}

// {provider} must be one word that no option parser reads as an option.
func TestProviderWord(t *testing.T) {
	for w, ok := range map[string]bool{"gcp": true, "compose": true, "a_b-1": true, "-rf": false, "--x": false, "": false, "A": false, "a b": false} {
		if providerWordRE.MatchString(w) != ok {
			t.Errorf("%q", w)
		}
	}
}

// status checks the required values in a fresh folder of its own: a session folder that a failed write-back left is never touched.
func TestStatusLeavesSessionFoldersAlone(t *testing.T) {
	h := goldenHarness(t)
	tmp := t.TempDir()
	h.env["TMPDIR"] = tmp
	left := sessionDir(h.env0(), tmp, "prod", "status")
	if err := os.MkdirAll(left, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(left, "made-by-a-run")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := h.run("status", "--env", "prod"); rc != 0 {
		t.Fatalf("%s", h.errb.String())
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("status removed a session folder")
	}
}
