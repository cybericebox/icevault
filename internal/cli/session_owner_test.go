package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// killOwner makes the owner file of a session directory name a process that is gone: the state a killed run leaves behind.
func killOwner(t *testing.T, dir string) {
	t.Helper()
	c := exec.Command("true")
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(ownerInfo{PID: c.Process.Pid, Since: time.Now().Format(time.RFC3339)})
	if err := os.WriteFile(ownerPath(dir), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func openHeld(t *testing.T, h *harness) (base, dir string) {
	t.Helper()
	base = filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	if rc := h.run("session", "open", "--env", "prod", "--base", base); rc != 0 {
		t.Fatal(h.errb.String())
	}
	return base, sessionDir(h.env0(), base, "prod", "")
}

func TestSecondOpenWhileTheOwnerRunsIsRefusedWithoutRecoverAdvice(t *testing.T) {
	h := goldenHarness(t)
	base, dir := openHeld(t, h)
	st, err := os.Stat(ownerPath(dir))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("owner file: %v", err)
	}
	rc := h.run("session", "open", "--env", "prod", "--base", base)
	msg := h.errb.String()
	if rc != 1 || !strings.Contains(msg, "is in progress") || !strings.Contains(msg, "--read-only") || strings.Contains(msg, "recover") || strings.Contains(msg, "delete") {
		t.Fatalf("rc=%d %s", rc, msg)
	}
	if !isDir(dir) {
		t.Fatal("the live session directory was touched")
	}
}

func TestSecondOpenAfterTheOwnerDiedSaysLeftOver(t *testing.T) {
	h := goldenHarness(t)
	base, dir := openHeld(t, h)
	killOwner(t, dir)
	rc := h.run("session", "open", "--env", "prod", "--base", base)
	if rc != 1 || !strings.Contains(h.errb.String(), "is left over from a run that was killed") || !strings.Contains(h.errb.String(), "recover") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	// an old-format leftover (no owner file) is the same
	_ = os.Remove(ownerPath(dir))
	rc = h.run("session", "open", "--env", "prod", "--base", base)
	if rc != 1 || !strings.Contains(h.errb.String(), "is left over from a run that was killed") {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
}

func TestRecoverIsRefusedWhileTheOwnerRuns(t *testing.T) {
	h := goldenHarness(t)
	base, dir := openHeld(t, h)
	if rc := h.run("recover", "--env", "prod", "--base", base); rc != 1 || !strings.Contains(h.errb.String(), "is in progress") || !isDir(dir) {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	killOwner(t, dir)
	if rc := h.run("recover", "--env", "prod", "--base", base); rc != 0 {
		t.Fatalf("%s", h.errb.String())
	}
	if isDir(dir) || isFile(ownerPath(dir)) {
		t.Fatal("recover left the directory or the owner file")
	}
}

func TestCloseRemovesTheOwnerFile(t *testing.T) {
	h := goldenHarness(t)
	base, dir := openHeld(t, h)
	if rc := h.run("session", "close", "--env", "prod", "--base", base); rc != 0 {
		t.Fatal(h.errb.String())
	}
	if isDir(dir) || isFile(ownerPath(dir)) {
		t.Fatal("the directory or the owner file is left")
	}
}

func TestReadOnlyRunsBesideAHeldSessionAndWritesNothingBack(t *testing.T) {
	h := goldenHarness(t)
	base, dir := openHeld(t, h)
	vp, err := vaultPath(h.env0())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := sha256File(vp)
	script := `test "$ICEVAULT_READ_ONLY" = 1 && test "$LUMEN_FILES" != "` + dir + `" && mkdir -p "$LUMEN_FILES/keys/gcp" && printf x > "$LUMEN_FILES/keys/gcp/new-in-ro" && printf y >> "$LUMEN_FILES/targets/gcp.env" && echo "$LUMEN_FILES" > "` + filepath.Join(h.dir, "where") + `"`
	if rc := h.run("session", "run", "--read-only", "--env", "prod", "--base", base, "--", "sh", "-c", script); rc != 0 {
		t.Fatalf("%s %s", h.out.String(), h.errb.String())
	}
	if !strings.Contains(h.out.String(), "read-only session: 2 file(s) changed in the session are not kept") {
		t.Fatalf("%s", h.out.String())
	}
	if after, _ := sha256File(vp); after != before {
		t.Fatal("a read-only session changed the vault file")
	}
	used, _ := os.ReadFile(filepath.Join(h.dir, "where"))
	if p := strings.TrimSpace(string(used)); p == "" || isDir(p) {
		t.Fatalf("the read-only directory %q was not removed", p)
	}
	if !isDir(dir) || !isFile(ownerPath(dir)) {
		t.Fatal("the held session was touched")
	}
	if rc := h.run("session", "run", "--env", "prod", "--base", base, "--", "true"); rc != 1 || !strings.Contains(h.errb.String(), "is in progress") {
		t.Fatalf("a normal run beside the held session: %s", h.errb.String())
	}
}

func TestReadOnlyDirectoryIsRemovedAfterAFailure(t *testing.T) {
	h := goldenHarness(t)
	base := filepath.Join(h.dir, "tmp")
	_ = os.Mkdir(base, 0o700)
	if rc := h.run("session", "run", "--read-only", "--env", "prod", "--base", base, "--", "sh", "-c", "exit 3"); rc != 3 {
		t.Fatalf("rc=%d %s", rc, h.errb.String())
	}
	left, _ := os.ReadDir(base)
	if len(left) != 0 {
		t.Fatalf("left in the base: %d entries", len(left))
	}
}


// tfDirs are the token directories of the user in base.
func tfDirs(t *testing.T, h *harness, base string) []string {
	t.Helper()
	ents, _ := os.ReadDir(base)
	var out []string
	for _, en := range ents {
		if en.IsDir() && strings.HasPrefix(en.Name(), tfDirPrefix(h.env0())+itoa(os.Getuid())+"-") {
			out = append(out, filepath.Join(base, en.Name()))
		}
	}
	return out
}

func TestRunsKeepTheTokenDirectoryOfALiveRun(t *testing.T) {
	h := goldenHarness(t)
	base, _ := openHeld(t, h)
	held := tfDirs(t, h, base)
	if len(held) != 1 || !isFile(ownerPath(held[0])) {
		t.Fatalf("the held session's token directory and its owner file: %v", held)
	}
	// a killed run's token directory, one of an older version (no owner file) and an owner file whose directory is gone
	dead := filepath.Join(base, tfDirPrefix(h.env0())+itoa(os.Getuid())+"-dead")
	old := filepath.Join(base, tfDirPrefix(h.env0())+itoa(os.Getuid())+"-old")
	_ = os.Mkdir(dead, 0o700)
	_ = os.Mkdir(old, 0o700)
	killOwner(t, dead)
	orphan := ownerPath(filepath.Join(base, tfDirPrefix(h.env0())+itoa(os.Getuid())+"-gone"))
	_ = os.WriteFile(orphan, []byte("{}"), 0o600)
	for i := 0; i < 3; i++ { // any number of read-only runs, one after another and beside the held session
		if rc := h.run("session", "run", "--read-only", "--env", "prod", "--base", base, "--", "sh", "-c", "test -f \"$ICEVAULT_SETTINGS_FILE\""); rc != 0 {
			t.Fatalf("read-only run %d: %s", i, h.errb.String())
		}
	}
	if !isDir(held[0]) || !isFile(ownerPath(held[0])) {
		t.Fatal("a read-only run removed the token directory of the live session")
	}
	if isDir(dead) || isFile(ownerPath(dead)) || isDir(old) || isFile(orphan) {
		t.Fatal("a token directory of a run that is gone, or an orphan owner file, stays")
	}
	if left := tfDirs(t, h, base); len(left) != 1 {
		t.Fatalf("token directories left: %v", left)
	}
	killOwner(t, held[0]) // the held run ends without its close: the next clean-up takes its directory
	cleanStaleTF(h.env0(), base)
	if isDir(held[0]) || isFile(ownerPath(held[0])) {
		t.Fatal("the token directory of a run that is gone, or its owner file, stays")
	}
}
