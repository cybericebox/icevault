package cliinstall

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeShell writes a shell script that stands in for the login shell; body runs before it answers. The pid of its background program goes to pidFile.
func fakeShell(t *testing.T, body string) (shell, pidFile string) {
	t.Helper()
	dir := t.TempDir()
	shell, pidFile = filepath.Join(dir, "sh"), filepath.Join(dir, "pid")
	script := "#!/bin/sh\n" + strings.ReplaceAll(body, "PIDFILE", pidFile) + "\n"
	if err := os.WriteFile(shell, []byte(script), 0o700); err != nil { // #nosec G306 -- a test program
		t.Fatal(err)
	}
	return shell, pidFile
}

// gone waits until the program whose pid is in pidFile has ended.
func gone(t *testing.T, pidFile string) bool {
	t.Helper()
	data, err := os.ReadFile(pidFile) // #nosec G304 -- a file of this test
	if err != nil {
		t.Fatalf("the background program did not start: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	for range 40 {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestTheShellAnswers(t *testing.T) {
	shell, _ := fakeShell(t, "printf %s /usr/bin:/opt/x/bin")
	if got := loginShellPath(shell, 3*time.Second); !reflect.DeepEqual(got, []string{"/usr/bin", "/opt/x/bin"}) {
		t.Fatalf("got %v", got)
	}
}

func TestABackgroundProgramOfTheProfileNeitherHoldsTheProbeNorOutlivesIt(t *testing.T) {
	// the profile starts a program that keeps the output open for a minute, then the shell answers and exits
	shell, pidFile := fakeShell(t, "sleep 60 &\necho $! > PIDFILE\nprintf %s /usr/bin")
	start := time.Now()
	got := loginShellPath(shell, 3*time.Second)
	if took := time.Since(start); took > 2500*time.Millisecond {
		t.Fatalf("the probe waited %v for the background program", took)
	}
	if !reflect.DeepEqual(got, []string{"/usr/bin"}) {
		t.Fatalf("got %v", got)
	}
	if !gone(t, pidFile) {
		t.Fatal("the background program of the profile still runs")
	}
}

func TestAHangingProfileEndsAtTheTimeoutWithEverythingItStarted(t *testing.T) {
	shell, pidFile := fakeShell(t, "sleep 60 &\necho $! > PIDFILE\nsleep 60")
	start := time.Now()
	if got := loginShellPath(shell, time.Second); got != nil {
		t.Fatalf("got %v", got)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the probe took %v with a timeout of 1s", took)
	}
	if !gone(t, pidFile) {
		t.Fatal("the program the profile started still runs")
	}
}
