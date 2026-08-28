//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestRunForwardsSIGTERMAndSignaledExit(t *testing.T) {
	bin := buildBin(t)
	helper := buildRunHelper(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	writeSecretFile(t, secrets, "gh_token", "tok-value")
	cfg := writeSinkRunConfig(t, dir, secrets, "")
	pidFile := filepath.Join(dir, "child.pid")

	cmd := exec.Command(bin, "run", "--config", cfg, "--", helper, "-sleep", pidFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	var childPID int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(pidFile)
		if err == nil && len(b) > 0 {
			n, err := strconv.Atoi(string(b))
			if err == nil && n > 0 {
				childPID = n
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID <= 0 {
		_ = cmd.Process.Kill()
		t.Fatal("child did not write pid file")
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal wrapper: %v", err)
	}
	err := cmd.Wait()
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("want ExitError, got %v", err)
	}
	want := 128 + int(syscall.SIGTERM)
	if ee.ExitCode() != want {
		t.Fatalf("want signaled exit %d, got %d", want, ee.ExitCode())
	}
	if err := syscall.Kill(childPID, 0); err == nil {
		t.Fatalf("secret-bearing child pid %d still running", childPID)
	}
}
