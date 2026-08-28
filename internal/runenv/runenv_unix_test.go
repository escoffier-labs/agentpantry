//go:build unix

package runenv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestInvokeSignaledExitCode(t *testing.T) {
	helper := buildTermSelfHelper(t)
	code, err := Invoke([]string{helper}, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	want := 128 + int(syscall.SIGTERM)
	if code != want {
		t.Fatalf("signaled child: want exit %d (128+SIGTERM), got %d", want, code)
	}
}

func TestInvokeForwardsSIGTERM(t *testing.T) {
	helper := buildHelper(t)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	errCh := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		code, err := Invoke([]string{helper, "-sleep", pidFile}, os.Environ())
		errCh <- struct {
			code int
			err  error
		}{code, err}
	}()

	var childPID int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(pidFile)
		if err == nil && len(b) > 0 {
			childPID, err = strconv.Atoi(string(b))
			if err == nil && childPID > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID <= 0 {
		t.Fatal("child did not write pid file")
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal wrapper: %v", err)
	}

	select {
	case got := <-errCh:
		if got.err != nil {
			t.Fatal(got.err)
		}
		want := 128 + int(syscall.SIGTERM)
		if got.code != want {
			t.Fatalf("forwarded SIGTERM: want exit %d, got %d", want, got.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Invoke did not return after SIGTERM")
	}

	if err := syscall.Kill(childPID, 0); err == nil {
		t.Fatalf("secret-bearing child pid %d still running", childPID)
	}
}

func buildTermSelfHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	body := `package main
import ("syscall"; "time")
func main() {
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	time.Sleep(10 * time.Second)
}
`
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "termself")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper build: %v\n%s", err, out)
	}
	return bin
}
