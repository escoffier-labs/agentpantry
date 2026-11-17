//go:build !windows

package onepassword

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func secureTokenForTest(string) error { return nil }
func TestTokenPermissionsAndSymlink(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if f, err := openToken(p); err == nil {
		_ = f.Close()
		t.Fatal("open permissions accepted")
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	link := p + "link"
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openToken(link); err == nil {
		_ = f.Close()
		t.Fatal("symlink accepted")
	}
	fifo := p + "fifo"
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := openToken(fifo); err == nil {
		_ = f.Close()
		t.Fatal("FIFO accepted")
	}
}
func TestBinaryReplacement(t *testing.T) {
	p := filepath.Join(t.TempDir(), "op")
	if err := os.WriteFile(p, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	b := &binary{p, info}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("replacement"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := b.check(); err == nil || !strings.Contains(err.Error(), "binary changed") {
		t.Fatal(err)
	}
}
func TestProcessTreeTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30 & wait")
	cleanup, err := startProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	start := time.Now()
	if err = cmd.Wait(); err == nil {
		t.Fatal("timeout succeeded")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("process tree retained pipes")
	}
}
func TestOutputCap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &capped{max: 4, cancel: cancel}
	if _, err := w.Write([]byte("secret")); err == nil || !w.exceeded || ctx.Err() == nil || w.buf.Len() != 0 {
		t.Fatal("unbounded output")
	}
}

func TestInvocationIsolationRedactionAndCaps(t *testing.T) {
	b, err := pinBinary("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("PARENT_SECRET", "must-not-inherit")
	raw, err := b.invoke(context.Background(), "fake-token", dir, []string{"-c", `printf '%s|%s|%s|%s' "$PARENT_SECRET" "$HOME" "$OP_CONFIG_DIR" "$1"`, "fake-op"})
	if err != nil || string(raw) != "|"+dir+"|"+dir+"|--cache=false" {
		t.Fatal("child isolation failed")
	}
	if os.Getenv("OP_SERVICE_ACCOUNT_TOKEN") == "fake-token" {
		t.Fatal("parent token environment modified")
	}
	_, err = b.invoke(context.Background(), "fake-token", dir, []string{"-c", `printf 'fake-token crash output' >&2; exit 1`, "fake-op"})
	if err == nil || strings.Contains(err.Error(), "fake-token") || strings.Contains(err.Error(), "crash") {
		t.Fatal("diagnostic leaked")
	}
	for _, script := range []string{`while :; do printf '0123456789012345678901234567890123456789'; done`, `while :; do printf '0123456789012345678901234567890123456789' >&2; done`} {
		_, err = b.invoke(context.Background(), "fake-token", dir, []string{"-c", script, "fake-op"})
		if err != errLimit {
			t.Fatalf("cap: %v", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = b.invoke(ctx, "fake-token", dir, []string{"-c", `/bin/sleep 30 & wait`, "fake-op"})
	if err == nil || err.Error() != "onepassword: timeout" {
		t.Fatalf("timeout: %v", err)
	}
}

func TestBinaryPathRules(t *testing.T) {
	if _, err := pinBinary("relative-op"); err == nil {
		t.Fatal("relative binary accepted")
	}
	path := filepath.Join(t.TempDir(), "op")
	if err := os.WriteFile(path, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(path)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkBinaryPathTo(path, root); err != nil {
		t.Fatal("positive baseline:", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0777); err != nil {
		t.Fatal(err)
	}
	if err := checkBinaryPathTo(path, root); err == nil {
		t.Fatal("writable binary parent accepted")
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if err := checkBinaryPathTo(path, root); err == nil {
		t.Fatal("writable binary accepted")
	}
}

func checkPrivateDirForTest(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0700 {
		return fmt.Errorf("directory mode %v", info.Mode().Perm())
	}
	return nil
}
func TestSetsidEscape(t *testing.T) {
	if os.Getenv("ONEPASSWORD_DETACH_HELPER") == "1" {
		child := exec.Command("/bin/sleep", "30")
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		fmt.Println(child.Process.Pid)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSetsidEscape$")
	cmd.Env = append(os.Environ(), "ONEPASSWORD_DETACH_HELPER=1")
	var out strings.Builder
	cmd.Stdout = &out
	cleanup, err := startProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(out.String())
	if len(fields) == 0 {
		t.Fatal("no descendant PID")
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	child, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Kill()
	cleanup()
	if err = child.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("setsid descendant did not survive group cleanup", err)
	}
}
