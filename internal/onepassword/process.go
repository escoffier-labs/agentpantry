package onepassword

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type binary struct {
	path string
	info os.FileInfo
}

func pinBinary(path string) (*binary, error) {
	if path == "" {
		var err error
		path, err = exec.LookPath("op")
		if err != nil {
			return nil, fixed("binary unavailable")
		}
	}
	if !filepath.IsAbs(path) {
		return nil, fixed("binary path must be absolute")
	}
	// Resolve installer symlinks once, then pin and execute only the canonical target.
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fixed("binary rejected")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fixed("binary rejected")
	}
	if err = checkBinaryPath(path); err != nil {
		return nil, err
	}
	return &binary{path, info}, nil
}
func (b *binary) check() error {
	info, err := os.Lstat(b.path)
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, b.info) || info.Size() != b.info.Size() || !info.ModTime().Equal(b.info.ModTime()) {
		return fixed("binary changed")
	}
	return checkBinaryPath(b.path)
}

type capped struct {
	buf      bytes.Buffer
	max      int
	exceeded bool
	cancel   context.CancelFunc
}

func (w *capped) Write(p []byte) (int, error) {
	if len(p) > w.max-w.buf.Len() {
		w.exceeded = true
		w.cancel()
		return 0, errLimit
	}
	return w.buf.Write(p)
}
func (b *binary) invoke(ctx context.Context, token, dir string, args []string) ([]byte, error) {
	if err := b.check(); err != nil {
		if err.Error() == "onepassword: binary changed" {
			_, _ = os.Stderr.WriteString("agentpantry: onepassword binary changed\n")
		}
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	args = append(append([]string{}, args...), "--cache=false")
	cmd := exec.CommandContext(ctx, b.path, args...) // #nosec G204 -- canonical operator-selected binary is checked and pinned before every invocation.
	cmd.Dir = dir
	cmd.Env = childEnv(token, dir)
	cmd.WaitDelay = time.Second
	out := &capped{max: totalLimit, cancel: cancel}
	stderr := &capped{max: 64 << 10, cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = stderr
	cleanup, err := startProcess(cmd)
	if err != nil {
		return nil, fixed("process unavailable")
	}
	defer cleanup()
	err = cmd.Wait()
	if out.exceeded || stderr.exceeded {
		return nil, errLimit
	}
	if ctx.Err() != nil {
		return nil, fixed("timeout")
	}
	if err != nil {
		// Only fixed categories leave this boundary. Redact before even classifying.
		s := strings.ToLower(strings.ReplaceAll(stderr.buf.String(), token, "[redacted]"))
		switch {
		case strings.Contains(s, "rate limit") || strings.Contains(s, "429"):
			return nil, fixed("rate limited")
		case strings.Contains(s, "not found"):
			return nil, fixed("not found")
		default:
			return nil, fixed("auth or command failed")
		}
	}
	return out.buf.Bytes(), nil
}
func readToken(f *os.File) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 {
		return "", fixed("token rejected")
	}
	s := strings.TrimRight(string(raw), "\r\n")
	if s == "" || strings.ContainsAny(s, "\x00\r\n") {
		return "", fixed("token rejected")
	}
	return s, nil
}
