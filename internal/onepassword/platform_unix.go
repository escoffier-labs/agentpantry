//go:build !windows

package onepassword

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func openToken(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		_ = f.Close()
		return nil, fixed("token rejected")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(st.Uid) != int64(os.Geteuid()) {
		_ = f.Close()
		return nil, fixed("token owner rejected")
	}
	return f, nil
}
func checkBinaryPath(path string) error { return checkBinaryPathTo(path, string(filepath.Separator)) }

func checkBinaryPathTo(path, root string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return fixed("binary permissions rejected")
		}
		parent := filepath.Dir(path)
		if path == root || parent == path {
			break
		}
		path = parent
	}
	return nil
}
func privateDir() (string, error) { return os.MkdirTemp("", "agentpantry-op-") }
func tokenFileError(string) error {
	return fixed("token file rejected: use a regular file owned by the current user with mode 0600")
}
func childEnv(token, dir string) []string {
	return []string{"OP_SERVICE_ACCOUNT_TOKEN=" + token, "OP_CONFIG_DIR=" + dir, "HOME=" + dir}
}
func startProcess(cmd *exec.Cmd) (func(), error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.Cancel = kill
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() { _ = kill() }, nil
}
