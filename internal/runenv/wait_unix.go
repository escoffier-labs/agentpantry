//go:build unix

package runenv

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// waitCmd waits for cmd (already started) and forwards SIGINT/SIGTERM so a
// signal to the wrapper does not leave a secret-bearing child running.
func waitCmd(cmd *exec.Cmd) (int, error) {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(ch)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case err := <-done:
			return childStatus(err)
		case sig := <-ch:
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}
}

func signaledExit(ee *exec.ExitError) (int, error) {
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return ee.ExitCode(), nil
}
