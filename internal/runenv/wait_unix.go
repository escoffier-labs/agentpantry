//go:build unix

package runenv

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func armSignals() (func(), <-chan os.Signal) {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	return func() { signal.Stop(ch) }, ch
}

// waitCmd waits for cmd (already started) and forwards SIGINT/SIGTERM so a
// signal to the wrapper does not leave a secret-bearing child running.
// sigs must already be armed via armSignals before cmd.Start.
func waitCmd(cmd *exec.Cmd, sigs <-chan os.Signal) (int, error) {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case err := <-done:
			return childStatus(err)
		case sig := <-sigs:
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
