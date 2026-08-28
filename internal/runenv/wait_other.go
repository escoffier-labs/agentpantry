//go:build !unix

package runenv

import (
	"os"
	"os/exec"
)

func armSignals() (func(), <-chan os.Signal) {
	return func() {}, nil
}

func waitCmd(cmd *exec.Cmd, _ <-chan os.Signal) (int, error) {
	return childStatus(cmd.Wait())
}

func signaledExit(ee *exec.ExitError) (int, error) {
	return ee.ExitCode(), nil
}
