//go:build !unix

package runenv

import "os/exec"

func waitCmd(cmd *exec.Cmd) (int, error) {
	return childStatus(cmd.Wait())
}

func signaledExit(ee *exec.ExitError) (int, error) {
	return ee.ExitCode(), nil
}
