package service

import (
	"strings"
	"testing"
)

func TestWindowsTaskCommand(t *testing.T) {
	cmd := WindowsTaskCommand("source", `C:\bin\agentpantry.exe`, `C:\cfg\config.toml`)
	for _, want := range []string{"schtasks", "agentpantry-source", `C:\bin\agentpantry.exe`, "source", `C:\cfg\config.toml`} {
		if !strings.Contains(cmd, want) {
			t.Errorf("task command missing %q\n%s", want, cmd)
		}
	}
}
