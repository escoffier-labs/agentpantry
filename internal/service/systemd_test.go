package service

import (
	"strings"
	"testing"
)

func TestSystemdUnitContents(t *testing.T) {
	unit := SystemdUnit("source", "/usr/local/bin/agentpantry", "/home/u/.config/agentpantry/config.toml")
	for _, want := range []string{
		"Description=agentpantry source",
		"ExecStart=/usr/local/bin/agentpantry source --config /home/u/.config/agentpantry/config.toml",
		"Restart=on-failure",
		"WantedBy=default.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q\n---\n%s", want, unit)
		}
	}
}

func TestUnitFileName(t *testing.T) {
	if got := UnitFileName("sink"); got != "agentpantry-sink.service" {
		t.Fatalf("got %q", got)
	}
}
