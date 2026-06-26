package main

import (
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/config"
)

func TestSidecarDBPathDefault(t *testing.T) {
	got := sidecarDBPath(config.Config{})
	want := filepath.Join(config.Dir(), "sidecar.db")
	if got != want {
		t.Fatalf("empty SidecarPath must use the config-dir default: got %q want %q", got, want)
	}
}

func TestSidecarDBPathOverride(t *testing.T) {
	custom := "/home/agent/.local/share/agentpantry/sidecar.db"
	got := sidecarDBPath(config.Config{SidecarPath: custom})
	if got != custom {
		t.Fatalf("non-empty SidecarPath must win: got %q want %q", got, custom)
	}
}
