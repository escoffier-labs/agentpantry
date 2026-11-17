package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/state"
)

func TestSourceRefusesConcurrentConfigBeforeVaultReads(t *testing.T) {
	dir, c := planFixture(t)
	cfgPath := filepath.Join(dir, "a.toml")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	stateFile, err := statePath(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.Acquire(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = cmdSource([]string{"-config", cfgPath, "-once", "-stdio"}); err == nil || !strings.Contains(err.Error(), "already locked") {
		t.Fatal("second source was not refused before fixture vault reads", err)
	}
}
