package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type stationManifest struct {
	Schema    string        `json:"schema"`
	Name      string        `json:"name"`
	Station   string        `json:"station"`
	Lifecycle string        `json:"lifecycle"`
	Tools     []stationTool `json:"tools"`
}

type stationTool struct {
	Name     string           `json:"name"`
	Kind     string           `json:"kind"`
	Command  string           `json:"command"`
	Install  []string         `json:"install"`
	Surfaces []stationSurface `json:"surfaces"`
}

type stationSurface struct {
	Kind           string   `json:"kind"`
	Command        []string `json:"command"`
	ReadOnly       bool     `json:"read_only"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	MaxChars       int      `json:"max_chars"`
	Probe          []string `json:"probe"`
	ProbeContains  []string `json:"probe_contains"`
}

func TestBrigadeStationManifestMatchesAgentPantryCLI(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "station.json"))
	if err != nil {
		t.Fatalf("read station.json: %v", err)
	}
	var manifest stationManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("parse station.json: %v", err)
	}

	if manifest.Schema != "brigade.station.v1" || manifest.Name != "agentpantry" || manifest.Station != "pantry" || manifest.Lifecycle != "active" {
		t.Fatalf("unexpected station identity: %#v", manifest)
	}
	if len(manifest.Tools) != 1 {
		t.Fatalf("tools = %d, want 1", len(manifest.Tools))
	}
	tool := manifest.Tools[0]
	if tool.Name != "agentpantry" || tool.Kind != "executable" || tool.Command != "agentpantry" {
		t.Fatalf("unexpected tool identity: %#v", tool)
	}
	wantInstall := []string{"go", "install", "github.com/escoffier-labs/agentpantry/cmd/agentpantry@latest"}
	if !reflect.DeepEqual(tool.Install, wantInstall) {
		t.Fatalf("install = %q, want %q", tool.Install, wantInstall)
	}

	wantSurfaces := []stationSurface{
		{
			Kind: "doctor-json", Command: []string{"agentpantry", "doctor", "--json", "--no-net"},
			ReadOnly: false, TimeoutSeconds: 10,
			Probe: []string{"agentpantry", "doctor", "--help"}, ProbeContains: []string{"-json", "-no-net"},
		},
		{
			Kind: "summary-json", Command: []string{"agentpantry", "inventory", "--json"},
			ReadOnly: true, TimeoutSeconds: 10, MaxChars: 4000,
			Probe: []string{"agentpantry", "inventory", "--help"}, ProbeContains: []string{"-json"},
		},
		{
			Kind: "verify-exit", Command: []string{"agentpantry", "version", "--json"},
			ReadOnly: true, TimeoutSeconds: 10,
		},
	}
	if !reflect.DeepEqual(tool.Surfaces, wantSurfaces) {
		t.Fatalf("surfaces = %#v, want %#v", tool.Surfaces, wantSurfaces)
	}
}
