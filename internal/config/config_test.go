package config

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("source")
	in.Peer = "198.51.100.5:8787"
	in.Domains.Allow = []string{"github.com"}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Role != "source" || out.Peer != "198.51.100.5:8787" {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	if len(out.Domains.Allow) != 1 || out.Domains.Allow[0] != "github.com" {
		t.Fatalf("domains lost: %+v", out.Domains)
	}
}

func TestDefaultSinkBindsLoopback(t *testing.T) {
	c := Default("sink")
	if c.Peer != "127.0.0.1:8787" {
		t.Fatalf("sink default must bind loopback, got %q", c.Peer)
	}
	if len(c.Surfaces) != 1 || c.Surfaces[0] != "sidecar" {
		t.Fatalf("default surface must be sidecar, got %v", c.Surfaces)
	}
}

func TestSecretsDirRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("source")
	in.SecretsDir = "/home/u/.config/agentpantry/secrets"
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.SecretsDir != in.SecretsDir {
		t.Fatalf("secrets dir lost: %q", out.SecretsDir)
	}
}
