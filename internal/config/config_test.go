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

func TestAdaptersRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("sink")
	in.Adapters = []AdapterRef{
		{Type: "netscape", Path: "/tmp/cookies.txt"},
		{Type: "gh", Path: "/tmp/hosts.yml", Secret: "gh_token", Host: "github.com", User: "octocat"},
		{Type: "openclaw", Path: "/tmp/auth.json", Profiles: map[string]string{"anthropic_secret": "anthropic:default"}},
	}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Adapters) != 3 {
		t.Fatalf("want 3 adapters, got %d", len(out.Adapters))
	}
	if out.Adapters[1].Secret != "gh_token" || out.Adapters[2].Profiles["anthropic_secret"] != "anthropic:default" {
		t.Fatalf("adapter fields lost: %+v", out.Adapters)
	}
}

func TestBrowserURLRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("source")
	in.Browsers = []BrowserRef{{Kind: "cdp", Profile: "chrome", URL: "http://127.0.0.1:9222"}}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Browsers) != 1 || out.Browsers[0].URL != "http://127.0.0.1:9222" {
		t.Fatalf("URL field lost: %+v", out.Browsers)
	}
}
