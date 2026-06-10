package config

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/policy"
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

func TestSaveTightensExistingPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("role = \"source\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, Default("source")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("config file must be tightened to 0600, got %v", info.Mode().Perm())
		}
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
		{Type: "hermes", Path: "/tmp/.hermes/agentpantry"},
	}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Adapters) != 4 {
		t.Fatalf("want 4 adapters, got %d", len(out.Adapters))
	}
	if out.Adapters[1].Secret != "gh_token" || out.Adapters[2].Profiles["anthropic_secret"] != "anthropic:default" || out.Adapters[3].Path != "/tmp/.hermes/agentpantry" {
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

func TestSecretNamesRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("source")
	in.SecretNames = policy.Names{Allow: []string{"gh_token"}, Deny: []string{"aws"}}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.SecretNames.Allow) != 1 || len(out.SecretNames.Deny) != 1 || out.SecretNames.Deny[0] != "aws" {
		t.Fatalf("secret_names lost: %+v", out.SecretNames)
	}
}

func TestResyncSecondsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("source")
	in.ResyncSeconds = 90
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.ResyncSeconds != 90 {
		t.Fatalf("resync_seconds lost: %d", out.ResyncSeconds)
	}
}

func TestLoadCheckedReportsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	body := `role = "source"
peer = "127.0.0.1:8787"
alow_typo = ["github.com"]

[domains]
allow = ["github.com"]
secrets_dir = "/tmp/misplaced"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, unknown, err := LoadChecked(path)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, k := range unknown {
		found[k] = true
	}
	if len(unknown) != 2 || !found["alow_typo"] || !found["domains.secrets_dir"] {
		t.Fatalf("unknown keys must name the typo and the misplaced key, got %v", unknown)
	}
}

func TestLoadCheckedCleanConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Save(path, Default("sink")); err != nil {
		t.Fatal(err)
	}
	_, unknown, err := LoadChecked(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 0 {
		t.Fatalf("clean config must report no unknown keys, got %v", unknown)
	}
}

func TestWriteTemplateParsesToDefaults(t *testing.T) {
	for _, role := range []string{"source", "sink"} {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := WriteTemplate(path, role); err != nil {
			t.Fatal(err)
		}
		got, unknown, err := LoadChecked(path)
		if err != nil {
			t.Fatalf("%s template must be valid TOML: %v", role, err)
		}
		if len(unknown) != 0 {
			t.Fatalf("%s template has unknown keys: %v", role, unknown)
		}
		want := Default(role)
		if got.Role != want.Role || got.Peer != want.Peer || got.KeyPath != want.KeyPath {
			t.Fatalf("%s template mismatch: got %+v want %+v", role, got, want)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte("#")) {
			t.Fatalf("%s template must carry guidance comments", role)
		}
	}
	srcPath := filepath.Join(t.TempDir(), "config.toml")
	if err := WriteTemplate(srcPath, "source"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("[[browsers]]")) || !bytes.Contains(body, []byte("allow")) {
		t.Fatal("source template must show a [[browsers]] skeleton and the domain allow list")
	}
}

func TestLoadCheckedInvalidTOML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("role = \"source\"\npeer = [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, unknown, err := LoadChecked(path)
	if err == nil {
		t.Fatal("invalid TOML must return an error")
	}
	if len(unknown) != 0 {
		t.Fatalf("invalid TOML must not report unknown keys, got %v", unknown)
	}
}

func TestWriteTemplateInvalidRole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := WriteTemplate(path, "gateway"); err == nil {
		t.Fatal("invalid role must return an error")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("invalid role must not write a config file")
	}
}

func TestSaveRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("orig"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := Save(path, Config{Role: "sink"}); err == nil {
		t.Fatal("must refuse to write config through a symlink")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "orig" {
		t.Fatalf("symlink target was overwritten: %q", body)
	}
}
