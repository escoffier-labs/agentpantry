package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitRefusesOverwriteWithoutForce(t *testing.T) {
	bin := buildBin(t)
	cfg := filepath.Join(t.TempDir(), "config.toml")

	code, _, _ := runCmd(t, bin, "init", "--role", "sink", "--config", cfg)
	if code != 0 {
		t.Fatalf("first init must succeed, exit %d", code)
	}
	if err := os.WriteFile(cfg, []byte("role = \"sink\"\npeer = \"192.0.2.10:9999\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runCmd(t, bin, "init", "--role", "sink", "--config", cfg)
	if code == 0 {
		t.Fatal("re-running init over an edited config must fail without -force")
	}
	if !strings.Contains(stderr, "force") {
		t.Fatalf("error must point at -force, got %q", stderr)
	}
	body, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "192.0.2.10:9999") {
		t.Fatal("refused init must leave the existing config untouched")
	}

	code, _, stderr = runCmd(t, bin, "init", "--role", "sink", "--config", cfg, "--force")
	if code != 0 {
		t.Fatalf("init -force must overwrite, exit %d: %s", code, stderr)
	}
}

func TestInitWritesCommentedTemplate(t *testing.T) {
	bin := buildBin(t)
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if code, _, stderr := runCmd(t, bin, "init", "--role", "source", "--config", cfg); code != 0 {
		t.Fatalf("init failed: %s", stderr)
	}
	body, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[[browsers]]", "allow", "agentpantry doctor"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("source template must mention %q", want)
		}
	}
}

func TestHelpListsCommands(t *testing.T) {
	bin := buildBin(t)
	for _, invocation := range [][]string{{"help"}, {"--help"}, {"-h"}} {
		code, stdout, _ := runCmd(t, bin, invocation...)
		if code != 0 {
			t.Fatalf("%v must exit 0, got %d", invocation, code)
		}
		for _, cmd := range []string{"init", "keygen", "source", "sink", "doctor", "status", "install-service", "version"} {
			if !strings.Contains(stdout, cmd) {
				t.Fatalf("%v output must list %q", invocation, cmd)
			}
		}
	}
}

func TestUnknownCommandIsNamed(t *testing.T) {
	bin := buildBin(t)
	code, _, stderr := runCmd(t, bin, "bogus")
	if code != 2 {
		t.Fatalf("unknown command must exit 2, got %d", code)
	}
	if !strings.Contains(stderr, "bogus") {
		t.Fatalf("error must name the unknown command, got %q", stderr)
	}
}

func TestDoctorWarnsOnUnknownConfigKeys(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	key := filepath.Join(dir, "psk.key")
	if code, _, stderr := runCmd(t, bin, "keygen", "--out", key); code != 0 {
		t.Fatalf("keygen failed: %s", stderr)
	}
	body := "role = \"sink\"\npeer = \"127.0.0.1:8787\"\nkey_path = " + tomlQuote(key) + "\nsurfaces = [\"sidecar\"]\n\n[domains]\nsecrets_dir = \"/tmp/misplaced\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCmd(t, bin, "doctor", "--config", cfg)
	if code != 0 {
		t.Fatalf("warnings must not fail doctor, exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "WARN") || !strings.Contains(stdout, "domains.secrets_dir") {
		t.Fatalf("doctor must WARN naming the unknown key, got:\n%s", stdout)
	}
}

// tomlQuote renders s as a TOML basic string (escaping Windows backslashes).
func tomlQuote(s string) string {
	return "\"" + strings.ReplaceAll(s, "\\", "\\\\") + "\""
}
