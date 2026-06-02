package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildBin compiles the agentpantry binary once into a temp dir and returns its path.
func buildBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "agentpantry")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

// runStatus runs the binary and returns (exitCode, stdout, stderr).
func runStatus(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"status"}, args...)...)
	stdout, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(stdout), string(ee.Stderr)
	}
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	return 0, string(stdout), ""
}

func TestStatusJSONUnwired(t *testing.T) {
	bin := buildBin(t)
	missing := filepath.Join(t.TempDir(), "nope.toml")
	code, _, stderr := runStatus(t, bin, "--json", "--config", missing)
	if code != 2 {
		t.Fatalf("want exit 2 for missing config, got %d (stderr=%s)", code, stderr)
	}
}

func TestStatusJSONConfigured(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	body := "role = \"source\"\npeer = \"127.0.0.1:8787\"\nkey_path = \"" +
		filepath.Join(dir, "psk.key") + "\"\nsurfaces = [\"sidecar\"]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runStatus(t, bin, "--json", "--config", cfg)
	if code != 0 {
		t.Fatalf("want exit 0, got %d (stderr=%s)", code, stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if payload["role"] != "source" {
		t.Fatalf("want role=source, got %v", payload["role"])
	}
	if payload["key_present"] != false {
		t.Fatalf("want key_present=false (no key file written), got %v", payload["key_present"])
	}
	for _, k := range []string{"role", "configured", "peer", "key_present", "surfaces", "browsers", "allow", "deny"} {
		if _, ok := payload[k]; !ok {
			t.Errorf("JSON payload missing required contract key %q", k)
		}
	}
}
