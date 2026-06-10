package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type cmdResult struct {
	code   int
	stdout string
	stderr string
}

// commandWithStderr runs the binary capturing stderr even on exit 0, which
// runCmd does not.
func commandWithStderr(t *testing.T, bin string, args ...string) cmdResult {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run error: %v", err)
	}
	return cmdResult{code, stdout.String(), stderr.String()}
}

func writeSinkConfig(t *testing.T, dir string) (cfg, key string) {
	t.Helper()
	cfg = filepath.Join(dir, "config.toml")
	key = filepath.Join(dir, "psk.key")
	body := "role = \"sink\"\npeer = \"127.0.0.1:8787\"\nkey_path = " + tomlQuote(key) +
		"\nsurfaces = [\"sidecar\"]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg, key
}

func TestRotateKeyLifecycle(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	cfg, key := writeSinkConfig(t, dir)
	if code, _, stderr := runCmd(t, bin, "keygen", "-out", key); code != 0 {
		t.Fatalf("keygen failed: %s", stderr)
	}
	before, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}

	// Rotate: old key preserved, new key written, operator script printed.
	code, stdout, stderr := runCmd(t, bin, "rotate-key", "-config", cfg)
	if code != 0 {
		t.Fatalf("rotate-key failed: %s", stderr)
	}
	oldPath := key + ".old"
	oldBody, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("old key must exist after rotate: %v", err)
	}
	if string(oldBody) != string(before) {
		t.Fatal("old-key file must hold the pre-rotation key")
	}
	after, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(before) {
		t.Fatal("rotate-key must write a fresh key")
	}
	if !strings.Contains(stdout, "-finish") || !strings.Contains(stdout, oldPath) {
		t.Fatalf("rotate-key must print the finish step and the old-key path, got: %s", stdout)
	}

	// Second rotate without finish must fail and leave both files alone.
	if code, _, stderr := runCmd(t, bin, "rotate-key", "-config", cfg); code == 0 {
		t.Fatal("second rotate-key without --finish must fail")
	} else if !strings.Contains(stderr, "rotation already in progress") {
		t.Fatalf("error must say a rotation is in progress, got: %s", stderr)
	}

	// Doctor surfaces the in-progress rotation as WARN, not FAIL.
	code, stdout, stderr = runCmd(t, bin, "doctor", "-config", cfg)
	if code != 0 {
		t.Fatalf("doctor must pass during a grace window, got %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "key-rotation") || !strings.Contains(stdout, "WARN") {
		t.Fatalf("doctor must show a key-rotation WARN row, got: %s", stdout)
	}

	// Status reports the rotation in JSON and text.
	code, stdout, stderr = runStatus(t, bin, "--json", "--config", cfg)
	if code != 0 {
		t.Fatalf("status failed: %s", stderr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if payload["rotation_in_progress"] != true {
		t.Fatalf("want rotation_in_progress=true, got %v", payload["rotation_in_progress"])
	}
	code, stdout, _ = runStatus(t, bin, "--config", cfg)
	if code != 0 || !strings.Contains(stdout, "rotation") {
		t.Fatalf("text status must mention the rotation, got: %s", stdout)
	}

	// Finish: old key removed, doctor WARN gone, status flag false.
	if code, _, stderr := runCmd(t, bin, "rotate-key", "-config", cfg, "-finish"); code != 0 {
		t.Fatalf("rotate-key -finish failed: %s", stderr)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatal("finish must remove the old-key file")
	}
	code, stdout, _ = runCmd(t, bin, "doctor", "-config", cfg)
	if code != 0 || strings.Contains(stdout, "key-rotation") {
		t.Fatalf("doctor must drop the key-rotation row after finish, got: %s", stdout)
	}
	code, stdout, stderr = runStatus(t, bin, "--json", "--config", cfg)
	if code != 0 {
		t.Fatalf("status failed: %s", stderr)
	}
	payload = map[string]any{}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["rotation_in_progress"] != false {
		t.Fatalf("want rotation_in_progress=false, got %v", payload["rotation_in_progress"])
	}

	// Finish without a rotation in progress must fail.
	if code, _, stderr := runCmd(t, bin, "rotate-key", "-config", cfg, "-finish"); code == 0 {
		t.Fatal("rotate-key -finish without a rotation must fail")
	} else if !strings.Contains(stderr, "no rotation in progress") {
		t.Fatalf("error must say no rotation is in progress, got: %s", stderr)
	}
}

func TestRotateKeyWarnsOnSourceRole(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	key := filepath.Join(dir, "psk.key")
	body := "role = \"source\"\npeer = \"127.0.0.1:8787\"\nkey_path = " + tomlQuote(key) + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCmd(t, bin, "keygen", "-out", key); code != 0 {
		t.Fatalf("keygen failed: %s", stderr)
	}
	cmd := commandWithStderr(t, bin, "rotate-key", "-config", cfg)
	if cmd.code != 0 {
		t.Fatalf("rotate-key on a source must still work: %s", cmd.stderr)
	}
	if !strings.Contains(cmd.stderr, "sink") {
		t.Fatalf("rotate-key on a source must warn that rotation runs on the sink, got: %s", cmd.stderr)
	}
}

func TestRotateKeyHelpListed(t *testing.T) {
	bin := buildBin(t)
	code, stdout, _ := runCmd(t, bin, "help")
	if code != 0 || !strings.Contains(stdout, "rotate-key") {
		t.Fatalf("help must list rotate-key, got: %s", stdout)
	}
}
