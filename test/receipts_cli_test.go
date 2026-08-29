package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/receipt"
)

func TestSourceOnceWritesHashChainedReceipts(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	addr := freeTCPAddr(t)
	keyPath := filepath.Join(dir, "psk.key")
	writeKey(t, keyPath)

	ffPath := filepath.Join(dir, "cookies.sqlite")
	writeFirefoxCookieDB(t, ffPath)
	srcSecrets := filepath.Join(dir, "source-secrets")
	sinkSecrets := filepath.Join(dir, "sink-secrets")
	if err := os.MkdirAll(srcSecrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcSecrets, "api_token"), []byte("secret-live-receipt"), 0o600); err != nil {
		t.Fatal(err)
	}

	sidecarPath := filepath.Join(dir, "sidecar.db")
	sourceCfg := filepath.Join(dir, "source.toml")
	sinkCfg := filepath.Join(dir, "sink.toml")
	sourceReceipts := filepath.Join(dir, "source-receipts.jsonl")
	sinkReceipts := filepath.Join(dir, "sink-receipts.jsonl")
	writeConfig(t, sinkCfg, fmt.Sprintf(`
role = "sink"
peer = %q
key_path = %q
surfaces = ["sidecar", "secrets"]
sidecar_path = %q
secrets_dir = %q

[receipts]
enabled = true
path = %q
`, addr, keyPath, sidecarPath, sinkSecrets, sinkReceipts))
	writeConfig(t, sourceCfg, fmt.Sprintf(`
role = "source"
peer = %q
key_path = %q
secrets_dir = %q

[[browsers]]
kind = "firefox"
profile = "default"
cookie_path = %q

[domains]
allow = ["example.com"]

[secret_names]
allow = ["api_token"]

[receipts]
enabled = true
path = %q
`, addr, keyPath, srcSecrets, ffPath, sourceReceipts))

	sinkProc := startSinkProcess(t, bin, sinkCfg, addr)
	defer sinkProc.stop(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "source", "--config", sourceCfg, "--once")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("source --once failed: %v\n%s", err, out)
	}
	if got := waitForFile(t, filepath.Join(sinkSecrets, "api_token")); got != "secret-live-receipt" {
		t.Fatalf("secret did not sync: %q", got)
	}
	if _, err := os.Stat(sourceReceipts); err != nil {
		t.Fatalf("source receipt missing: %v\n%s", err, out)
	}
	if _, err := os.Stat(receipt.HeadPath(sourceReceipts)); err != nil {
		t.Fatalf("source receipt tip missing: %v\n%s", err, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, logErr := os.Stat(sinkReceipts)
		_, tipErr := os.Stat(receipt.HeadPath(sinkReceipts))
		if logErr == nil && tipErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sink receipt or tip missing\n%s\n%s", out, sinkProc.out.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	sinkProc.stop(t)

	for _, tc := range []struct {
		path, cfg string
	}{
		{sourceReceipts, sourceCfg},
		{sinkReceipts, sinkCfg},
	} {
		raw, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.ContainsSensitive(raw, "secret-live-receipt", "example-session") {
			t.Fatalf("%s leaked secret material:\n%s", tc.path, raw)
		}
		code, stdout, stderr := runReceipts(t, bin, "verify", "--config", tc.cfg, "--path", tc.path)
		if code != 0 {
			t.Fatalf("verify %s: %s", tc.path, stderr)
		}
		if !strings.Contains(stdout, "1 receipt") {
			t.Fatalf("verify %s: %s", tc.path, stdout)
		}
	}

	_, stdout, stderr := runReceipts(t, bin, "show", "--config", sourceCfg, "--json")
	if stderr != "" && !strings.Contains(stdout, "sync.send") {
		t.Fatalf("show source: %s %s", stdout, stderr)
	}
	var recs []receipt.Record
	if err := json.Unmarshal([]byte(stdout), &recs); err != nil {
		t.Fatalf("show json: %v\n%s", err, stdout)
	}
	if len(recs) != 1 || recs[0].Event != receipt.EventSend || recs[0].SourceID == "" || recs[0].SinkID == "" {
		t.Fatalf("source receipt: %+v", recs)
	}
}

func runReceipts(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"receipts"}, args...)...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return code, stdout.String(), stderr.String()
}
