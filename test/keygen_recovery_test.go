package test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// keygenRecoveryChecklistComplete reports whether blunt keygen replacement output
// tells operators to stop or close existing sink sessions and restart persistent
// sources after redistributing the new PSK.
func keygenRecoveryChecklistComplete(guidance string) bool {
	lower := strings.ToLower(guidance)
	sessionStop := (strings.Contains(lower, "stop") && strings.Contains(lower, "session")) ||
		(strings.Contains(lower, "close") && strings.Contains(lower, "connection"))
	sourceRestart := strings.Contains(lower, "restart") && strings.Contains(lower, "source")
	return sessionStop && sourceRestart
}

func runCLI(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run error: %v", err)
	}
	return code, stdout.String(), stderr.String()
}

// TestKeygenReplacementRecoveryChecklist reproduces issue #63: cmd/agentpantry/main.go
// loads the source PSK once before its reconnect loop while each sink connection
// builds a fresh opener from the on-disk key (newSinkOpener). After blunt keygen
// replaces the sink key, a persistent source still seals with the stale PSK and
// cannot authenticate to new sink connections. An unfinished rotate-key grace
// file must not keep accepting that stale key after blunt recovery. Operators
// need to stop existing sink sessions and restart persistent sources; keygen's
// recovery output must say so.
func TestKeygenReplacementRecoveryChecklist(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	addr := freeTCPAddr(t)
	keyPath := filepath.Join(dir, "psk.key")

	if code, _, stderr := runCLI(t, bin, "keygen", "--out", keyPath); code != 0 {
		t.Fatalf("initial keygen failed: %s", stderr)
	}

	ffPath := filepath.Join(dir, "cookies.sqlite")
	writeFirefoxCookieDB(t, ffPath)
	srcSecrets := filepath.Join(dir, "source-secrets")
	sinkSecrets := filepath.Join(dir, "sink-secrets")
	if err := os.MkdirAll(srcSecrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcSecrets, "api_token"), []byte("secret-live"), 0o600); err != nil {
		t.Fatal(err)
	}
	sidecarPath := filepath.Join(dir, "sidecar.db")
	sourceCfg := filepath.Join(dir, "source.toml")
	sinkCfg := filepath.Join(dir, "sink.toml")
	writeConfig(t, sinkCfg, fmt.Sprintf(`
role = "sink"
peer = %q
key_path = %q
surfaces = ["sidecar", "secrets"]
sidecar_path = %q
secrets_dir = %q
`, addr, keyPath, sidecarPath, sinkSecrets))
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
deny = ["blocked.example"]
`, addr, keyPath, srcSecrets, ffPath))

	sinkProc := startSinkProcess(t, bin, sinkCfg, addr)
	defer sinkProc.stop(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outPath := filepath.Join(dir, "source.out")
	outFile, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()
	sourceOut := func() string {
		data, _ := os.ReadFile(outPath)
		return string(data)
	}
	cmd := exec.CommandContext(ctx, bin, "source", "--config", sourceCfg)
	cmd.Stdout = outFile
	cmd.Stderr = outFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	if got := waitForFile(t, filepath.Join(sinkSecrets, "api_token")); got != "secret-live" {
		t.Fatalf("initial sync secret did not land: %q\n%s", got, sourceOut())
	}

	oldKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := keyPath + ".old"

	// Leave an unfinished rotation behind: K0 is the still-running source key,
	// K1 is the rotated key, and psk.key.old holds K0 for the grace window.
	if code, _, stderr := runCLI(t, bin, "rotate-key", "--config", sinkCfg); code != 0 {
		t.Fatalf("rotate-key failed: %s", stderr)
	}
	rotationOldKey, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("read rotation old key: %v", err)
	}
	if string(rotationOldKey) != string(oldKey) {
		t.Fatal("rotation old key must retain the pre-rotation source key")
	}

	// Blunt recovery procedure: replace the sink key in place with K2. It must
	// also revoke the unfinished rotation's K0 grace key.
	code, keygenStdout, keygenStderr := runCLI(t, bin, "keygen", "--out", keyPath)
	if code != 0 {
		t.Fatalf("replacement keygen failed: %s", keygenStderr)
	}
	guidance := keygenStdout + keygenStderr
	newKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldKey) == string(newKey) {
		t.Fatal("replacement keygen must write a fresh key")
	}

	// Drop the live session so the sink builds a new opener from the replacement key.
	// Keep the restarted sink in its own variable and stop it before TempDir cleanup:
	// on Windows an open sidecar.db handle blocks RemoveAll (PR #65 CI failure).
	sinkProc.stop(t)
	restartedSink := startSinkProcess(t, bin, sinkCfg, addr)
	defer restartedSink.stop(t)

	if err := os.WriteFile(filepath.Join(srcSecrets, "api_token"), []byte("after-keygen"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Persistent source still seals with the PSK loaded once at startup; new sink
	// connections cannot open those frames.
	deadline := time.Now().Add(8 * time.Second)
	var sawReconnect bool
	for time.Now().Before(deadline) {
		out := sourceOut()
		if strings.Contains(out, "connection lost") || strings.Contains(out, "reconnecting") {
			sawReconnect = true
		}
		if data, err := os.ReadFile(filepath.Join(sinkSecrets, "api_token")); err == nil && string(data) == "after-keygen" {
			t.Fatalf("stale source PSK must not sync after blunt keygen replacement\nsource output:\n%s", out)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sawReconnect {
		t.Fatalf("persistent source must attempt reconnect after sink session reset\nsource output:\n%s", sourceOut())
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("blunt keygen must remove the unfinished rotation key %s, stat error: %v", oldPath, err)
	}

	if !keygenRecoveryChecklistComplete(guidance) {
		t.Fatalf("keygen replacement recovery checklist must tell operators to stop existing sink sessions and restart persistent sources after redistributing the new PSK; got:\n%s\nsource output after stale-key reconnect:\n%s", guidance, sourceOut())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("source did not stop after cancellation\n%s", sourceOut())
	}
	// Release sidecar.db before t.TempDir cleanup (required on Windows).
	restartedSink.stop(t)
}
