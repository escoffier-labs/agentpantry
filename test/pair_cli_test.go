package test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/keyfile"
	"github.com/escoffier-labs/agentpantry/internal/pair"
)

func TestPairThenOnceSync(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sinkKey := filepath.Join(dir, "sink.key")
	srcKey := filepath.Join(dir, "source.key")

	sinkCmd := exec.Command(bin, "pair", "-role", "sink", "-key", sinkKey, "-bind", "127.0.0.1:0", "-timeout", "15s")
	var sinkOut bytes.Buffer
	sinkCmd.Stdout = &sinkOut
	sinkCmd.Stderr = &sinkOut
	if err := sinkCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sinkCmd.Process.Kill() }()

	code, addr := waitPairBanner(t, &sinkOut)
	if srcCode, _, stderr := runCLI(t, bin, "pair", "-role", "source", "-key", srcKey, "-peer", addr, "-code", code); srcCode != 0 {
		t.Fatalf("source pair failed: %s\nsink:\n%s", stderr, sinkOut.String())
	}
	if err := sinkCmd.Wait(); err != nil {
		t.Fatalf("sink pair failed: %v\n%s", err, sinkOut.String())
	}

	sk, err := keyfile.Load(sinkKey)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := keyfile.Load(srcKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk, ck) {
		t.Fatal("paired keys must match")
	}
	fp := pair.Fingerprint(sk)
	if !strings.Contains(sinkOut.String(), fp) {
		t.Fatalf("sink must print confirmation %s\n%s", fp, sinkOut.String())
	}

	addr = freeTCPAddr(t)
	ffPath := filepath.Join(dir, "cookies.sqlite")
	writeFirefoxCookieDB(t, ffPath)
	srcSecrets := filepath.Join(dir, "source-secrets")
	sinkSecrets := filepath.Join(dir, "sink-secrets")
	if err := os.MkdirAll(srcSecrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcSecrets, "api_token"), []byte("paired-secret"), 0o600); err != nil {
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
`, addr, sinkKey, sidecarPath, sinkSecrets))
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
`, addr, srcKey, srcSecrets, ffPath))

	sinkProc := startSinkProcess(t, bin, sinkCfg, addr)
	defer sinkProc.stop(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "source", "--config", sourceCfg, "--once")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("source --once after pair failed: %v\n%s", err, out)
	}
	if got := waitForFile(t, filepath.Join(sinkSecrets, "api_token")); got != "paired-secret" {
		t.Fatalf("paired PSK did not sync secret: %q\n%s", got, out)
	}
	sinkProc.stop(t)
	if got := readSidecarCookie(t, sidecarPath, "example.com"); got != "example-session" {
		t.Fatalf("paired PSK did not sync cookie: %q", got)
	}
}

func waitPairBanner(t *testing.T, out *bytes.Buffer) (code, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s := out.String()
		if code == "" {
			if _, rest, ok := strings.Cut(s, "pairing code: "); ok {
				code, _, _ = strings.Cut(rest, "\n")
				code = strings.TrimSpace(code)
			}
		}
		if addr == "" {
			if _, rest, ok := strings.Cut(s, "waiting on "); ok {
				addr, _, _ = strings.Cut(rest, " ")
				addr = strings.TrimSpace(addr)
			}
		}
		if code != "" && addr != "" {
			return code, addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("did not parse pairing banner:\n%s", out.String())
	return "", ""
}
