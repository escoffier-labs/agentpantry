package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/receipt"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

func TestReceiptsVerifyAndShow(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "psk.key")
	if code, _, stderr := runCmd(t, bin, "keygen", "--out", key); code != 0 {
		t.Fatalf("keygen: %s", stderr)
	}
	cfg := filepath.Join(dir, "config.toml")
	logPath := filepath.Join(dir, "receipts.jsonl")
	body := "role = \"sink\"\npeer = \"127.0.0.1:8787\"\nkey_path = " + tomlQuote(key) + "\nsurfaces = [\"sidecar\"]\n\n[receipts]\nenabled = true\npath = " + tomlQuote(logPath) + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCmd(t, bin, "receipts", "verify", "--config", cfg)
	if code != 0 {
		t.Fatalf("empty verify must succeed, exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "0 receipt") {
		t.Fatalf("empty verify: %q", stdout)
	}

	keyBytes, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := hex.DecodeString(strings.TrimSpace(string(keyBytes)))
	if err != nil {
		t.Fatal(err)
	}
	lg := &receipt.Log{
		Path:     logPath,
		Key:      dec,
		Role:     "sink",
		SourceID: "source",
		SinkID:   "127.0.0.1:8787",
	}
	p := wire.Payload{
		Cookies: cookie.Diff{Upserts: []cookie.Cookie{{Host: "example.com", Name: "sid", Path: "/", Value: "cookie-live-value"}}},
		Secrets: secret.Diff{Upserts: []secret.Secret{{Name: "api", Value: "secret-live-value"}}},
	}
	if err := lg.Append(receipt.EventApply, p); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr = runCmd(t, bin, "receipts", "verify", "--config", cfg)
	if code != 0 {
		t.Fatalf("verify failed: %s", stderr)
	}
	if !strings.Contains(stdout, "1 receipt") {
		t.Fatalf("verify: %q", stdout)
	}

	code, stdout, stderr = runCmd(t, bin, "receipts", "show", "--config", cfg, "--json")
	if code != 0 {
		t.Fatalf("show --json: %s", stderr)
	}
	var recs []receipt.Record
	if err := json.Unmarshal([]byte(stdout), &recs); err != nil {
		t.Fatalf("show json: %v\n%s", err, stdout)
	}
	if len(recs) != 1 || recs[0].Event != receipt.EventApply {
		t.Fatalf("show records: %+v", recs)
	}
	if strings.Contains(stdout, "cookie-live-value") || strings.Contains(stdout, "secret-live-value") {
		t.Fatal("show must not print cookie or secret values")
	}

	code, stdout, stderr = runCmd(t, bin, "receipts", "show", "--config", cfg)
	if code != 0 {
		t.Fatalf("show: %s", stderr)
	}
	if !strings.Contains(stdout, "sync.apply") || !strings.Contains(stdout, "source=") {
		t.Fatalf("show text: %q", stdout)
	}
}

func TestReceiptsVerifyDetectsTamper(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "psk.key")
	if code, _, stderr := runCmd(t, bin, "keygen", "--out", key); code != 0 {
		t.Fatalf("keygen: %s", stderr)
	}
	cfg := filepath.Join(dir, "config.toml")
	logPath := filepath.Join(dir, "receipts.jsonl")
	body := "role = \"source\"\npeer = \"127.0.0.1:8787\"\nkey_path = " + tomlQuote(key) + "\n\n[receipts]\nenabled = true\npath = " + tomlQuote(logPath) + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("{\"v\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCmd(t, bin, "receipts", "verify", "--config", cfg)
	if code == 0 {
		t.Fatal("tampered log must fail verify")
	}
	if !strings.Contains(stderr, "receipt") {
		t.Fatalf("error should name the receipt, got %q", stderr)
	}
}
