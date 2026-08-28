package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/keyfile"
	"github.com/escoffier-labs/agentpantry/internal/pair"
)

func TestPairRequiresRoleAndCode(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "psk.key")
	if code, _, stderr := runCmd(t, bin, "pair", "-key", key); code == 0 {
		t.Fatalf("pair without role must fail, stderr=%s", stderr)
	}
	if code, _, stderr := runCmd(t, bin, "pair", "-role", "source", "-key", key, "-peer", "127.0.0.1:9"); code == 0 {
		t.Fatalf("source pair without -code must fail, stderr=%s", stderr)
	}
}

func TestPairRefusesDuringRotation(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "psk.key")
	if err := keyfile.Generate(key); err != nil {
		t.Fatal(err)
	}
	if _, err := keyfile.Rotate(key); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCmd(t, bin, "pair", "-role", "sink", "-key", key, "-bind", "127.0.0.1:0")
	if code == 0 {
		t.Fatal("pair during rotation must fail")
	}
	if !strings.Contains(stderr, "rotation") {
		t.Fatalf("error must mention rotation, got %q", stderr)
	}
}

func TestPairCLIRoundTripWritesMatchingKeys(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	sinkKey := filepath.Join(dir, "sink.key")
	srcKey := filepath.Join(dir, "source.key")

	sinkCmd := exec.Command(bin, "pair", "-role", "sink", "-key", sinkKey, "-bind", "127.0.0.1:0", "-timeout", "15s")
	sinkOut, err := sinkCmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	sinkCmd.Stderr = sinkCmd.Stdout
	if err := sinkCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sinkCmd.Process.Kill() }()

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 256)
	deadline := time.Now().Add(10 * time.Second)
	var code, addr string
	for time.Now().Before(deadline) && (code == "" || addr == "") {
		n, rerr := sinkOut.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		out := string(buf)
		if code == "" {
			if _, rest, ok := strings.Cut(out, "pairing code: "); ok {
				code, _, _ = strings.Cut(rest, "\n")
				code = strings.TrimSpace(code)
			}
		}
		if addr == "" {
			if _, rest, ok := strings.Cut(out, "waiting on "); ok {
				addr, _, _ = strings.Cut(rest, " ")
				addr = strings.TrimSpace(addr)
			}
		}
		if rerr != nil {
			break
		}
	}
	if code == "" || addr == "" {
		t.Fatalf("did not parse sink pairing banner:\n%s", buf)
	}

	srcCode, stdout, stderr := runCmd(t, bin, "pair", "-role", "source", "-key", srcKey, "-peer", addr, "-code", code)
	if srcCode != 0 {
		t.Fatalf("source pair failed: %s", stderr)
	}
	if err := sinkCmd.Wait(); err != nil {
		t.Fatalf("sink pair failed: %v\n%s", err, buf)
	}

	sk, err := keyfile.Load(sinkKey)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := keyfile.Load(srcKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(sk) != string(ck) {
		t.Fatal("paired keys must match")
	}
	fp := pair.Fingerprint(sk)
	if !strings.Contains(stdout, fp) && !strings.Contains(string(buf), fp) {
		t.Fatalf("both sides must print confirmation %s\nsource:\n%s\nsink:\n%s", fp, stdout, buf)
	}
}

func TestPairHelpMentionsFlags(t *testing.T) {
	bin := buildBin(t)
	res := commandWithStderr(t, bin, "pair", "-h")
	if !strings.Contains(res.stderr, "-role") || !strings.Contains(res.stderr, "-code") {
		t.Fatalf("pair -h must mention -role and -code, got %q", res.stderr)
	}
}
