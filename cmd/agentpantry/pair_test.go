package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/keyfile"
	"github.com/escoffier-labs/agentpantry/internal/pair"
)

func TestSinkPairAddrIgnoresConfigPeer(t *testing.T) {
	if got := sinkPairAddr(""); got != defaultPairBind {
		t.Fatalf("empty -bind must default to %s, got %s", defaultPairBind, got)
	}
	if got := sinkPairAddr("0.0.0.0:9"); got != "0.0.0.0:9" {
		t.Fatalf("-bind must win, got %s", got)
	}
}

func TestPairingBindIsWide(t *testing.T) {
	cases := []struct {
		addr string
		wide bool
	}{
		{":8787", true},
		{"0.0.0.0:8787", true},
		{"[::]:8787", true},
		{"192.0.2.10:8787", true},
		{"127.0.0.1:8787", false},
		{"[::1]:8787", false},
		{"localhost:8787", false},
	}
	for _, tc := range cases {
		if got := pairingBindIsWide(tc.addr); got != tc.wide {
			t.Errorf("pairingBindIsWide(%q) = %v, want %v", tc.addr, got, tc.wide)
		}
	}
}

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

func TestPairDefaultsToLoopbackDespiteWideSinkPeer(t *testing.T) {
	ln, err := net.Listen("tcp", defaultPairBind)
	if err != nil {
		t.Skipf("%s busy: %v", defaultPairBind, err)
	}
	_ = ln.Close()

	bin := buildBin(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "psk.key")
	srcKey := filepath.Join(dir, "source.key")
	cfg := filepath.Join(dir, "config.toml")
	body := "role = \"sink\"\npeer = \"0.0.0.0:8787\"\nkey_path = " + tomlQuote(key) + "\nsurfaces = [\"sidecar\"]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	sinkCmd := exec.Command(bin, "pair", "-role", "sink", "-config", cfg, "-timeout", "15s")
	var stdout, stderr syncBuf
	sinkCmd.Stdout = &stdout
	sinkCmd.Stderr = &stderr
	if err := sinkCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sinkCmd.Process.Kill() }()

	code, addr := waitPairBannerFromBuffers(t, &stdout, &stderr)
	if addr != defaultPairBind {
		t.Fatalf("sink config peer 0.0.0.0:8787 must not seed the pairing listener, waiting on %q\nstdout:\n%s\nstderr:\n%s", addr, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "0.0.0.0") {
		t.Fatalf("must not warn about the sync peer bind when pairing on loopback:\n%s", stderr.String())
	}

	srcCode, _, srcErr := runCmd(t, bin, "pair", "-role", "source", "-key", srcKey, "-peer", addr, "-code", code)
	if srcCode != 0 {
		t.Fatalf("source pair failed: %s", srcErr)
	}
	if err := sinkCmd.Wait(); err != nil {
		t.Fatalf("sink pair failed: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
}

func TestPairWarnsOnEmptyHostBind(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "sink.key")
	srcKey := filepath.Join(dir, "source.key")

	sinkCmd := exec.Command(bin, "pair", "-role", "sink", "-key", key, "-bind", ":0", "-timeout", "15s")
	var stdout, stderr syncBuf
	sinkCmd.Stdout = &stdout
	sinkCmd.Stderr = &stderr
	if err := sinkCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sinkCmd.Process.Kill() }()

	code, addr := waitPairBannerFromBuffers(t, &stdout, &stderr)
	if !strings.Contains(stderr.String(), "beyond loopback") {
		t.Fatalf("-bind :0 must warn that an empty host is wide-open, stderr=%q", stderr.String())
	}

	srcCode, _, srcErr := runCmd(t, bin, "pair", "-role", "source", "-key", srcKey, "-peer", addr, "-code", code)
	if srcCode != 0 {
		t.Fatalf("source pair failed: %s\nsink stderr:\n%s", srcErr, stderr.String())
	}
	if err := sinkCmd.Wait(); err != nil {
		t.Fatalf("sink pair failed: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
}

func TestPairBacksUpExistingKey(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	sinkKey := filepath.Join(dir, "sink.key")
	srcKey := filepath.Join(dir, "source.key")
	if err := keyfile.Generate(sinkKey); err != nil {
		t.Fatal(err)
	}
	old, err := keyfile.Load(sinkKey)
	if err != nil {
		t.Fatal(err)
	}

	sinkCmd := exec.Command(bin, "pair", "-role", "sink", "-key", sinkKey, "-bind", "127.0.0.1:0", "-timeout", "15s")
	var stdout, stderr syncBuf
	sinkCmd.Stdout = &stdout
	sinkCmd.Stderr = &stderr
	if err := sinkCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sinkCmd.Process.Kill() }()

	code, addr := waitPairBannerFromBuffers(t, &stdout, &stderr)
	srcCode, srcOut, srcErr := runCmd(t, bin, "pair", "-role", "source", "-key", srcKey, "-peer", addr, "-code", code)
	if srcCode != 0 {
		t.Fatalf("source pair failed: %s", srcErr)
	}
	if err := sinkCmd.Wait(); err != nil {
		t.Fatalf("sink pair failed: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
	combined := stdout.String() + srcOut
	if !strings.Contains(combined, "backed up previous PSK") {
		t.Fatalf("re-pair must report a backup, sink:\n%s\nsource:\n%s", stdout.String(), srcOut)
	}
	matches, err := filepath.Glob(sinkKey + ".bak.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("re-pair must leave psk.key.bak.* beside the replaced key")
	}
	got, err := keyfile.Load(sinkKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == string(old) {
		t.Fatal("re-pair must replace the existing key")
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitPairBannerFromBuffers(t *testing.T, stdout, stderr *syncBuf) (code, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out := stdout.String() + stderr.String()
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
		if code != "" && addr != "" {
			return code, addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("did not parse sink pairing banner:\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	return "", ""
}
