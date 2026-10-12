package test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type treeEntry struct {
	size  int64
	mode  fs.FileMode
	mtime time.Time
}

func treeSnapshot(t *testing.T, root string) map[string]treeEntry {
	t.Helper()
	out := map[string]treeEntry{}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out[path] = treeEntry{size: info.Size(), mode: info.Mode(), mtime: info.ModTime()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func requireSameTree(t *testing.T, label string, before, after map[string]treeEntry) {
	t.Helper()
	for path, e := range after {
		prev, ok := before[path]
		if !ok {
			t.Errorf("%s: created %s", label, path)
		} else if prev != e {
			t.Errorf("%s: modified %s", label, path)
		}
	}
	for path := range before {
		if _, ok := after[path]; !ok {
			t.Errorf("%s: removed %s", label, path)
		}
	}
}

// peerWatch listens where a source would dial and reports whether anything
// connected. A dial completes in the kernel backlog even before Accept, so a
// short post-run Accept deadline is enough to catch it.
type peerWatch struct {
	ln *net.TCPListener
}

func newPeerWatch(t *testing.T) *peerWatch {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return &peerWatch{ln: ln.(*net.TCPListener)}
}

func (w *peerWatch) addr() string { return w.ln.Addr().String() }

func (w *peerWatch) requireNoConnection(t *testing.T, label string) {
	t.Helper()
	if err := w.ln.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := w.ln.Accept()
	if err == nil {
		_ = conn.Close()
		t.Fatalf("%s: the plan connected to the peer", label)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("%s: unexpected accept error: %v", label, err)
	}
}

func runPlanCLI(t *testing.T, bin, root string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(),
		"HOME="+filepath.Join(root, "home"),
		"USERPROFILE="+filepath.Join(root, "home"),
		"XDG_CONFIG_HOME="+filepath.Join(root, "xdg"),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return code, stdout.String(), stderr.String()
}

// TestSourceDryRunHasNoSideEffects drives the real binary against synthetic
// fixtures and proves the plan never syncs, dials, creates a key, emits a salt
// or frame, materializes a value, or mutates a file.
func TestSourceDryRunHasNoSideEffects(t *testing.T) {
	bin := agentpantryCLI(t)
	root := t.TempDir()
	for _, d := range []string{"home", "xdg", "cfg"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfgDir := filepath.Join(root, "cfg")
	keyPath := filepath.Join(cfgDir, "psk.key")
	writeKey(t, keyPath)
	missingKey := filepath.Join(cfgDir, "missing", "psk.key")

	ffPath := filepath.Join(root, "cookies.sqlite")
	writeFirefoxCookieDB(t, ffPath) // holds the cookie value "example-session"
	secretsDir := filepath.Join(root, "source-secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const secretValue = "plan-cli-secret-value"
	if err := os.WriteFile(filepath.Join(secretsDir, "api_token"), []byte(secretValue), 0o600); err != nil {
		t.Fatal(err)
	}

	peer := newPeerWatch(t)
	writeCfg := func(name, key string) string {
		p := filepath.Join(cfgDir, name)
		writeConfig(t, p, fmt.Sprintf(`
role = "source"
peer = %q
key_path = %q
secrets_dir = %q
warn_expiry_days = 14

[[browsers]]
kind = "firefox"
profile = "research"
cookie_path = %q

[domains]
allow = ["example.com"]
deny = ["blocked.example"]

[receipts]
enabled = true
`, peer.addr(), key, secretsDir, ffPath))
		return p
	}
	readyCfg := writeCfg("ready.toml", keyPath)
	missingKeyCfg := writeCfg("missing-key.toml", missingKey)

	leaks := []string{"example-session", "should-not-sync", secretValue, strings.Repeat("42", 32)}
	checkNoLeak := func(label, out string) {
		t.Helper()
		for _, v := range leaks {
			if strings.Contains(out, v) {
				t.Fatalf("%s: output contains value %q:\n%s", label, v, out)
			}
		}
	}

	type planJSON struct {
		DryRun bool `json:"dry_run"`
		Route  struct {
			Kind string `json:"kind"`
		} `json:"route"`
		Key struct {
			Present bool `json:"present"`
		} `json:"key"`
		Status struct {
			ConfigReadiness       string `json:"config_readiness"`
			CaptureCoverage       string `json:"capture_coverage"`
			WebsiteAuthentication string `json:"website_authentication"`
		} `json:"status"`
		Problems []string `json:"problems"`
	}
	// Decoding the whole of stdout as one JSON value proves no salt bytes or
	// sealed frames were written ahead of or after the plan.
	decode := func(label, stdout string) planJSON {
		t.Helper()
		var p planJSON
		dec := json.NewDecoder(strings.NewReader(stdout))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			t.Fatalf("%s: stdout is not a single JSON plan: %v\n%q", label, err, stdout)
		}
		if rest := strings.TrimSpace(stdout[dec.InputOffset():]); rest != "" {
			t.Fatalf("%s: unexpected bytes after the plan: %q", label, rest)
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		return p
	}

	runs := []struct {
		name      string
		args      []string
		wantCode  int
		wantReady string
		wantRoute string
		wantKey   bool
	}{
		{"tcp json", []string{"source", "-dry-run", "-json", "-config", readyCfg}, 0, "ready", "tcp", true},
		{"stdio once json", []string{"source", "-stdio", "-once", "-dry-run", "-json", "-config", readyCfg}, 0, "ready", "stdio", true},
		{"missing key json", []string{"source", "-dry-run", "-json", "-config", missingKeyCfg}, 1, "not_ready", "tcp", false},
	}
	for _, r := range runs {
		before := treeSnapshot(t, root)
		code, stdout, stderr := runPlanCLI(t, bin, root, r.args...)
		if code != r.wantCode {
			t.Fatalf("%s: exit %d, want %d\nstdout=%s\nstderr=%s", r.name, code, r.wantCode, stdout, stderr)
		}
		checkNoLeak(r.name, stdout+stderr)
		p := decode(r.name, stdout)
		if !p.DryRun || p.Status.ConfigReadiness != r.wantReady || p.Route.Kind != r.wantRoute || p.Key.Present != r.wantKey {
			t.Fatalf("%s: unexpected plan %+v", r.name, p)
		}
		if p.Status.CaptureCoverage != "not_measured" || p.Status.WebsiteAuthentication != "not_verified" {
			t.Fatalf("%s: coverage/auth must not be claimed: %+v", r.name, p.Status)
		}
		peer.requireNoConnection(t, r.name)
		requireSameTree(t, r.name, before, treeSnapshot(t, root))
	}
	if _, err := os.Stat(missingKey); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the plan created the missing key: %v", err)
	}
	for _, name := range []string{"state.json", "receipts.jsonl", "receipts.head"} {
		if _, err := os.Stat(filepath.Join(cfgDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the plan wrote %s: %v", name, err)
		}
	}

	// Text mode prints the same plan for an operator.
	before := treeSnapshot(t, root)
	code, stdout, stderr := runPlanCLI(t, bin, root, "source", "-dry-run", "-config", readyCfg)
	if code != 0 {
		t.Fatalf("text plan: exit %d\n%s%s", code, stdout, stderr)
	}
	checkNoLeak("text", stdout+stderr)
	for _, want := range []string{"config_readiness: ready", "capture_coverage: not_measured", "website_authentication: not_verified", "account identity: unknown", "profile \"research\""} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("text plan missing %q:\n%s", want, stdout)
		}
	}
	peer.requireNoConnection(t, "text")
	requireSameTree(t, "text", before, treeSnapshot(t, root))

	// -json without -dry-run is refused before anything runs.
	before = treeSnapshot(t, root)
	code, stdout, stderr = runPlanCLI(t, bin, root, "source", "-json", "-config", readyCfg)
	if code == 0 || !strings.Contains(stderr, "-json is only supported with -dry-run") {
		t.Fatalf("-json alone: exit %d stderr=%s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("-json alone wrote to stdout: %q", stdout)
	}
	peer.requireNoConnection(t, "json without dry-run")
	requireSameTree(t, "json without dry-run", before, treeSnapshot(t, root))
}
