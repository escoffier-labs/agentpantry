package test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/state"
)

var cliBuild struct {
	once sync.Once
	path string
	err  error
}

func agentpantryCLI(t *testing.T) string {
	t.Helper()
	cliBuild.once.Do(func() {
		dir, err := os.MkdirTemp("", "agentpantry-cli-test-")
		if err != nil {
			cliBuild.err = err
			return
		}
		name := "agentpantry"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		cliBuild.path = filepath.Join(dir, name)
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", cliBuild.path, "../cmd/agentpantry")
		out, err := cmd.CombinedOutput()
		if err != nil {
			cliBuild.err = fmt.Errorf("go build: %w\n%s", err, out)
		}
	})
	if cliBuild.err != nil {
		t.Fatal(cliBuild.err)
	}
	return cliBuild.path
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func writeKey(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Repeat("42", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFirefoxCookieDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE moz_cookies(
		id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT '',
		name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER,
		lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER,
		isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0,
		sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(5 * 24 * time.Hour).Unix()
	rows := []struct {
		host, value string
	}{
		{"example.com", "example-session"},
		{"blocked.example", "should-not-sync"},
	}
	for _, row := range rows {
		if _, err := db.Exec(`INSERT INTO moz_cookies(name,value,host,path,expiry,isSecure,isHttpOnly,sameSite)
			VALUES(?,?,?,?,?,?,?,?)`, "sid", row.value, row.host, "/", expiry, 1, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
}

type runningProcess struct {
	cancel   context.CancelFunc
	done     chan error
	out      *bytes.Buffer
	stopOnce sync.Once
}

func startSinkProcess(t *testing.T, bin, cfgPath, addr string) *runningProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "sink", "--config", cfgPath)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	rp := &runningProcess{cancel: cancel, done: make(chan error, 1), out: &out}
	go func() { rp.done <- cmd.Wait() }()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return rp
		}
		select {
		case err := <-rp.done:
			cancel()
			t.Fatalf("sink exited before listening: %v\n%s", err, out.String())
		case <-time.After(25 * time.Millisecond):
		}
	}
	cancel()
	t.Fatalf("sink did not listen on %s\n%s", addr, out.String())
	return nil
}

// stop cancels the process and waits for it to exit. Idempotent: safe to call
// explicitly (to flush and release a sink's sidecar file before reading it)
// and again via defer.
func (rp *runningProcess) stop(t *testing.T) {
	t.Helper()
	rp.stopOnce.Do(func() {
		rp.cancel()
		select {
		case <-rp.done:
		case <-time.After(3 * time.Second):
			t.Fatalf("process did not exit after cancellation\n%s", rp.out.String())
		}
	})
}

func waitForFile(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			return string(data)
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("file %s never appeared: %v", path, lastErr)
	return ""
}

// openSidecarRO opens the sidecar read-only, matching surface.OpenSidecarReadOnly.
// Call only after the writing sink process has stopped: a cross-process read
// while the sink still holds the file open is unreliable on Windows.
func openSidecarRO(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatalf("open sidecar: %v", err)
	}
	return db
}

func readSidecarCookie(t *testing.T, path, host string) string {
	t.Helper()
	db := openSidecarRO(t, path)
	defer db.Close()
	var got string
	if err := db.QueryRow(`SELECT value FROM cookies WHERE host=?`, host).Scan(&got); err != nil {
		t.Fatalf("cookie %s missing from sidecar: %v", host, err)
	}
	return got
}

func countSidecarCookies(t *testing.T, path, host string) int {
	t.Helper()
	db := openSidecarRO(t, path)
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cookies WHERE host=?`, host).Scan(&n); err != nil {
		t.Fatalf("count cookies for %s: %v", host, err)
	}
	return n
}

func TestSourceOnceSyncsAndExits(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(srcSecrets, "api_token"), []byte("secret-live"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcSecrets, "drop_token"), []byte("drop-me"), 0o600); err != nil {
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
warn_expiry_days = 14

[[browsers]]
kind = "firefox"
profile = "default"
cookie_path = %q

[domains]
allow = ["example.com"]
deny = ["blocked.example"]

[secret_names]
allow = ["api_token", "drop_token"]
deny = ["drop_token"]
`, addr, keyPath, srcSecrets, ffPath))

	sinkProc := startSinkProcess(t, bin, sinkCfg, addr)
	defer sinkProc.stop(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "source", "--config", sourceCfg, "--once")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("source --once failed: %v\n%s", err, out)
	}
	if ctx.Err() != nil {
		t.Fatalf("source --once did not exit before timeout\n%s", out)
	}
	// The synced secret file proves the sink applied the frame. Then stop the
	// sink so its sidecar handle is flushed and released before we read it: a
	// cross-process sqlite read while the sink holds the file open is
	// unreliable on Windows.
	if got := waitForFile(t, filepath.Join(sinkSecrets, "api_token")); got != "secret-live" {
		t.Fatalf("allowed secret did not sync: %q", got)
	}
	if _, err := os.Stat(filepath.Join(sinkSecrets, "drop_token")); !os.IsNotExist(err) {
		t.Fatalf("denied secret synced: %v", err)
	}
	sinkProc.stop(t)

	if got := readSidecarCookie(t, sidecarPath, "example.com"); got != "example-session" {
		t.Fatalf("example cookie mismatch: %q", got)
	}
	if n := countSidecarCookies(t, sidecarPath, "blocked.example"); n != 0 {
		t.Fatal("denied domain synced to sidecar")
	}
	output := string(out)
	if !strings.Contains(output, "warning: cookie sid@example.com expires") {
		t.Fatalf("near-expiry warning missing from source output:\n%s", output)
	}
	if strings.Contains(output, "blocked.example") {
		t.Fatalf("near-expiry warning ignored domain policy:\n%s", output)
	}
	st, err := state.Load(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st.LastSyncUnix == 0 || st.LastSentUnix == 0 || st.Cookies != 1 || st.Secrets != 1 {
		t.Fatalf("state not persisted after --once sync: %+v", st)
	}
}

func TestSourceOnceStdioSyncsAndExits(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "psk.key")
	writeKey(t, keyPath)

	ffPath := filepath.Join(dir, "cookies.sqlite")
	writeFirefoxCookieDB(t, ffPath)
	sidecarPath := filepath.Join(dir, "sidecar.db")
	sourceCfg := filepath.Join(dir, "source.toml")
	sinkCfg := filepath.Join(dir, "sink.toml")
	writeConfig(t, sinkCfg, fmt.Sprintf(`
role = "sink"
peer = "127.0.0.1:1"
key_path = %q
surfaces = ["sidecar"]
sidecar_path = %q
`, keyPath, sidecarPath))
	writeConfig(t, sourceCfg, fmt.Sprintf(`
role = "source"
peer = "127.0.0.1:1"
key_path = %q

[[browsers]]
kind = "firefox"
profile = "default"
cookie_path = %q

[domains]
allow = ["example.com"]
deny = ["blocked.example"]
`, keyPath, ffPath))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pr, pw := io.Pipe()
	var sourceOut, sinkOut bytes.Buffer
	sinkCmd := exec.CommandContext(ctx, bin, "sink", "--config", sinkCfg, "--stdio")
	sinkCmd.Stdin = pr
	sinkCmd.Stdout = &sinkOut
	sinkCmd.Stderr = &sinkOut
	if err := sinkCmd.Start(); err != nil {
		t.Fatal(err)
	}
	sinkDone := make(chan error, 1)
	go func() { sinkDone <- sinkCmd.Wait() }()

	sourceCmd := exec.CommandContext(ctx, bin, "source", "--config", sourceCfg, "--once", "--stdio")
	sourceCmd.Stdout = pw
	sourceCmd.Stderr = &sourceOut
	sourceDone := make(chan error, 1)
	if err := sourceCmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		t.Fatal(err)
	}
	go func() {
		sourceDone <- sourceCmd.Wait()
		_ = pw.Close()
	}()

	if err := <-sourceDone; err != nil {
		_ = pr.Close()
		t.Fatalf("source --once --stdio failed: %v\n%s", err, sourceOut.String())
	}
	select {
	case err := <-sinkDone:
		if err != nil {
			t.Fatalf("sink --stdio failed: %v\nsource:\n%s\nsink:\n%s", err, sourceOut.String(), sinkOut.String())
		}
	case <-time.After(3 * time.Second):
		_ = pr.Close()
		t.Fatalf("sink --stdio did not exit after source --once closed stdout\nsource:\n%s\nsink:\n%s", sourceOut.String(), sinkOut.String())
	}
	if ctx.Err() != nil {
		t.Fatalf("stdio --once pipeline timed out\nsource:\n%s\nsink:\n%s", sourceOut.String(), sinkOut.String())
	}
	// Both processes have exited, so the sidecar handle is released.
	if got := readSidecarCookie(t, sidecarPath, "example.com"); got != "example-session" {
		t.Fatalf("example cookie mismatch after stdio --once: %q", got)
	}
}

func TestSourceOnceReturnsNonzeroOnInitialSyncFailure(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	addr := freeTCPAddr(t)
	keyPath := filepath.Join(dir, "psk.key")
	writeKey(t, keyPath)

	sidecarPath := filepath.Join(dir, "sidecar.db")
	sourceCfg := filepath.Join(dir, "source.toml")
	sinkCfg := filepath.Join(dir, "sink.toml")
	writeConfig(t, sinkCfg, fmt.Sprintf(`
role = "sink"
peer = %q
key_path = %q
surfaces = ["sidecar"]
sidecar_path = %q
`, addr, keyPath, sidecarPath))
	writeConfig(t, sourceCfg, fmt.Sprintf(`
role = "source"
peer = %q
key_path = %q

[[browsers]]
kind = "firefox"
profile = "missing"
cookie_path = %q

[domains]
allow = ["example.com"]
deny = []
`, addr, keyPath, filepath.Join(dir, "missing-cookies.sqlite")))

	sinkProc := startSinkProcess(t, bin, sinkCfg, addr)
	defer sinkProc.stop(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "source", "--config", sourceCfg, "--once")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("source --once succeeded despite unreadable browser source\n%s", out)
	}
	if ctx.Err() != nil {
		t.Fatalf("source --once failure did not exit before timeout\n%s", out)
	}
	if !strings.Contains(string(out), "error:") {
		t.Fatalf("source --once failure did not report an error:\n%s", out)
	}
}

func TestSourceWithoutOnceKeepsRunningAfterInitialSync(t *testing.T) {
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
	// Source output goes to a file so it can be read race-free while the
	// process is still running (go test -race forbids reading a live buffer).
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

	// Wait for the secret file, which the sink writes as a plain file when it
	// applies the source's initial frame: portable proof the initial sync
	// landed, without racing the sink for its open sidecar handle.
	if got := waitForFile(t, filepath.Join(sinkSecrets, "api_token")); got != "secret-live" {
		t.Fatalf("initial sync secret did not land: %q\n%s", got, sourceOut())
	}
	// Core assertion: without --once the source stays running after that sync.
	select {
	case err := <-done:
		t.Fatalf("source exited without --once after initial sync: %v\n%s", err, sourceOut())
	case <-time.After(500 * time.Millisecond):
	}
	// Stop the sink to flush and release its sidecar handle, then read the
	// cookie cleanly (see readSidecarCookie).
	sinkProc.stop(t)
	if got := readSidecarCookie(t, sidecarPath, "example.com"); got != "example-session" {
		t.Fatalf("initial sync cookie mismatch: %q", got)
	}
	if n := countSidecarCookies(t, sidecarPath, "blocked.example"); n != 0 {
		t.Fatal("denied domain synced to sidecar")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("source did not stop after cancellation\n%s", sourceOut())
	}
}
