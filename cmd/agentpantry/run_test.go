package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeSinkRunConfig(t *testing.T, dir, secretsDir, extra string) string {
	t.Helper()
	cfg := filepath.Join(dir, "config.toml")
	body := "role = \"sink\"\npeer = \"127.0.0.1:8787\"\nsurfaces = [\"sidecar\"]\nsecrets_dir = " + tomlQuote(secretsDir) + "\n" + extra
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeSecretFile(t *testing.T, dir, name, value string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func buildRunHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	body := `package main
import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)
func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "-print":
		if len(os.Args) < 3 {
			os.Exit(2)
		}
		fmt.Print(os.Getenv(os.Args[2]))
	case "-exit":
		if len(os.Args) < 3 {
			os.Exit(2)
		}
		n, err := strconv.Atoi(os.Args[2])
		if err != nil {
			os.Exit(2)
		}
		os.Exit(n)
	case "-cat":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "-sleep":
		if len(os.Args) >= 3 {
			_ = os.WriteFile(os.Args[2], []byte(strconv.Itoa(os.Getpid())), 0o600)
		}
		time.Sleep(60 * time.Second)
	default:
		os.Exit(2)
	}
}
`
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "helper")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper build: %v\n%s", err, out)
	}
	return bin
}

func runRun(t *testing.T, bin string, extraEnv []string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"run"}, args...)...)
	if extraEnv != nil {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	stdout, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(stdout), string(ee.Stderr)
	}
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	return 0, string(stdout), ""
}

func TestRunInjectsSecretAndPreservesParentEnv(t *testing.T) {
	bin := buildBin(t)
	helper := buildRunHelper(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	writeSecretFile(t, secrets, "gh_token", "tok-value")
	cfg := writeSinkRunConfig(t, dir, secrets, "")

	code, stdout, stderr := runRun(t, bin, []string{"PARENT_KEEP=from-parent"}, "--config", cfg, "--", helper, "-print", "GH_TOKEN")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if stdout != "tok-value" {
		t.Fatalf("injected value: %q", stdout)
	}

	code, stdout, stderr = runRun(t, bin, []string{"PARENT_KEEP=from-parent"}, "--config", cfg, "--", helper, "-print", "PARENT_KEEP")
	if code != 0 {
		t.Fatalf("parent env exit %d: %s", code, stderr)
	}
	if stdout != "from-parent" {
		t.Fatalf("parent env lost: %q", stdout)
	}
}

func TestRunDenyWinsDoesNotInject(t *testing.T) {
	bin := buildBin(t)
	helper := buildRunHelper(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	writeSecretFile(t, secrets, "ap_run_allowed", "tok-value")
	writeSecretFile(t, secrets, "ap_run_denied", "aws-value")
	cfg := writeSinkRunConfig(t, dir, secrets, "\n[secret_names]\nallow = []\ndeny = [\"ap_run_denied\"]\n")

	code, stdout, stderr := runRun(t, bin, nil, "--config", cfg, "--", helper, "-print", "AP_RUN_DENIED")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("denied secret must not be injected, got %q", stdout)
	}

	code, stdout, stderr = runRun(t, bin, nil, "--config", cfg, "--", helper, "-print", "AP_RUN_ALLOWED")
	if code != 0 {
		t.Fatalf("allowed exit %d: %s", code, stderr)
	}
	if stdout != "tok-value" {
		t.Fatalf("allowed secret missing: %q", stdout)
	}
}

func TestRunSecretFlagNarrows(t *testing.T) {
	bin := buildBin(t)
	helper := buildRunHelper(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	writeSecretFile(t, secrets, "gh_token", "tok-value")
	writeSecretFile(t, secrets, "ap_run_other", "other-value")
	cfg := writeSinkRunConfig(t, dir, secrets, "")

	code, stdout, stderr := runRun(t, bin, nil, "--config", cfg, "--secret", "gh_token", "--", helper, "-print", "AP_RUN_OTHER")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("unselected secret must not be injected, got %q", stdout)
	}
}

func TestRunDeniedSecretFlagFailsClosed(t *testing.T) {
	bin := buildBin(t)
	helper := buildRunHelper(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	writeSecretFile(t, secrets, "aws_key", "aws-value")
	cfg := writeSinkRunConfig(t, dir, secrets, "\n[secret_names]\ndeny = [\"aws_key\"]\n")

	code, stdout, stderr := runRun(t, bin, nil, "--config", cfg, "--secret", "aws_key", "--", helper, "-print", "AWS_KEY")
	if code == 0 {
		t.Fatal("denied -secret must fail")
	}
	if strings.Contains(stdout, "aws-value") || strings.Contains(stderr, "aws-value") {
		t.Fatalf("secret value leaked: stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "denied") {
		t.Fatalf("error should name the deny, got %q", stderr)
	}
}

func TestRunDryRunNamesOnlyNoExec(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	writeSecretFile(t, secrets, "gh_token", "tok-value")
	cfg := writeSinkRunConfig(t, dir, secrets, "")

	code, stdout, stderr := runRun(t, bin, nil, "--config", cfg, "--dry-run", "--", "/nonexistent/agentpantry-run-should-not-exec")
	if code != 0 {
		t.Fatalf("dry-run exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "GH_TOKEN") {
		t.Fatalf("dry-run should list GH_TOKEN, got %q", stdout)
	}
	if strings.Contains(stdout, "tok-value") || strings.Contains(stderr, "tok-value") {
		t.Fatalf("dry-run leaked value: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestRunEnvMapping(t *testing.T) {
	bin := buildBin(t)
	helper := buildRunHelper(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	writeSecretFile(t, secrets, "gh_token", "tok-value")
	cfg := writeSinkRunConfig(t, dir, secrets, "")

	code, stdout, stderr := runRun(t, bin, nil, "--config", cfg, "--env", "gh_token=MY_TOKEN", "--", helper, "-print", "MY_TOKEN")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if stdout != "tok-value" {
		t.Fatalf("mapped env: %q", stdout)
	}
}

func TestRunRejectsReservedEnvShadowing(t *testing.T) {
	bin := buildBin(t)
	helper := buildRunHelper(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	writeSecretFile(t, secrets, "path", "/tmp/evil-bin")
	writeSecretFile(t, secrets, "ld_preload", "/tmp/evil.so")
	cfg := writeSinkRunConfig(t, dir, secrets, "")

	for _, tc := range []struct{ secret, env string }{
		{"path", "PATH"},
		{"ld_preload", "LD_PRELOAD"},
	} {
		code, stdout, stderr := runRun(t, bin, nil, "--config", cfg, "--secret", tc.secret, "--", helper, "-print", tc.env)
		if code == 0 {
			t.Fatalf("%s must not inject, helper ran", tc.env)
		}
		if !strings.Contains(stderr, "reserved") {
			t.Fatalf("%s error should mention reserved, got %q", tc.env, stderr)
		}
		if strings.Contains(stdout, "/tmp/evil") || strings.Contains(stderr, "/tmp/evil") {
			t.Fatalf("%s leaked value: stdout=%q stderr=%q", tc.env, stdout, stderr)
		}
	}
}

func TestRunStdinPassthrough(t *testing.T) {
	bin := buildBin(t)
	helper := buildRunHelper(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := writeSinkRunConfig(t, dir, secrets, "")

	cmd := exec.Command(bin, "run", "--config", cfg, "--", helper, "-cat")
	cmd.Stdin = strings.NewReader("stdin-payload")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("stdin passthrough exit %d: %s", ee.ExitCode(), ee.Stderr)
		}
		t.Fatal(err)
	}
	if string(out) != "stdin-payload" {
		t.Fatalf("stdin passthrough: got %q", out)
	}
}

func TestRunRejectsSourceRole(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte("role = \"source\"\npeer = \"127.0.0.1:8787\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runRun(t, bin, nil, "--config", cfg, "--dry-run")
	if code == 0 {
		t.Fatal("source role must fail")
	}
	if !strings.Contains(stderr, "sink") {
		t.Fatalf("error should mention sink, got %q", stderr)
	}
}

func TestRunRequiresCommand(t *testing.T) {
	bin := buildBin(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := writeSinkRunConfig(t, dir, secrets, "")
	code, _, stderr := runRun(t, bin, nil, "--config", cfg)
	if code == 0 {
		t.Fatal("missing command must fail")
	}
	if !strings.Contains(stderr, "command") {
		t.Fatalf("error should mention command, got %q", stderr)
	}
}

func TestRunPropagatesChildExit(t *testing.T) {
	bin := buildBin(t)
	helper := buildRunHelper(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := writeSinkRunConfig(t, dir, secrets, "")
	code, _, stderr := runRun(t, bin, nil, "--config", cfg, "--", helper, "-exit", "7")
	if code != 7 {
		t.Fatalf("want child exit 7, got %d (%s)", code, stderr)
	}
}

func TestRunDoesNotStageSecretFiles(t *testing.T) {
	bin := buildBin(t)
	helper := buildRunHelper(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	writeSecretFile(t, secrets, "gh_token", "tok-value")
	cfg := writeSinkRunConfig(t, dir, secrets, "")

	before, err := os.ReadDir(secrets)
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runRun(t, bin, nil, "--config", cfg, "--", helper, "-print", "GH_TOKEN")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	after, err := os.ReadDir(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("run must not create secret files, before=%d after=%d", len(before), len(after))
	}
}
