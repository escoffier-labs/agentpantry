package test

// Release-script reliability regressions.
//
// Two findings, both about failures being masked as success:
//
//  1. Makefile `package` loop: a failed platform `go build` was masked by the
//     subsequent successful `tar`, so `make package` exited 0 with a broken or
//     stale archive in dist/. The loop must fail fast.
//  2. scripts/cut-release.sh step 4: when publication polling exhausted its
//     ~15m budget, the script warned and continued into `make install` and the
//     final "released" message with exit 0. It must exit nonzero before
//     install, with recovery guidance.
//
// These tests execute the REAL files (never the live repo state): a verbatim
// copy of the real Makefile runs via `make package` in an isolated temp dir
// with a fake `go` (and explicit VERSION/COMMIT/DATE/PLATFORMS overrides), and
// a verbatim copy of the real cut-release.sh runs in an isolated temp repo
// root with fake git/gh/sleep/make. No network, no tags, no live binary is
// touched.
//
// Why not extract the recipe text: each Make recipe line runs in its own
// shell, so concatenating the `package:` recipe lines into one script changes
// the semantics under test (a `cd dist` from one line would leak into the
// next). Running the real Makefile through `make` is the only faithful
// harness, and it also covers the `clean-dist test vet gosec vuln`
// prerequisites via the same fake `go`.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// execTimeout bounds every external harness invocation so a missing fake
// (e.g. a real `sleep 10` x 90 poll loop) can never hang the suite for ~15m.
const releaseExecTimeout = 2 * time.Minute

func releaseBash(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	for _, p := range []string{
		`C:\Program Files\Git\bin\bash.exe`,
		`C:\Program Files (x86)\Git\bin\bash.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatal("bash not available; cannot run shell regression harness")
	return ""
}

// releaseMake locates a make binary, including the Windows Git Bash layout
// where make is visible to bash but not to Go's PATH. It never skips: the
// repo policy prohibits weakening checks, so a missing tool is fatal.
func releaseMake(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("make"); err == nil {
		return p
	}
	if p, err := exec.LookPath("mingw32-make"); err == nil {
		return p
	}
	if p, err := exec.LookPath("gmake"); err == nil {
		return p
	}
	for _, p := range []string{
		`C:\Program Files\Git\mingw64\bin\make.exe`,
		`C:\Program Files\Git\usr\bin\make.exe`,
		`C:\Program Files (x86)\Git\mingw64\bin\make.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Last resort: ask Git Bash itself where make lives.
	bash, err := exec.LookPath("bash")
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, bash, "-c", "command -v make").Output()
		if err == nil {
			if p := strings.TrimSpace(string(out)); p != "" {
				return p
			}
		}
	}
	t.Fatal("make not available (checked PATH, mingw32-make, gmake, Git Bash layouts, and bash -c 'command -v make'); cannot run make package regression harness")
	return ""
}

// repoRootForRelease returns the working-tree root (parent of test/).
func repoRootForRelease(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "Makefile")); err != nil {
		t.Fatalf("cannot locate repo root from test dir: %v", err)
	}
	return root
}

func writeReleaseFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeReleaseExec(t *testing.T, path, content string) {
	t.Helper()
	writeReleaseFile(t, path, content)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// fakeGoForPackage only special-cases `go build` (fail the windows build on
// demand, otherwise materialize the -o output). Every other subcommand the
// package prerequisites use (`test`, `vet`, `run` for gosec/govulncheck)
// succeeds immediately so the fixture never needs the real toolchain.
const fakeGoForPackage = `#!/usr/bin/env bash
if [[ "${1:-}" == "build" ]]; then
  out=""
  prev=""
  for a in "$@"; do
    if [[ "$prev" == "-o" ]]; then out="$a"; fi
    prev="$a"
  done
  if [[ "${FAKE_GO_FAIL_WINDOWS:-0}" == "1" && "${GOOS:-}" == "windows" ]]; then
    echo "fake go: simulated build failure for $GOOS/$GOARCH" >&2
    exit 1
  fi
  if [[ -n "$out" ]]; then
    mkdir -p "$(dirname "$out")"
    printf 'fake-binary %s/%s\n' "${GOOS:-?}" "${GOARCH:-?}" > "$out"
  fi
  exit 0
fi
exit 0
`

// fakeGoHelperSource is a native-executable twin of fakeGoForPackage for
// Windows. Native make resolves `go` through CreateProcess, which ignores the
// extensionless bash fake and falls through to the real go.exe (then
// `go test ./...` fails in the fixture dir with "directory prefix . does
// not contain main module"). Compiling this stdlib-only helper to bin/go.exe
// gives the Windows resolver a real executable that shadows the toolchain,
// while Unix keeps using the shell script. Behavior mirrors
// fakeGoForPackage exactly, including the FAKE_GO_FAIL_WINDOWS gate and the
// asserted stderr text.
const fakeGoHelperSource = `package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "build" {
		out := ""
		prev := ""
		for _, a := range os.Args[1:] {
			if prev == "-o" {
				out = a
			}
			prev = a
		}
		if os.Getenv("FAKE_GO_FAIL_WINDOWS") == "1" && os.Getenv("GOOS") == "windows" {
			fmt.Fprintf(os.Stderr, "fake go: simulated build failure for %s/%s\n", os.Getenv("GOOS"), os.Getenv("GOARCH"))
			os.Exit(1)
		}
		if out != "" {
			_ = os.MkdirAll(filepath.Dir(out), 0o755)
			_ = os.WriteFile(out, []byte(fmt.Sprintf("fake-binary %s/%s\n", os.Getenv("GOOS"), os.Getenv("GOARCH"))), 0o755)
		}
		os.Exit(0)
	}
	os.Exit(0)
}
`

// ensureFakeGoExe compiles fakeGoHelperSource to bin/go.exe on Windows so
// native make selects the fake over the real toolchain. No-op elsewhere;
// no new dependency (stdlib only, built with the real toolchain).
func ensureFakeGoExe(t *testing.T, bin string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "fakego.go")
	writeReleaseFile(t, src, fakeGoHelperSource)
	out := filepath.Join(bin, "go.exe")
	ctx, cancel := context.WithTimeout(context.Background(), releaseExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, src)
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GO111MODULE=off")
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building native fake go.exe: %v\n%s", err, raw)
	}
}

// setupMakePackageFixture copies the REAL Makefile verbatim into an isolated
// temp dir with the fixture files the recipe needs plus a fake `go`, and
// returns the dir and the fake bin dir.
func setupMakePackageFixture(t *testing.T) (string, string) {
	t.Helper()
	root := repoRootForRelease(t)
	real, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeReleaseFile(t, filepath.Join(dir, "Makefile"), string(real))
	writeReleaseFile(t, filepath.Join(dir, "README.md"), "readme\n")
	writeReleaseFile(t, filepath.Join(dir, "CHANGELOG.md"), "changelog\n")
	writeReleaseFile(t, filepath.Join(dir, "LICENSE"), "license\n")
	bin := t.TempDir()
	writeReleaseExec(t, filepath.Join(bin, "go"), fakeGoForPackage)
	ensureFakeGoExe(t, bin)
	return dir, bin
}

// runMakePackage invokes the real `make package` in the fixture dir through
// a bash wrapper (so the Windows Git Bash `make` resolves even when it is
// not on Go's PATH), with explicit VERSION/COMMIT/DATE/PLATFORMS overrides
// so no git, date, or default platform list leaks in from the live repo.
func runMakePackage(t *testing.T, dir, bin, version, platforms, failWindows string) (string, int) {
	t.Helper()
	bash := releaseBash(t)
	makePath := releaseMake(t)
	ctx, cancel := context.WithTimeout(context.Background(), releaseExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "-c", `exec "$0" "$@"`, makePath,
		"package",
		"PLATFORMS="+platforms,
		"VERSION="+version,
		"COMMIT=testcommit",
		"DATE=2026-09-26T00:00:00Z",
	)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_GO_FAIL_WINDOWS="+failWindows,
	)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running make package: %v\n%s", err, out)
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("make package timed out after %v (missing fake or real toolchain leak?)\n%s", releaseExecTimeout, out)
	}
	_ = bash
	return string(out), code
}

// A failed platform build must fail the whole packaging run instead of being
// masked by a later successful tar.
func TestMakePackageFailsFastOnBuildError(t *testing.T) {
	dir, bin := setupMakePackageFixture(t)
	out, code := runMakePackage(t, dir, bin, "v0.0.0-test", "linux/amd64 windows/amd64", "1")
	if !strings.Contains(out, "fake go: simulated build failure for windows/amd64") {
		t.Fatalf("packaging did not reach the simulated build failure\n%s", out)
	}
	if code == 0 {
		t.Fatalf("make package exited 0 despite a failed platform build; failure was masked\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist", "agentpantry_v0.0.0-test_windows_amd64.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("tarball for the failed windows/amd64 build exists; broken archive was packaged")
	}
}

// The success path must keep working: all platform archives plus checksums.
func TestMakePackageSuccessBuildsAllTars(t *testing.T) {
	dir, bin := setupMakePackageFixture(t)
	out, code := runMakePackage(t, dir, bin, "v0.0.0-test", "linux/amd64 windows/amd64", "0")
	if code != 0 {
		t.Fatalf("make package failed on the success path (exit %d)\n%s", code, out)
	}
	for _, pkg := range []string{"agentpantry_v0.0.0-test_linux_amd64", "agentpantry_v0.0.0-test_windows_amd64"} {
		if _, err := os.Stat(filepath.Join(dir, "dist", pkg+".tar.gz")); err != nil {
			t.Fatalf("missing expected archive dist/%s.tar.gz: %v\n%s", pkg, err, out)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "dist", "checksums.txt")); err != nil {
		t.Fatalf("missing dist/checksums.txt: %v\n%s", err, out)
	}
}

const fakeGitScript = `#!/usr/bin/env bash
# Fake git for cut-release tests. Models: clean master, synced with
# origin/master, tag free, CHANGELOG names the version.
state="${FAKESTATE:?}"
case "$1 $2" in
  "rev-parse --abbrev-ref") echo "master"; exit 0 ;;
  "status --porcelain") exit 0 ;;
  "fetch origin") exit 0 ;;
  "rev-parse HEAD") echo "deadbeef"; exit 0 ;;
  "rev-parse origin/master") echo "deadbeef"; exit 0 ;;
  "rev-parse -q") exit 1 ;; # tag does not exist locally
  "ls-remote --exit-code") exit 1 ;; # tag does not exist on origin
  "tag -a") touch "$state/tagged"; exit 0 ;;
  "push origin") touch "$state/pushed"; exit 0 ;;
esac
echo "fake git: unexpected args: $*" >&2
exit 99
`

const fakeGhScript = `#!/usr/bin/env bash
# Fake gh. GH_MODE=always-fail never publishes; GH_MODE=flaky publishes on the 3rd poll.
state="${FAKESTATE:?}"
if [[ "${GH_MODE:?}" == "always-fail" ]]; then
  exit 1
fi
n=0
if [[ -f "$state/gh_polls" ]]; then n=$(cat "$state/gh_polls"); fi
n=$((n + 1))
echo "$n" > "$state/gh_polls"
if [[ "$n" -ge 3 ]]; then
  exit 0
fi
exit 1
`

const fakeMakeScript = `#!/usr/bin/env bash
echo "$*" >> "${FAKESTATE:?}/make_calls"
exit 0
`

const fakeVerifyScript = `#!/usr/bin/env bash
echo "$*" >> "${FAKESTATE:?}/verify_calls"
exit 0
`

// setupCutReleaseFixture builds an isolated repo root containing a verbatim
// copy of the real scripts/cut-release.sh plus fakes for every external
// command, and returns the root, state dir, and fake bin dir.
//
// The fake bin dir is returned explicitly (and mirrored in
// CUTRELEASE_FAKEBIN) so runCutRelease can re-assert its precedence INSIDE
// the running Bash. On Windows, a Bash launched from PowerShell reinserts
// Git paths ahead of the inherited PATH, so inheriting PATH alone lets the
// real git win ("fatal: not a git repository").
func setupCutReleaseFixture(t *testing.T, ghMode string) (string, string, string) {
	t.Helper()
	releaseBash(t) // fatal if no shell available
	root := repoRootForRelease(t)
	real, err := os.ReadFile(filepath.Join(root, "scripts", "cut-release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	tmpRoot := t.TempDir()
	writeReleaseFile(t, filepath.Join(tmpRoot, "scripts", "cut-release.sh"), string(real))
	writeReleaseExec(t, filepath.Join(tmpRoot, "scripts", "verify"), fakeVerifyScript)
	writeReleaseFile(t, filepath.Join(tmpRoot, "CHANGELOG.md"), "# Changelog\n\n## v9.9.9 - 2026-09-26\n\n- test fixture\n")
	state := t.TempDir()
	bin := t.TempDir()
	writeReleaseExec(t, filepath.Join(bin, "git"), fakeGitScript)
	writeReleaseExec(t, filepath.Join(bin, "gh"), fakeGhScript)
	writeReleaseExec(t, filepath.Join(bin, "sleep"), "#!/usr/bin/env bash\nexit 0\n")
	writeReleaseExec(t, filepath.Join(bin, "make"), fakeMakeScript)
	writeReleaseExec(t, filepath.Join(bin, "agentpantry"),
		"#!/usr/bin/env bash\nif [[ \"${1:-}\" == \"version\" ]]; then echo \"agentpantry v9.9.9 (deadbeef 2026-09-26T00:00:00Z)\"; else echo \"fake agentpantry\"; fi\n")
	t.Setenv("FAKESTATE", state)
	t.Setenv("GH_MODE", ghMode)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CUTRELEASE_FAKEBIN", bin)
	return tmpRoot, state, bin
}

func runCutRelease(t *testing.T, tmpRoot, fakeBin string) (string, int) {
	t.Helper()
	bash := releaseBash(t)
	if fakeBin == "" {
		fakeBin = os.Getenv("CUTRELEASE_FAKEBIN")
	}
	if fakeBin == "" {
		t.Fatal("runCutRelease: missing fake bin dir (setupCutReleaseFixture must pass it explicitly)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), releaseExecTimeout)
	defer cancel()
	// Re-assert fake-bin precedence INSIDE the already-running Bash, after
	// its startup path reorder. Convert the Windows-style fake-bin path via
	// cd/pwd so the export uses an MSYS path, then source (not re-exec) the
	// verbatim copied script so no second Bash startup can reorder PATH
	// again. BASH_SOURCE stays scripts/cut-release.sh so ROOT resolves to
	// the fixture root. The resolution gate is fail-closed: any fake not
	// resolving under the fake bin aborts before the real script runs.
	wrapper := `set -euo pipefail
fake_bin="$(cd -- "$1" && pwd -P)"
export PATH="$fake_bin:$PATH"
for cmd in git gh make sleep agentpantry; do
  p="$(command -v "$cmd" || true)"
  case "$p" in
    "$fake_bin"/*) ;;
    *) echo "error: fake $cmd not isolated (got '${p:-missing}', want under $fake_bin)" >&2; echo "PATH=$PATH" >&2; exit 99 ;;
  esac
done
shift
source scripts/cut-release.sh "$@"
`
	cmd := exec.CommandContext(ctx, bash, "-c", wrapper, "--", fakeBin, "v9.9.9")
	cmd.Dir = tmpRoot
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running cut-release.sh: %v\n%s", err, out)
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("cut-release.sh timed out after %v (a real sleep/poll loop leaked through?)\n%s", releaseExecTimeout, out)
	}
	return string(out), code
}

// When polling exhausts without the release publishing, the script must exit
// nonzero BEFORE make install, with recovery guidance - never install and
// never print the final "released" message.
func TestCutReleaseFailsBeforeInstallWhenUnpublished(t *testing.T) {
	tmpRoot, state, fakeBin := setupCutReleaseFixture(t, "always-fail")
	out, code := runCutRelease(t, tmpRoot, fakeBin)
	if code == 0 {
		t.Fatalf("cut-release.sh exited 0 after polling exhaustion; unpublished release was reported as released\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(state, "make_calls")); !os.IsNotExist(err) {
		t.Fatalf("make install ran despite the release publication being unconfirmed")
	}
	for _, want := range []string{"gh release view", "v9.9.9", "actions", "make install"} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("recovery guidance missing %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "released and the live binary is current") {
		t.Errorf("final released message printed despite unconfirmed publication:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(state, "tagged")); err != nil {
		t.Errorf("tag step did not run before the polling gate:\n%s", out)
	}
}

// The success path must keep working: published release proceeds to install
// and the final confirmation.
func TestCutReleaseSuccessInstallsAndConfirms(t *testing.T) {
	tmpRoot, state, fakeBin := setupCutReleaseFixture(t, "flaky")
	out, code := runCutRelease(t, tmpRoot, fakeBin)
	if code != 0 {
		t.Fatalf("cut-release.sh failed on the success path (exit %d)\n%s", code, out)
	}
	calls, err := os.ReadFile(filepath.Join(state, "make_calls"))
	if err != nil || !strings.Contains(string(calls), "install") {
		t.Fatalf("make install did not run on the success path (calls=%q, err=%v)\n%s", calls, err, out)
	}
	if !strings.Contains(out, "released and the live binary is current") {
		t.Fatalf("final confirmation missing on the success path:\n%s", out)
	}
}
