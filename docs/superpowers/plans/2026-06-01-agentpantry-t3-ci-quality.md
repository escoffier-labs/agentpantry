# agentpantry T3 Implementation Plan (CI / quality)

> REQUIRED SUB-SKILL: subagent-driven-development / executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** GitHub Actions CI, golangci-lint config, SECURITY.md + threat model, and `internal/dbcopy` dedup. Base branch `t3-ci-quality` off master.

---

### Task 1: internal/dbcopy + swap the three call sites

**Files:** Create `internal/dbcopy/dbcopy.go`, `internal/dbcopy/dbcopy_test.go`; Modify `internal/vault/linux_chromium.go`, `internal/ffvault/firefox.go`, `internal/vault/windows_chromium.go`

- [ ] **Step 1: Failing test** — `internal/dbcopy/dbcopy_test.go`:
```go
package dbcopy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestToTempCopiesAnd0600(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := ToTemp(src)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "hello" {
		t.Fatalf("copy mismatch: %q / %v", b, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("temp copy must be 0600, got %v", info.Mode().Perm())
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("cleanup must remove the temp file")
	}
}

func TestToTempMissingSourceErrors(t *testing.T) {
	if _, _, err := ToTemp(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing source must error")
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/dbcopy/`.

- [ ] **Step 3: Implement** — `internal/dbcopy/dbcopy.go`:
```go
// Package dbcopy copies a (possibly locked) SQLite file to a private temp copy.
package dbcopy

import (
	"io"
	"os"
)

// ToTemp copies src to a fresh 0600 temp file and returns its path plus a
// cleanup closure that removes it. Used to read browser cookie stores without
// contending with a running browser's lock.
func ToTemp(src string) (string, func(), error) {
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "agentpantry-db-*.sqlite")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}
```
(`os.CreateTemp` files are created `0600` by default.)

- [ ] **Step 4: Swap call sites** — in each reader, replace the local copy helper with `dbcopy.ToTemp` and delete the now-dead local function:
  - `internal/vault/linux_chromium.go`: replace `copyToTemp(v.CookiePath)` with `dbcopy.ToTemp(v.CookiePath)`; delete the package-local `copyToTemp`; add the `dbcopy` import. (If `io` becomes unused in that file, drop it.)
  - `internal/ffvault/firefox.go`: same swap; delete its local `copyToTemp`; fix imports.
  - `internal/vault/windows_chromium.go`: replace `copyToTempWin(v.CookiePath)` with `dbcopy.ToTemp(v.CookiePath)`; delete `copyToTempWin`; add the import; drop now-unused `io`.

- [ ] **Step 5: Build, vet, test, windows** — `go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...`. (The vault/ffvault reader tests still pass through the new helper.)

- [ ] **Step 6: Commit**
```bash
git add internal/dbcopy/ internal/vault/ internal/ffvault/
git commit -m "refactor: extract dbcopy.ToTemp shared by the cookie readers"
```

---

### Task 2: golangci-lint config + CI workflow

**Files:** Create `.golangci.yml`, `.github/workflows/ci.yml`

- [ ] **Step 1: golangci-lint config** — `.golangci.yml`:
```yaml
version: "2"
linters:
  enable:
    - govet
    - staticcheck
    - ineffassign
    - unused
    - misspell
    - gofmt
```
(errcheck deliberately not enabled; see the T3 spec.)

- [ ] **Step 2: Validate the lint set locally** — run `go vet ./...` (clean) and `go run honnef.co/go/tools/cmd/staticcheck@latest ./...`; fix any real finding so CI will be green. Record the clean result.

- [ ] **Step 3: CI workflow** — `.github/workflows/ci.yml`:
```yaml
name: ci
on:
  push:
    branches: [master]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - run: go build ./...
      - run: go vet ./...
      - run: go test -race ./...
      - run: GOOS=windows go build ./...
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - uses: golangci/golangci-lint-action@v6
        with:
          version: latest
  vuln:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

- [ ] **Step 4: Sanity** — confirm the workflow YAML parses (e.g. `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"`) and `go test -race ./...` passes locally.

- [ ] **Step 5: Commit**
```bash
git add .golangci.yml .github/workflows/ci.yml
git commit -m "ci: add github actions (test -race, vet, windows build, lint, govulncheck)"
```

---

### Task 3: SECURITY.md + threat model

**Files:** Create `SECURITY.md`, `docs/threat-model.md`; Modify `CHANGELOG.md`

- [ ] **Step 1: SECURITY.md** — supported versions (pre-1.0: latest `master`), how to report (a private contact / GitHub security advisory), and a one-paragraph posture summary. No em dashes, no private IPs/hostnames.

- [ ] **Step 2: docs/threat-model.md** — the Protected / Operator-responsibilities / NOT-protected sections from the T3 spec section 4. Cover: PSK channel guarantees, session-salt replay defense, domain opt-in + secret-name policy, 0600/0700 perms; operator must bind loopback, keep the PSK secret, treat the CDP debug port as sensitive; plaintext sidecar is cleartext at rest, no forward secrecy/key rotation, a compromised host sees sessions, `--stdio` relies on the channel. Use only `127.0.0.1`/`sink.example`.

- [ ] **Step 3: CHANGELOG** — Unreleased/Added: GitHub Actions CI, golangci-lint config, SECURITY.md + threat model, `internal/dbcopy` dedup.

- [ ] **Step 4: Final verify** — `go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...`.

- [ ] **Step 5: Commit**
```bash
git add SECURITY.md docs/threat-model.md CHANGELOG.md
git commit -m "docs: add security policy and threat model"
```

---

## Self-Review Notes

- **Spec coverage:** CI (spec 2) -> Task 2; lint config (spec 3) -> Task 2; SECURITY/threat-model (spec 4) -> Task 3; dbcopy (spec 5) -> Task 1.
- **Type consistency:** `dbcopy.ToTemp(src) (string, func(), error)` replaces three local helpers with identical signatures; call sites updated.
- **Lint greenness:** the chosen linter set is validated locally (vet + staticcheck) before the CI job is committed, so the first CI run is green; errcheck intentionally excluded and documented.
- **No placeholders.**
