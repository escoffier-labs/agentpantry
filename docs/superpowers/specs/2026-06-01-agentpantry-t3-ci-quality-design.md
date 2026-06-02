# agentpantry T3 - design (CI / quality)

Status: approved (autonomous scope per goal directive), ready for implementation planning
Date: 2026-06-01
Builds on: P1-P7, T1, T2. Hardening track 3 of 4.

## 1. Goal

1. **CI**: a GitHub Actions workflow gating every push/PR with the checks I run
   manually (test -race, vet, Windows cross-build, lint, govulncheck).
2. **SECURITY.md + threat-model doc**: state what the PSK does and does not
   protect, the loopback-bind guidance, and the plaintext-sidecar tradeoff.
3. **Dedup**: extract the triplicated `copyToTemp` into `internal/dbcopy`.

## 2. CI workflow (`.github/workflows/ci.yml`)

Triggers: `push` and `pull_request`. `ubuntu-latest`, `actions/setup-go` pinned
to the module's Go (1.25.x). Jobs:

- **test**: `go build ./...`, `go vet ./...`, `go test -race ./...`,
  `GOOS=windows go build ./...`.
- **lint**: `golangci-lint` via `golangci/golangci-lint-action`.
- **vuln**: `govulncheck ./...` via `golang.org/x/vuln/cmd/govulncheck`.

Pin action versions. Keep it a single workflow file with three jobs.

## 3. golangci-lint config (`.golangci.yml`)

Enable a curated, green-on-current-code set: `govet`, `staticcheck`,
`ineffassign`, `unused`, `misspell`, `gofmt`. Deliberately NOT enabling
`errcheck` yet: the codebase intentionally ignores a few `conn.Close()` /
`SetDeadline` returns (consistent with idiomatic network code), and turning on
errcheck now would be churn without value; documented as a future tightening.
Verify locally (`go vet`, `staticcheck`) that the chosen set is clean before
committing, fixing any real finding.

## 4. SECURITY.md + docs/threat-model.md

- `SECURITY.md`: supported versions, how to report a vulnerability (private
  contact), and a one-paragraph posture summary.
- `docs/threat-model.md`:
  - **Protected**: channel confidentiality, integrity, and authentication via the
    pre-shared key (AES-256-GCM); per-session salt + HKDF defeats cross-session
    replay; in-session monotonic-counter replay protection; domain policy is
    opt-in per cookie domain; secret-name allow/deny; file perms 0600/0700.
  - **Operator responsibilities**: bind the sink to loopback (or a trusted VPN);
    keep the PSK secret (`0600`); treat a CDP `--remote-debugging-port` as
    sensitive (loopback only).
  - **Explicitly NOT protected / tradeoffs**: the plaintext sidecar is cleartext
    at rest on the sink (treat the sink as a secret store); a compromised sink or
    source host sees the synced sessions; no forward secrecy / key rotation
    (PSK is long-lived); `--stdio` replay protection relies on the underlying
    channel (e.g. SSH); not a password manager.

## 5. internal/dbcopy

`copyToTemp` exists three times (`internal/vault/linux_chromium.go`,
`internal/ffvault/firefox.go`, `internal/vault/windows_chromium.go` as
`copyToTempWin`). Extract one platform-neutral helper:

- `internal/dbcopy/dbcopy.go`: `func ToTemp(src string) (path string, cleanup func(), error)`
  copies `src` to an `os.CreateTemp` file (mode `0600`), returns the temp path
  and a cleanup closure; on copy failure it removes the temp file and returns the
  error.
- Replace all three call sites with `dbcopy.ToTemp`. Remove the now-dead local
  copies. (The Windows file is build-tagged; `dbcopy` is platform-neutral so it
  compiles everywhere.)

## 6. Testing

- `dbcopy.ToTemp`: copies content faithfully, the temp file is `0600`, cleanup
  removes it, a missing source errors.
- The three readers continue to pass their existing tests after the swap.
- `go build ./...`, `go vet ./...`, `go test -race ./...`, `GOOS=windows go build`
  all green locally; `staticcheck ./...` clean (validates the lint set).
- govulncheck clean (already true).

## 7. Out of scope

errcheck enablement (documented future tightening); release automation
(goreleaser); coverage gating.
