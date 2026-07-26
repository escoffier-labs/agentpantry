# Repository Guidance

Go 1.25 single-module CLI (`agentpantry`) that syncs browser cookies and named secrets from a daily-driver machine (source role) to an agent machine (sink role) over an encrypted byte stream. Single binary, role chosen by subcommand. Default branch is `master`.

## Definition of Done
Before reporting ANY change complete, run this and confirm it passes:
```
./scripts/verify
```
It runs `make build`, `go vet ./...`, and `go test ./...` (includes `test/` integration tests).

Conditional gates not covered by the script:
- `make windows` if you touched anything near a `_windows.go` / `_other.go` pair (`cmd/agentpantry/`, `internal/wincrypto`)
- For security-relevant changes (parsers, framing, filesystem writes, cookie decoding): `make gosec`, `make vuln`, and the matching fuzz target, e.g. `make fuzz PKG=./internal/transport FUZZ=FuzzOpen`. Fuzz targets exist in `internal/{transport,surface,wire,vault,wincrypto,policy}`.

Report actual command results. If anything fails, quote the failure verbatim and do not claim success. CI additionally runs `go test -race ./...` on Linux and Windows, golangci-lint, govulncheck, and gosec; do not assume local green covers those.

## Code Map
- Entry point: `cmd/agentpantry/main.go`. All logic under `internal/`: `source`, `sink`, `transport` (handshake, AES-256-GCM framing, replay counters), `cookie`, `vault`/`cdpvault`/`ffvault`/`wincrypto` (per-browser decryption), `policy`, `surface` (sink outputs), `secret`/`secretsrc`, `config`, `doctor`, `keyfile`, `service`, `state`, `wire`.
- Cross-package integration tests: `test/`. Copyable configs: `examples/`. Threat model: `docs/threat-model.md`.
- `make package` is the full release gate (test, vet, gosec, vuln, multi-platform build into `dist/`).

## Rules
- Stating a command, flag, or API behavior? Verify it in the code or Makefile first. If you cannot find it, say so. Never invent it.
- Blocked by sandboxing, missing tool, auth, or network? Stop and report the exact blocker and the command that failed. Do not silently work around it or substitute a weaker check.
- A test, fuzz target, lint rule, or CI gate fails? Fix the code. Never weaken, skip, delete, or `t.Skip` it to get green. If you believe the test itself is wrong, say so and wait for confirmation.
- Touching `internal/transport/handshake.go`? Keep both salt-direction paths working: `--stdio` mode inverts who issues the handshake salt (sink sends it over TCP, source sends it over stdio). Add or update tests for both.
- Changing user-facing flow, surfaces, or doctor checks? Update the README claims to match, and bump `CHANGELOG.md` for releases.
- Staging files? Run `git status` first. `psk.key`, `config.toml`, the root `agentpantry` binary, `dist/`, `memory/`, and `.brigade/` are gitignored on purpose. Never commit keys, configs, or runtime state, and never use `git add -f` on ignored paths.
- Pushing? Never. Do not push unless the user explicitly asks, and never with `--no-verify` if a pre-push hook exists.

## Security Invariants (do not weaken)
This tool moves live authenticated browser sessions and real secrets. The following are load-bearing; do not loosen, bypass, or "simplify" any of them. Any intentional change here requires a matching update to `docs/threat-model.md` and explicit user sign-off:
- Session-salt handshake plus HKDF per-session keys. Never reuse a session key, never make the salt static, never skip the handshake in tests by patching it out of production paths.
- Strictly monotonic replay counter on the sink. Never accept equal or lower counters, never reset it for convenience.
- Deny-wins domain and secret-name policy. Never flip to allow-wins or add bypass flags.
- 0600 modes on key and secret files. Never broaden permissions to fix a test.
- The sink's dual-key rotation window (`rotate-key` until `-finish`) intentionally accepts the old key. Do not "fix" that without reading the rotation section of the README.
- Never run `agentpantry source` or `agentpantry sink` against real browser profiles or a real `~/.config/agentpantry` during development or tests unless the user explicitly asks in this session. Tests use temp dirs and fixtures; keep it that way.

## Gotchas
- Cookie decryption is per-platform: Linux Chromium uses the freedesktop Secret Service with a fixed "peanuts" fallback, Windows uses DPAPI from the profile's `Local State`, Firefox cookies are plaintext, and app-bound Chrome 127+ (`v20`) requires the `cdp` reader over a DevTools port instead of file reads.
- The Chromium cookie DB is copied while locked (`internal/dbcopy`) before reading. Never open the live store directly.
- SQLite is the pure-Go `modernc.org/sqlite` driver, no cgo. Keep it that way for cross-compilation.
- Windows-specific code is split into `*_windows.go` / `*_other.go` build-tag pairs. Keep both sides compiling (`make windows`).

## Memory Handoff
At the end of any substantial task, write a handoff note to `.claude/memory-handoffs/` using that directory's `TEMPLATE.md`. Record durable discoveries, gotchas, and decisions. Do not wait to be reminded.
