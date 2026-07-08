# Changelog

## Unreleased

## v0.6.0 - 2026-07-08

### Added
- `agentpantry restore` can materialize cookies from a sidecar backup into
  Netscape `cookies.txt`, a Chromium profile cookie DB, or a running loopback
  Chrome DevTools target with `--to cdp=http://127.0.0.1:PORT`. CDP restore
  writes through `Storage.setCookies`, skips expired cookies with a safe count,
  and supports `--verify` readback with per-domain expected vs present counts
  and cookie names only. Cookie values never appear in any output, including
  CDP protocol errors.
- Source configs can set `peer = "none"` for local script-driven deployments:
  `doctor` skips peer reachability and reports the local topology as OK, while
  the long-running source loop rejects the sentinel and sink configs still fail
  validation.
- `agentpantry source --once` runs the startup sync path once over TCP or
  `--stdio`, persists source state, then exits 0 on success without starting the
  watcher or resync timer.
- Source-side KeePass secret reader: `keepass_path`/`keepass_keyfile`/`keepass_pass_file`/`keepass_tag`
  read tagged vault entries as named secrets, replacing the need for a plaintext `secrets_dir`.
  `agentpantry doctor` validates the unlock and reports the tagged entry count.
- `make install` builds a version-stamped binary into `$(PREFIX)/bin` (default
  `~/.local/bin`), and `scripts/cut-release.sh vX.Y.Z` cuts a release end to end:
  verify, tag, push, wait for the published release, install the live binary, and
  confirm the running version matches the tag.

### Security
- Bumped the Go toolchain to 1.25.12, resolving GO-2026-5856 in the `crypto/tls`
  standard library flagged by govulncheck.

## v0.5.0 - 2026-06-27

### Added
- `agentpantry inventory` reads a sidecar backup store and summarizes what it actually contains, including total cookies, persistent vs session-only counts, per-host counts, near-expiry auth cookies, `--store`, `--expiry-days`, and `--json` output for downstream tools and dashboards.
- The `source` role can warn on cookies nearing expiry: set `warn_expiry_days = N` to print a per-cookie stderr advisory (host, name, expiry date) on startup for any synced cookie expiring within N days. The sync stays read-only and never blocks; this only makes a looming re-auth visible. True auto-refresh is out of scope for read-only sync.
- The sink sidecar surface path is configurable with `sidecar_path`. Set it to give each profile its own store instead of juggling `XDG_CONFIG_HOME` to avoid identity collisions. Symlinks are still rejected.

### Fixed
- The CDP source now reads cookies with `Storage.getCookies` instead of `Network.getAllCookies`, so partitioned (CHIPS, `Partitioned` attribute) cookies are included. The old method silently dropped them, which lost a real `claude.ai` session cookie.
- The Linux Chromium disk reader no longer emits mis-decrypted garbage: a value that decrypts to non-printable bytes (a profile whose key lives in an unsupported keystore, e.g. an xdg portal) is excluded, and a single aggregated stderr warning suggests preferring a CDP source. Genuinely valid values are unaffected.

### Changed
- README now leads with a recorded terminal demo (`docs/assets/agentpantry-setup.svg`, reproducible from `agentpantry-setup.cast`) of the four-command agent-machine setup (init, keygen, doctor, status), and adds `CODE_OF_CONDUCT.md`.
- README adoption pass: a "What it does" overview, "Why not something else?" and "What agentpantry is not" sections, a website link and release badge in the header, an issue-template chooser config, and a no-PII checklist item in the PR template.

## v0.4.1 - 2026-06-16

### Added
- `agentpantry sink` warns at startup when the bind address exposes the sink beyond loopback, mirroring the existing `doctor` check at the moment it matters.
- `keygen` now tells the operator to delete the `psk.key.bak.<timestamp>` backup once a rotation is confirmed, since it holds retired key material.

### Changed
- go.mod now pins `toolchain go1.25.11`, so from-source installs (`go install ...@latest`) build with the patched standard library instead of whatever Go 1.25.x the machine happens to have. Release binaries were already built with 1.25.11.
- SECURITY.md's key rotation guidance now describes the `rotate-key` dual-key grace-window flow introduced in v0.4.0, with `keygen` documented as the stop-the-world fallback.
- CI's test jobs now run `scripts/verify` (plus `go test -race`) so the build/vet/test gate is defined in exactly one place.
- CI pins `govulncheck` and `gosec` to tagged versions instead of `@latest`, so the security and vuln gates are reproducible.
- `scripts/verify` now gofmt-gates the tree, and a new `.gitattributes` forces LF on source files so the gate is consistent across platforms (including the Windows CI job).

### Fixed
- The CDP cookie reader sets a read deadline, so a hung or crashed DevTools target fails the sync cycle instead of wedging it.

## v0.4.0 - 2026-06-09

### Added
- `agentpantry rotate-key` rotates the pre-shared key with a dual-key grace window: the sink preserves the old key as `psk.key.old`, accepts new connections under either key (new key tried first, warning logged on old-key sessions), and `rotate-key -finish` retires the old key. A running sink picks the rotation up per connection, no restart needed. `doctor` shows the in-progress window as a WARN row and `status` reports `rotation_in_progress`.

### Fixed
- The release workflow installs syft as a prebuilt binary; `go run syft@latest` broke the v0.3.0 tag build when syft's minimum Go version passed the pinned toolchain.

## v0.3.0 - 2026-06-09

### Added
- `agentpantry help` (and `-h`/`--help`) prints a command list with one-line descriptions; an unknown subcommand is now named in the error instead of only printing the usage line.
- Config loading now reports unknown or misplaced config keys: `doctor` shows them as WARN rows, and `source`, `sink`, and `status` print a stderr warning, so a typo like `alow` or a key placed under the wrong table no longer silently disables syncing.
- `hermes` adapter that writes an Agent Pantry-owned Hermes bundle directory with `cookies.txt`, `secrets/<name>`, and an `agentpantry.json` manifest for Hermes Agent launch wrappers or plugins.
- GitHub tag release workflow that builds platform archives, publishes checksums, generates a source SPDX SBOM, and requests artifact provenance attestations.
- Copyable example configs for Chromium, Firefox, CDP, Hermes Agent, GitHub CLI, OpenClaw, and SSH stdio transport.
- Contributor docs, issue templates, PR template, and Dependabot config for Go modules and GitHub Actions.

### Changed
- `agentpantry init` now writes a commented starter config that walks through each field (including a `[[browsers]]` skeleton and the domain allow list), and refuses to overwrite an existing config unless `-force` is passed.
- `agentpantry keygen` now backs up an existing key by default before replacing it, making pre-shared-key rotation safer.
- Private file writes (adapter outputs, secrets, state, config, key) are now atomic: staged in a same-directory 0600 temp file, fsynced, and renamed into place, so a crash mid-write can no longer truncate or destroy merged credential files, and a freshly written secret never inherits a pre-existing file's looser mode.
- Transport frame cap lowered from 64 MiB to 8 MiB, bounding the allocation an unauthenticated peer can force per frame.
- The TCP sink now serves connections concurrently (bounded at 32, surface writes serialized) and drops peers that fail to send an authenticated frame within 30 seconds, so one stalled or unauthenticated connection can no longer block all other sources.
- Key handling hardened: generation refuses symlinked key paths (before any backup copy is taken), loading checks permissions on the opened descriptor instead of a separate stat, rejects oversized key files instead of silently truncating them, and rejects non-regular files (a FIFO at the key path previously hung the process).
- `doctor` now delegates key validation to the same loader the runtime uses, so its verdict can no longer diverge from runtime behavior.
- Secret-directory sink writes now report real I/O failures (disk full, permissions) instead of silently counting them as skipped; unsafe names and planted symlinks are still skipped without failing the sync.
- The sidecar surface refuses a symlinked database path.

### Fixed
- `examples/source-chromium.toml` placed `secrets_dir` after the `[domains]` table header, so TOML parsed it as `domains.secrets_dir` and secret syncing silently never started for anyone who copied the example. The key now sits at the top level where it belongs (and the new unknown-key warnings would have flagged it).
- Windows: sink adapters and `doctor` no longer reject every output directory and key file due to Unix permission checks that are meaningless on Windows (Go reports synthesized 0777/0666 modes there). The full test suite now passes on Windows.

## v0.2.1 - 2026-06-03

### Changed
- BREAKING (transport): the connection now begins with a session-salt handshake and derives a per-session AES key (HKDF) from the pre-shared key, so a frame captured from one session can no longer be replayed into another. Source and sink must both run this version or newer.
- Release packaging now gates archives on tests, vet, gosec, and govulncheck before cross-building.
- CDP sources now require loopback HTTP and WebSocket endpoints; remote DevTools endpoints are rejected because they grant full browser control.
- Runtime PSK loading now rejects group/world-readable key files on Unix-like systems instead of only warning in `doctor`.
- Sink secret and adapter writes now tighten existing output file modes, refuse existing symlink targets, and reject shared-writable adapter output directories.
- Source secret reads now skip symlinks and non-regular files.

### Added
- `make gosec` and a CI security job, with documented suppressions only for intentional operator-selected paths, Chromium compatibility crypto, and bounded conversions.
- `agentpantry version` command with JSON output for release and support diagnostics.
- `make package` release packaging target that cross-builds Linux, macOS, and Windows archives with checksums.
- Windows sink real-Chrome re-encrypt surface: a Windows sink can write synced cookies into a real Chrome Cookies store as `v10` AES-256-GCM, encrypted with the sink's own DPAPI-unwrapped key. Best used against a not-running, pre-app-bound, or dedicated automation profile (an app-bound v127+ profile may prefer v20).
- GitHub Actions CI (go test -race, vet, Windows cross-build, golangci-lint, govulncheck) and a `.golangci.yml` config.
- SECURITY.md and a threat-model document (what the pre-shared key protects, operator responsibilities, and the plaintext-sidecar / no-forward-secrecy tradeoffs).
- Source auto-reconnect with capped exponential backoff (1s..30s): a sink restart or network blip recovers in-process, resending full state on reconnect.
- Periodic resync (`resync_seconds`, 0 = off) so a missed filesystem event does not cause drift; `kind=cdp` sources default to a 60s poll since they have no file to watch.
- Secret-name allow/deny policy (`[secret_names]`) mirroring the cookie domain policy.
- Fuzz targets for the wire payload, transport open path, Netscape parser, and the v10/v11 cookie decoders; a `Makefile` with `vuln` (govulncheck) and `fuzz` targets.
- `[[adapters]]` config block declaring per-CLI sink adapters layered on top of the `surfaces` list.
- Netscape `cookies.txt` cookie adapter (curl, wget, yt-dlp format) that seeds from its own file on start so a sink restart does not drop rows, and rewrites the whole file mode 0600 on each apply.
- `gh` hosts adapter that writes the GitHub token into the GitHub CLI `hosts.yml`, merge-only so other hosts survive and upsert-only so a transient missing secret never logs you out.
- `openclaw` auth-profiles adapter that merges provider profiles into an OpenClaw `auth-profiles.json` (object keyed by `<provider>:default`), merge-only and upsert-only, skipping any secret whose value is not valid profile JSON.
- Secrets bus: sync a secrets directory from source to sink (one file per secret), with strict secret-name sanitization on the sink.
- Real-Chrome re-encrypt surface: the sink can write synced cookies into an existing Chrome Cookies SQLite, re-encrypted with the sink's own keyring key. Schema is introspected so it tolerates Chrome version differences. Targets a not-running profile.
- `wire.Payload` envelope carrying cookies and secrets in one encrypted frame.
- `secrets_dir` config field and `chrome` / `secrets` sink surfaces.
- `doctor` command that reports specific setup failures (key, role, peer, surfaces) and, on a source, peer reachability, exiting non-zero when any check fails.
- Persisted last-sync state surfaced by `status`: the time of the last successful sync plus the cookie and secret counts in the last frame sent.
- `--stdio` transport mode on `source` and `sink` so the link can ride an SSH channel instead of a TCP listener.
- Firefox source reader: a `kind = "firefox"` browser entry reads plaintext cookies from a profile's `cookies.sqlite` (no keyring needed); a pure-Firefox source skips the keyring check in `doctor`.
- Windows Chromium source support: decrypts `v10` AES-256-GCM cookies using the DPAPI-unwrapped key from `Local State`. `install-service` on Windows prints a Scheduled Task registration command.
- App-bound Chrome (v127+, `v20` cookies) support via the DevTools Protocol: a `kind = "cdp"` browser exports cookies from a Chrome launched with `--remote-debugging-port` (Chrome decrypts its own cookies), with a `url` config field and a `doctor` reachability check.

## v0.1.0

### Added
- Linux Chromium cookie sync (source) to a plaintext sidecar SQLite (sink).
- Transport-agnostic AES-256-GCM framed push with replay protection.
- Opt-in domain allow/deny policy.
- systemd user unit generation.
