# Changelog

## Unreleased

### Changed
- BREAKING (transport): the connection now begins with a session-salt handshake and derives a per-session AES key (HKDF) from the pre-shared key, so a frame captured from one session can no longer be replayed into another. Source and sink must both run this version or newer.

### Added
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
