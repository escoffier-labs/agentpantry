# Changelog

## Unreleased

### Added
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
- Windows Chromium source support (needs validation on a Windows host): decrypts `v10` AES-256-GCM cookies using the DPAPI-unwrapped key from `Local State`. App-bound `v20` cookies (Chrome 127+) are skipped pending a later release. `install-service` on Windows prints a Scheduled Task registration command.

## v0.1.0

### Added
- Linux Chromium cookie sync (source) to a plaintext sidecar SQLite (sink).
- Transport-agnostic AES-256-GCM framed push with replay protection.
- Opt-in domain allow/deny policy.
- systemd user unit generation.
