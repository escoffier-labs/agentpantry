# Changelog

## Unreleased

### Added
- Secrets bus: sync a secrets directory from source to sink (one file per secret), with strict secret-name sanitization on the sink.
- Real-Chrome re-encrypt surface: the sink can write synced cookies into an existing Chrome Cookies SQLite, re-encrypted with the sink's own keyring key. Schema is introspected so it tolerates Chrome version differences. Targets a not-running profile.
- `wire.Payload` envelope carrying cookies and secrets in one encrypted frame.
- `secrets_dir` config field and `chrome` / `secrets` sink surfaces.

## v0.1.0

### Added
- Linux Chromium cookie sync (source) to a plaintext sidecar SQLite (sink).
- Transport-agnostic AES-256-GCM framed push with replay protection.
- Opt-in domain allow/deny policy.
- systemd user unit generation.
