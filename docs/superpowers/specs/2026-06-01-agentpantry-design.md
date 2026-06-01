# agentpantry - design

Status: approved (brainstorming), ready for implementation planning
Date: 2026-06-01

## 1. Purpose

agentpantry continuously mirrors authenticated browser sessions and secrets
from a daily-driver machine (the source) to an agent-runtime machine (the
sink), encrypted over any reachable network path, so agent runtimes (OpenClaw,
Hermes, Claude Code, or any other) wake up already authenticated without
re-logging-in.

It is a cross-platform, transport-agnostic reimagining of the macOS-only
`agentcookie`. Linux source and Linux sink ship first. Windows source and sink
come next.

Non-goals for the project:

- No cloud broker or hosted intermediary. Peer to peer only.
- No browser automation, no scraping, no credential harvesting from machines
  the operator does not own. This is an operator tool for syncing your own
  sessions between your own machines.
- Not a password manager. Secrets pass through; they are not stored as a vault
  of record.

## 2. Topology and components

A single Go binary, `agentpantry` (installed alias `pantry`). Role is selected
by subcommand.

- `pantry source` - watches cookie stores and the secrets directory, decrypts,
  diffs against the last snapshot, encrypts, and pushes deltas to the sink.
- `pantry sink` - listens for encrypted frames, decrypts, and fans the payload
  out to the enabled delivery surfaces.
- `pantry init` - scaffold a config file for a chosen role.
- `pantry keygen` - generate the pre-shared transport key.
- `pantry status` - report role, peer reachability, last sync time, surfaces.
- `pantry doctor` - validate config, key permissions, vault access, peer auth.
- `pantry install-service` - write the OS service unit for the current role.

Data flow:

```
Chrome writes -> fsnotify -> [source] read + decrypt -> normalize -> domain policy filter
                                                                             |
                                          AES-256-GCM envelope over TCP      v
[agent reads] <- delivery surfaces <- [sink] decrypt <----------------- push frame
```

The source is active (it watches and pushes). The sink is passive (it listens
and writes). No bidirectional sync in any planned phase.

## 3. Cookie crypto abstraction (the portable core)

All per-OS and per-browser detail lives behind a `BrowserVault` interface so the
sync engine, diff logic, and transport never learn platform specifics.

Interface responsibilities:

- Locate the browser profile(s) and cookie store path.
- Read the cookie store safely (copy the SQLite file to a temp path first to
  avoid lock contention with a running browser).
- Resolve the encryption key for the profile.
- Decrypt an encrypted cookie value to plaintext (source side).
- Encrypt a plaintext cookie value for this machine's store (sink side, real
  Chrome surface only).

Implementations:

- **Linux / Chromium family** (Chrome, Chromium, Brave, Edge): cookie store is
  `Cookies` SQLite. Encrypted values carry a `v10` or `v11` prefix and use
  AES-128-CBC. The key derives via PBKDF2 from a passphrase fetched from the
  Secret Service over D-Bus (the "Chrome Safe Storage" entry), with the
  hardcoded `peanuts` passphrase as the documented fallback when no keyring is
  present.
- **Firefox** (phase 4): cookie store is `cookies.sqlite` and values are stored
  in plaintext. No decrypt step; this is a distinct reader, not a vault.
- **Windows / Chromium family** (phase 5): encrypted values are AES-256-GCM with
  a DPAPI-wrapped key stored in `Local State`. Chrome v127+ adds app-bound
  encryption, which binds the key to the browser process and requires going
  through the elevation service. App-bound encryption is an explicit research
  spike, called out as the highest-risk item, and may constrain which Chrome
  versions phase 5 supports.

A normalized in-memory cookie model (host, name, value, path, expiry, flags) is
the only thing that crosses the vault boundary. The engine operates on the
normalized model exclusively.

## 4. Transport

Transport-agnostic by design. The tool does its own confidentiality and
authentication and runs over whatever network path is reachable (Tailscale,
Twingate, LAN, or an SSH tunnel).

- Wire format: length-prefixed frames, each frame an AES-256-GCM ciphertext.
- Authentication and confidentiality: a pre-shared key produced by
  `pantry keygen`, stored in a file with `0600` permissions. Both ends load the
  same key.
- Replay protection: per-frame random nonce plus a monotonic counter; the sink
  rejects frames at or below the last seen counter.
- Connection: the source dials the sink at a configured `host:port`. The sink
  binds a configured address (loopback by default; operator opts into a wider
  bind).
- `--stdio` mode: source and sink can speak over stdin/stdout so the whole link
  can ride an existing channel, for example `ssh sink pantry sink --stdio`.

No TLS certificate management in v1. The PSK provides mutual authentication.
mTLS may be added later as an optional transport but is out of scope for the
planned phases.

## 5. Delivery surfaces (sink)

The sink writes the received session into one or more surfaces. Surfaces are
layered: a safe always-on baseline plus opt-in surfaces for richer cases.

- **Plaintext sidecar SQLite** (always on): a cookies database with values in
  cleartext, written `0600`. Requires no sink keyring. This is the baseline that
  always works and is the recommended target for agent tooling that can be
  pointed at a cookie file.
- **Real Chrome store re-encrypt** (opt-in): re-encrypt each cookie with the
  sink machine's own `BrowserVault` key and write into the sink's `Cookies`
  SQLite so unmodified Chrome and agents that drive real Chrome just work.
  Documented constraint: writing a live Chrome profile is fragile because Chrome
  caches cookies in memory and locks the database. This surface targets a
  not-running profile or a dedicated automation profile; `doctor` warns when the
  target profile's browser is running.
- **Secrets bus** (phase 2): bearer tokens, API keys, and auth blobs are carried
  separately from cookies and written to a secrets directory or the sink keyring.
- **Per-CLI adapters** (phase 3): write session material in the exact shape
  specific tools expect, for example Netscape `cookies.txt`, the `gh` hosts
  file, and OpenClaw `auth-profiles.json`. Each adapter is a small, independently
  testable writer.

## 6. Security model

- AES-256-GCM PSK transport; cookie and secret values are never written to logs
  at any level.
- **Domain policy**: an allowlist/denylist controls which cookie domains sync.
  The default is opt-in per domain (nothing syncs until a domain is allowed) so
  banking, email, and other sensitive sessions stay put unless the operator
  explicitly opts them in.
- File permissions: the PSK, the plaintext sidecar, secrets files, and adapter
  outputs are all `0600`. Directories are `0700`.
- Secrets never land on disk in cleartext unless a surface that requires it is
  explicitly enabled.
- `doctor` checks key permissions, bind exposure, and whether the real-Chrome
  target profile is in use.

## 7. Config

`~/.config/agentpantry/config.toml` (honoring `XDG_CONFIG_HOME`). Fields:

- `role` - `source` or `sink`.
- `peer` - `host:port` for the source to dial, or bind address for the sink.
- `key_path` - path to the PSK file.
- `surfaces` - which delivery surfaces are enabled (sink only).
- `browsers` - list of browser + profile paths to watch (source) or write
  (sink).
- `domains` - allowlist and denylist for cookie domains.

`pantry init --role source|sink` writes a starter config with safe defaults
(loopback bind, empty domain allowlist, sidecar surface only).

## 8. Service install

`pantry install-service` writes the OS-appropriate service unit for the current
role and prints the enable/start commands without running them (manual enable,
matching the operator-system convention of keeping activation decisions
explicit).

- Linux (now): a systemd **user** unit under
  `~/.config/systemd/user/agentpantry-<role>.service`.
- Windows (phase 5): a Windows service definition.

## 9. Phasing

- **Phase 1 (v0.1)**: Linux Chromium cookie source to sink. Plaintext sidecar
  surface. Transport-agnostic AES-GCM push with replay protection. systemd user
  unit. Domain policy. End-to-end loopback works and is covered by an
  integration test.
- **Phase 2**: real-Chrome re-encrypt surface and the secrets bus.
- **Phase 3**: per-CLI adapters (Netscape `cookies.txt`, `gh`, OpenClaw
  `auth-profiles.json`).
- **Phase 4**: Firefox reader (plaintext `cookies.sqlite`).
- **Phase 5**: Windows source and sink (DPAPI plus the app-bound-encryption
  research spike).

Each phase is independently shippable and leaves the tool in a working state.

## 10. Testing

Test-driven throughout.

- Unit: cookie decrypt against known `v10`/`v11` fixtures; AES-256-GCM transport
  round-trip including replay rejection; snapshot diff logic; domain policy
  filtering; each surface writer against a temp SQLite or temp dir.
- Integration: a source and a sink wired over loopback, verifying a cookie
  written on the source appears in the sink's sidecar after one sync cycle, and
  that denied domains do not appear.
- Fixtures: checked-in encrypted-cookie samples and a fake Secret Service double
  so vault tests do not need a live keyring.

## 11. Relationship to brigade

agentpantry is a standalone repo with its own release cadence. brigade may later
gain a thin wrapper or doctor check that references an installed agentpantry, but
no brigade code is required for agentpantry to function, and agentpantry pulls in
no brigade dependency.
