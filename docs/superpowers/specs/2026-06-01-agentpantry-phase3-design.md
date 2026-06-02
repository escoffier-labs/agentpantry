# agentpantry Phase 3 - design (operability core)

Status: approved (autonomous scope per goal directive), ready for implementation planning
Date: 2026-06-01
Builds on: P1 (cookies->sidecar), P2 (secrets bus + chrome surface), and the roadmap
(docs/superpowers/specs/2026-06-01-agentpantry-roadmap-p3-p7.md).

## 1. Goal

Make agentpantry self-diagnosing and SSH-rideable by implementing the three CLI
capabilities the master design names but P1/P2 deferred:

1. `pantry doctor` - validate the local setup and report specific, actionable
   failures.
2. A real `pantry status` - report the last successful sync time and counts from
   a persisted state file, on top of the existing config summary.
3. `--stdio` transport mode on `source` and `sink` - run the link over stdin/
   stdout so it can ride an existing channel (for example
   `pantry source --stdio | ssh sink pantry sink --stdio`).

No new delivery surfaces, no new browser or platform support. Operability only.

## 2. Last-sync state

A small persisted state file records what the source last did, so `status` can
report real liveness instead of only static config.

- Location: `<config dir>/state.json` (honoring `XDG_CONFIG_HOME`), mode `0600`.
- Shape:
  ```go
  type State struct {
      LastSyncUnix int64 `json:"last_sync_unix"` // last successful SyncOnce cycle
      LastSentUnix int64 `json:"last_sent_unix"` // last cycle that actually sent a frame
      Cookies      int   `json:"cookies"`        // cookie upserts in the last sent frame
      Secrets      int   `json:"secrets"`         // secret upserts in the last sent frame
  }
  ```
- The source updates state after every successful `SyncOnce`: `LastSyncUnix`
  always advances (the cycle completed), and when a frame was sent
  `LastSentUnix` and the counts update too.
- Writing is best-effort: a state write failure logs a warning and does not fail
  the sync.
- Time is injected via a `Clock` interface (`Now() time.Time`) so tests are
  deterministic; the CLI supplies a real clock. (Wallclock calls must stay out of
  the pure logic.)

Decoupling: `source.Syncer` does not import the state package. Instead it exposes
an optional hook `AfterSync func(sent bool, cookies, secrets int)` invoked at the
end of a successful `SyncOnce`. The CLI wires that hook to update and save state.
Tests pass a recording hook.

## 3. doctor

`pantry doctor` runs a role-appropriate set of checks and prints each as
pass/warn/fail; it exits non-zero if any check is fatal.

- Check result model (in `internal/doctor`):
  ```go
  type Status int // OK, Warn, Fail
  type Check struct {
      Name   string
      Status Status
      Detail string // human-readable, never contains secret/cookie values
  }
  ```
- Pure checks (filesystem + config in, results out, no network):
  - **key**: PSK file exists, is `0600` (Fail if group/other bits set), decodes
    to 32 bytes.
  - **config**: role is source|sink; peer is non-empty and parses as host:port.
  - **source vaults** (role=source): each configured browser cookie store path
    exists and is readable; the keyring passphrase resolves (Warn if it falls
    back to `peanuts`).
  - **secrets dir** (if `secrets_dir` set): source = exists and readable; sink =
    parent exists and is writable.
  - **sink surfaces** (role=sink): each enabled surface can initialize - sidecar
    path writable; chrome target `Cookies` exists (Warn if a `SingletonLock`
    suggests the browser is running); secrets dir writable. Unknown surface name
    is Fail.
  - **bind** (role=sink): Warn if `peer` binds a non-loopback address (wider
    exposure).
- Network check (separate, bounded, role=source): **peer reachable** - dial
  `peer` with a short timeout (default 3s, `--timeout` flag) and report
  reachable/unreachable. No data is sent. This is the one check that touches the
  network; it is its own function so the pure checks test without it.
- `--config`, `--timeout`, and `--json` flags. Exit code: 0 if no Fail, 1 if any
  Fail (Warns do not fail).

## 4. --stdio transport

- `pantry source --stdio`: build the Syncer with `Out = os.Stdout` (no
  `net.Dial`), and run `Watch` as usual. Frames stream to stdout.
- `pantry sink --stdio`: no listener; construct one `Opener` and call
  `Serve(ctx, os.Stdin)` once, returning when stdin reaches EOF.
- The flag is mutually exclusive with the network path; when `--stdio` is set the
  `peer` field is ignored (doctor still validates it for the non-stdio case).
- This reuses the existing seams: `Syncer.Out io.Writer` and
  `Server.Serve(ctx, io.Reader)`; no transport changes.

## 5. Config

No schema change. `state.json` lives beside `config.toml` under the config dir.

## 6. Security

- `state.json` is `0600` and records only counts and timestamps, never cookie or
  secret values or names.
- doctor output never prints secret/cookie values; the keyring check reports only
  resolved/fallback, not the passphrase.
- The bind check actively warns when the sink is exposed beyond loopback.

## 7. Testing

- `state`: Save/Load round trip; `0600` perms; Clock injection makes timestamps
  deterministic; a missing state file loads as zero-value ("never synced").
- `source`: `AfterSync` hook fires once per successful `SyncOnce` with correct
  `sent`/counts (sent=false on a no-change cycle, true with counts on a change).
- `doctor`: each pure check against temp-dir fixtures - good key vs `0644` key
  (Fail), missing cookie store (Fail), non-loopback bind (Warn), unknown surface
  (Fail), healthy config (all OK). Peer-reachable check against a real listener
  on `127.0.0.1` (reachable) and a closed port (unreachable), with a short
  timeout.
- CLI/integration: `status` reports "never synced" before any sync and a real
  timestamp + counts after; a `source --stdio` writing to an `os.Pipe` whose
  read end feeds `sink --stdio` (`Serve` on the pipe) delivers a cookie to the
  sidecar end-to-end.

## 8. Out of scope

Metrics export, a daemon control socket, multi-peer, remote `doctor` (checking
the sink from the source beyond a reachability dial).
