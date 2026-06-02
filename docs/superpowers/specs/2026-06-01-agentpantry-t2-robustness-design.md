# agentpantry T2 - design (robustness)

Status: approved (autonomous scope per goal directive), ready for implementation planning
Date: 2026-06-01
Builds on: P1-P7, T1. Hardening track 2 of 4.

## 1. Goal

Keep a source syncing reliably without manual restarts:

1. **Auto-reconnect with capped backoff** when the TCP link to the sink drops.
2. **Periodic full-resync ticker** so a missed fsnotify event does not cause
   silent drift.
3. **CDP interval polling** so a `kind=cdp` source (which has no file to watch)
   re-syncs on a timer.

## 2. Auto-reconnect (TCP source)

Today `cmdSource` dials once; if the connection drops, `Watch`'s send errors,
`Watch` returns, the process exits (and systemd restarts it). Add an in-process
reconnect loop so a transient sink restart or network blip recovers without
relying on the supervisor:

- `cmdSource` (non-stdio) runs a loop: dial -> `RecvSalt` handshake ->
  `NewSealer(key, salt)` -> set `syncer.Sealer`/`syncer.Out` -> `syncer.Reset()`
  -> `Watch(...)`. When `Watch` returns a non-context error (connection lost),
  close the conn, wait a backoff interval, and reconnect. Return cleanly on
  context cancellation.
- **Reset on reconnect:** the sink gets a fresh `Opener` (counter 0) and may have
  lost in-memory surface state, so on every (re)connection the source clears its
  previous snapshots (`Syncer.Reset()`) and the next sync resends the full
  current state. `Reset()` zeroes `prev` and `prevSecrets`.
- **Backoff:** `backoff(attempt) = min(1s * 2^attempt, 30s)` (1,2,4,8,16,30,30...).
  Reset `attempt` to 0 after a successful connection. The wait is
  context-cancellable (`select` on a timer vs `ctx.Done()`).
- `--stdio` is a one-shot pipe (no reconnect); its path is unchanged.

`Syncer` gains exported `Sealer`/`Out` reuse (already exported) plus a `Reset()`
method; the dial/handshake/backoff loop lives in `cmd/agentpantry/main.go`, with
a small unit-tested `backoff` helper (in `internal/source` or a tiny helper).

## 3. Periodic full-resync ticker

`Watch` gains a `resync time.Duration` parameter. When `resync > 0`, a ticker
fires `SyncOnce` on that interval in addition to debounced fsnotify events.
`SyncOnce` already diffs current state against `prev`, so a periodic call catches
any change a missed event would have dropped (no reset needed; it is a delta
sync). `resync == 0` disables the ticker (today's behavior).

Config: `ResyncSeconds int` (`toml:"resync_seconds"`, default 0 = off).

## 4. CDP interval polling

A `kind=cdp` source has no watched file, so it only syncs at startup unless a
timer drives it. Reuse the resync ticker: when any configured browser is `cdp`
and `ResyncSeconds == 0`, default the effective resync interval to 60s (logged),
so cdp sources poll. An explicit `resync_seconds` always wins.

## 5. Config

- `ResyncSeconds int` (`toml:"resync_seconds"`), additive, default 0.
- No other schema change. Reconnect is always on for the TCP source (no flag).

## 6. Testing

- `Syncer.Reset()` clears prior snapshots: after `Reset`, the next `SyncOnce`
  re-sends the full current state (a previously-synced cookie reappears as an
  upsert).
- `backoff(attempt)` returns the expected capped sequence.
- `Watch` with a short `resync` and NO fsnotify events triggers `SyncOnce` more
  than once (periodic resync fires) and returns on context cancel.
- The reconnect loop is validated by a live loopback smoke test (sink up; source
  connects and syncs; kill the sink; confirm the source retries with backoff;
  restart the sink; confirm the source reconnects and resyncs the full state).
- Existing `Watch` callers updated for the new `resync` parameter.

## 7. Out of scope

Concurrent multi-connection sink (the accept loop stays serial, handshake-
deadline-bounded from T1); sink-initiated reconnect; configurable backoff curve.
