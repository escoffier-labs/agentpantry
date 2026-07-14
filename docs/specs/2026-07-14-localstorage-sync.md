# Spec: localStorage capture and restore (Slice 2)

Date: 2026-07-14
Status: draft (spec only; no code yet)
Scope: one feature across source, wire, sink, sidecar, and restore. Add browser
`localStorage` to the sync so a Playwright/Puppeteer `storageState` (Slice 1) and
a live automation Chrome wake up with the full session, not just cookies.
Follows: `feat/storagestate-playwright` (Slice 1, the cookies-only storageState
surface). Precedes: Slice 3 (browser launch helper + anti-bot doctor).

## Context

Slice 1 shipped a `storagestate` surface that writes a Playwright `storageState`
file, but it only carries cookies and always writes `"origins": []`. Modern auth
on the sites this pivot targets (job boards, SaaS) increasingly keeps the
load-bearing session material, JWTs, refresh tokens, device IDs, in
`localStorage`, not cookies. A cookies-only restore leaves those sessions
signed out even though the cookie jar looks complete. Slice 2 captures
`localStorage` on the source and carries it end to end so the restored session is
whole.

`localStorage` lives in LevelDB on disk (`Local Storage/leveldb`), which is not
safely readable without cgo and while the browser holds the lock. So capture is
**CDP-source only**, which fits the live-Chrome pivot: the source is a running
Chrome we ask over the DevTools Protocol, exactly as the `kind = "cdp"` cookie
reader already does (`internal/cdpvault`).

`sessionStorage`, IndexedDB, service worker state, and cache data remain out of
scope (ephemeral or too large to mirror as diffs).

## Goal / success criteria

1. A `kind = "cdp"` source with capture enabled mirrors `localStorage` for
   policy-permitted origins into the same AES-256-GCM frame as cookies/secrets.
2. The `storagestate` sink surface and the sidecar persist `localStorage`, so a
   `restore --to storagestate=<path>` produces a Playwright file with real
   `origins[].localStorage`, and `browser.newContext({ storageState })` restores
   the whole session.
3. Diff-based like cookies/secrets: only changed items move; an item removed at
   the source propagates as a delete; a transient capture failure never wipes
   already-synced `localStorage` on the sink.
4. Deny-wins domain policy applies to origins exactly as it does to cookie hosts.
5. Values (tokens) are never logged, on either end, including in CDP error text.
6. Additive and backward compatible: an old sink ignores the new frame field; a
   new sink treats an old frame as empty `localStorage`. No framing, handshake,
   replay-counter, or HKDF change.
7. Non-intrusive capture: reading `localStorage` never navigates or reloads the
   source browser (navigation is both destructive to the user's tabs and visible
   to anti-bot fingerprinting).

## Approach (decided)

Model `localStorage` as a third diff that rides the existing envelope, mirroring
the cookie and secret pipelines exactly (`internal/cookie`, `internal/secret`).
The three pipelines are already structural twins (`Item`/`Snapshot`/`DiffFrom`/
`Diff{Upserts,Deletes}`), so this adds a parallel package, one wire field, one
source reader interface, and one sink surface interface, with no change to the
security-critical framing.

Capture reads `localStorage` from origins **already open in the source browser's
tabs**, via `Runtime.evaluate` per page target. Rejected alternatives:

- **Navigate a temp page to every cookie origin to read its storage** (how
  Playwright's own `storageState` collector works): rejected. It reloads/creates
  pages in the user's live browser and is exactly the automated-navigation signal
  anti-bot systems watch for. agentpantry reads the browser as-is.
- **Read LevelDB from disk**: rejected. Needs cgo or a fragile pure-Go LevelDB
  reader, and the store is locked by the running browser. This is why capture is
  CDP-only.
- **`DOMStorage` domain enumeration**: no CDP method lists all origins that hold
  storage without a tracked frame, so it cannot enumerate origins you are not
  currently viewing. Used only for the (stretch) live-restore write path.

## Design

### New package `internal/webstorage`

Twin of `internal/cookie` and `internal/secret`. `localStorage` only.

```go
package webstorage

// Item is one localStorage entry for one origin.
type Item struct {
    Origin string `json:"origin"` // scheme://host[:port], e.g. https://github.com
    Key    string `json:"key"`
    Value  string `json:"value"`
}

// Key identifies a slot by origin + key.
func Key(i Item) string { return i.Origin + "\x00" + i.Key }

type Snapshot struct{ Items map[string]Item }
func NewSnapshot(items []Item) Snapshot { /* keyed by Key */ }

type Diff struct {
    Upserts []Item   `json:"upserts"`
    Deletes []string `json:"deletes"` // Key() values
}
func (d Diff) IsEmpty() bool { return len(d.Upserts)==0 && len(d.Deletes)==0 }
func (s Snapshot) DiffFrom(prev Snapshot) Diff { /* identical shape to cookie.DiffFrom */ }
```

`OriginHost(origin string) (string, bool)` parses the host from an origin URL for
policy checks; a non-http(s) origin (e.g. `chrome-extension://`) returns
`false` and is dropped before it can be synced.

### Wire (`internal/wire/wire.go`)

Add one field. This is the only change to the frame body; the seal, replay
counter, salt handshake, and HKDF key are untouched.

```go
type Payload struct {
    Cookies cookie.Diff     `json:"cookies"`
    Secrets secret.Diff     `json:"secrets"`
    Storage webstorage.Diff `json:"storage"` // NEW; omitted-field on old frames = empty
}
func (p Payload) IsEmpty() bool {
    return p.Cookies.IsEmpty() && p.Secrets.IsEmpty() && p.Storage.IsEmpty()
}
```

Compatibility: `encoding/json` drops the unknown `"storage"` field for an old
sink, and defaults it to a zero (empty) `Diff` for a new sink reading an old
frame. No version negotiation needed.

### Source capture (`internal/cdpvault`)

Add a `StorageReader` capability to the CDP reader, invoked only when the browser
entry opts in.

```go
// in internal/source
type StorageReader interface { ReadStorage(ctx context.Context) ([]webstorage.Item, error) }
```

CDP implementation (`internal/cdpvault`), non-intrusive:

1. `Target.getTargets`; keep `type == "page"` targets on loopback (reuse
   `ValidateLoopbackURL`).
2. For each page target, over its existing DevTools websocket:
   `Runtime.evaluate` with expression
   `JSON.stringify({o: location.origin, e: Object.entries(localStorage)})`,
   `returnByValue: true`. No navigation, no page creation.
3. Parse `{o, e:[[key,value],...]}`; emit `Item{Origin:o, Key, Value}` for each
   pair. A target whose origin is `about:blank`/non-http(s) is skipped.
4. Enforce caps (below); dedupe by `Key` (last write wins, deterministic order).

Frame/iframe localStorage is out of scope for v1 (top document per tab only);
noted as a limitation. This can extend to `Page.getFrameTree` + per-frame
execution contexts later without a wire change.

Source wiring (`internal/source/source.go`), parallel to secrets:

- `Syncer.Storage []StorageReader`, `prevStorage webstorage.Snapshot`,
  `Reset()` clears it (so a reconnect resends full storage state, matching
  cookies).
- In `SyncOnce`: read storage, keep only items whose `OriginHost` is
  `Policy.Permit`-ed, snapshot, `DiffFrom(prevStorage)`, set `prevStorage`.
- Transient failure handling mirrors secrets: if a capture read errors, log
  `localStorage source unavailable this cycle, leaving synced storage untouched`
  and send an empty storage diff (never a delete-all). Cookies/secrets still
  proceed.
- `afterSync` gains a storage count for `status`.

### Caps (DoS / frame-size guard)

`localStorage` is attacker-influenceable and can be megabytes. Bound it, and
**log what was dropped** (never silently truncate):

- Per-item value cap (e.g. 256 KiB) and per-origin item-count cap.
- Total captured-bytes cap per cycle.
- On exceed: skip the offending item/origin, increment a counter, print a single
  aggregated stderr line with counts only (no keys/values).

Exact limits decided during implementation; defaults chosen to comfortably fit
real auth material while refusing a pathological store.

### Sink routing (`internal/sink/sink.go`)

Add a third surface interface and route the third diff, mirroring cookies:

```go
type StorageSurface interface { ApplyStorage(d webstorage.Diff) error }
// Server gains StorageSurfaces []StorageSurface
// apply(): if !p.Storage.IsEmpty() { for each StorageSurface: ApplyStorage(p.Storage) }
```

Surfaces implementing `ApplyStorage`:

- **`storagestate` file surface (`internal/surface/storagestate.go`)**: the
  primary deliverable. Fold items into the `origins` array it already preserves:
  group upserts by origin into `{origin, localStorage:[{name,value}]}`; apply
  deletes by origin+key; drop an origin whose list becomes empty. Slice 1 already
  round-trips `origins` verbatim, so this only replaces "preserve" with "merge".
  Still atomic 0600; values never logged.
- **`sidecar` surface (`internal/surface/sidecar.go`)**: add a `localstorage`
  table (`origin, key, value`, PK `(origin,key)`), written in the same
  transaction style as cookies. This is what makes capture-once-materialize work:
  `restore` and `inventory` read `localStorage` from the sidecar.
- **live CDP surface (stretch, best-effort)**: `DOMStorage.setDOMStorageItem`
  against origins that already have a tracked frame in the target browser; skip
  and warn (names/counts only) for origins with no frame. Full seeding of an
  arbitrary origin needs a navigation, which belongs to the Slice 3 launch
  helper, not here. May be deferred to Slice 3 entirely.

### Restore (`cmd/agentpantry/main.go`)

`restore --to storagestate=<path>` reads `localStorage` from the sidecar
(alongside cookies), applies the same origin/domain narrowing, and writes real
`origins[].localStorage`. `--domains` filters origins by host suffix just like
cookies. Values never printed; the dry-run/summary reports origin and item counts
only. `netscape`, `chromium`, and `cdp` targets ignore `localStorage`
(cookies-only formats); `cdp` may gain best-effort writes with the stretch
surface.

### inventory / status / doctor

- `inventory`: add a `localStorage: N items across M origins` line and `--json`
  fields. No values.
- `status`: last-sync line adds a `localStorage` count.
- `doctor`: on a source, if a browser entry sets `capture_localstorage = true`,
  confirm `kind == "cdp"` (FAIL otherwise, since disk/Firefox cannot capture it)
  and that the CDP endpoint is reachable (reuses the existing dial). On a sink,
  no new check (the storageState/sidecar surfaces already validate paths).

### Config

Opt-in, off by default (this captures more sensitive data than cookies, so it
should be a deliberate choice; domain policy still gates it):

```toml
[[browsers]]
kind = "cdp"
url  = "http://127.0.0.1:9222"
capture_localstorage = true   # NEW; valid only for kind = "cdp"
```

New field `BrowserRef.CaptureLocalStorage bool` (`toml:"capture_localstorage"`).
No new sink config: the `storagestate` adapter and `sidecar` surface start
receiving storage automatically once the source sends it.

## Security review (load-bearing; requires threat-model update + sign-off)

Per `AGENTS.md`, the security invariants are load-bearing. This spec:

- **Does not touch** the salt handshake, per-session HKDF key, strictly monotonic
  replay counter, deny-wins policy, or 0600 file modes. `localStorage` rides the
  same sealed frame; it is one more JSON field inside the already-encrypted body.
- **Treats values as secret**: `localStorage` values are tokens. They live only in
  memory, the encrypted frame, the 0600 sidecar, and the 0600 storageState file,
  never in logs or error strings (CDP error handling copies the cookie path:
  report codes/counts, withhold browser messages).
- **Applies deny-wins domain policy to origins** before anything is captured or
  sent; a non-http(s) origin is dropped.
- **Bounds untrusted input**: per-item, per-origin, and per-cycle caps with logged
  (count-only) drops; a new fuzz target over the CDP `localStorage` JSON parser
  and the storageState `origins` parser (`make fuzz`).
- **Requires** a matching update to `docs/threat-model.md` ("What is protected"
  now includes `localStorage`; "Not protected" still lists sessionStorage/
  IndexedDB) and explicit user sign-off before implementation, because it widens
  what the tool exfiltrates from the source browser.

Threat delta to call out for sign-off: enabling capture means a broader class of
in-browser secrets leaves the source. Mitigations: opt-in per browser, off by
default, gated by the same allowlist, and CDP-only (so it cannot silently start
reading a disk profile).

## Limitations (to document in README)

| Limit | Behavior |
| --- | --- |
| Capture is CDP-only | Disk Chromium/Firefox sources cannot read `localStorage`; only a `kind = "cdp"` source with `capture_localstorage = true` does. |
| Open tabs only (v1) | Only origins currently loaded in a top-level tab are captured; a site you are not viewing is not read. Open it once to seed. |
| iframes (v1) | Only the top document per tab; cross-origin iframe `localStorage` is out of scope for v1. |
| sessionStorage etc. | `sessionStorage`, IndexedDB, service workers, cache are out of scope. |
| Live CDP restore | Writing `localStorage` into a running browser is best-effort for origins with an existing frame; arbitrary-origin seeding needs the Slice 3 launch helper. The storageState file path has no such limit. |
| Size caps | Oversized items/origins are skipped and counted (never silently truncated). |

## Phased implementation plan

1. **Model + wire** (`internal/webstorage`, `wire.Payload` field). Pure, fully
   unit-tested. No behavior change (empty diffs). Confirms backward compat with a
   round-trip test old<->new payload.
2. **Source capture** (`internal/cdpvault` `ReadStorage`, `source.Syncer`
   wiring, config field, policy filter, caps, unavailable handling). Tested with
   the existing fake-CDP websocket harness in `test/`.
3. **Sink persistence + restore** (`sink.StorageSurface`, `storagestate`
   `ApplyStorage`, `sidecar` `localstorage` table, `restore` reads it,
   `inventory`/`status` counts). End-to-end CLI test: capture -> sidecar ->
   `restore --to storagestate=` -> assert real `origins[].localStorage` and no
   value leak.
4. **Stretch**: live CDP `ApplyStorage` (best-effort, framed origins only).
5. **Docs + gates**: README (surfaces, restore, limitations), CHANGELOG,
   `docs/threat-model.md` update, `examples/source-cdp.toml` gains the opt-in,
   fuzz targets. Run the full Definition of Done plus `make windows/gosec/vuln`
   and the new fuzz targets (filesystem + untrusted-parser changes).

## Testing / Definition of Done

- `./scripts/verify` (build, vet, `go test ./...`), `go test -race`.
- `make windows` (touches `cmd/`, sidecar), `make gosec`, `make vuln`.
- `make fuzz` for the new CDP `localStorage` and storageState `origins` parsers.
- Unit: `webstorage` diff/snapshot; origin host parsing; caps drop-and-count.
- Integration (`test/`): fake CDP serving `Runtime.evaluate` localStorage;
  end-to-end capture -> sidecar -> restore -> storageState with `origins`;
  no-value-leak assertions on all output and error paths; transient-failure
  leaves synced storage intact; deny-wins origin filtering.

## Open questions (resolve before/at sign-off)

1. Exact caps (per-item, per-origin, per-cycle). Proposed: 256 KiB / 512 items /
   8 MiB, tunable if a real store needs more.
2. Is live CDP `localStorage` restore in Slice 2 (best-effort) or deferred to
   Slice 3's launch helper (which can navigate to seed cleanly)? Leaning defer.
3. iframe/subframe capture: v1 top-document-only, or include same-site frames?
   Leaning top-document-only for v1.
4. `inventory` near-expiry has no analog for `localStorage` (no expiry); confirm
   we only report counts.
```
