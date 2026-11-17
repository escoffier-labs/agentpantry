# Operating agentpantry

Day-two commands and behavior: `doctor`, `receipts`, `status`, `inventory`, `run`, `restore`, stdio transport, the source dry-run plan, reliability, and release packaging. Back to the [README](../README.md).

## Operating

`agentpantry doctor` checks a configuration before you rely on it. It verifies
that the pre-shared key exists, is 32 bytes, and is mode 0600, that the role
and peer are well formed, and that the role-specific pieces are in place: on a
source it confirms each browser cookie store and the secrets directory are
readable, and on a sink it confirms the bind address is loopback (warning for
wide binds, including an empty host such as `:8787`), and that each configured
surface is satisfiable. On a source it also
dials the peer to confirm reachability. Pass `--no-net` to skip that or
`--timeout` to change the dial timeout. A source config may set
`peer = "none"` for a local script-driven deployment with no long-running
network peer. Doctor reports that as an `OK` peer row and skips the dial.
Sink configs cannot use that sentinel. Each check prints `OK`, `WARN`, or
`FAIL`. doctor exits 0 when nothing failed and exits 1 when any check is a
`FAIL` (warnings do not fail the run), so it can gate a startup script. Pass
`--json` for a machine-readable payload with check rows, fail/warn counts, and a
safe config summary for operator dashboards such as Brigade.

`agentpantry receipts` is an opt-in, local, append-only JSON Lines log of
successful syncs. Enable `[receipts] enabled = true` on a source and/or sink
(default path: `receipts.jsonl` beside the config). Each line records a UTC
timestamp, this node's identity (`[receipts] identity`, default hostname,
`source_id` and `sink_id` both carry that local asserted identity),
event type (`sync.send` or `sync.apply`), a monotonic `seq`, a SHA-256 digest
of a value-free payload summary (counts and identifiers only), the previous
receipt's hash, and an HMAC-SHA256 bound to the pre-shared key. A `0600` tip
file (`receipts.head`) stores the last seq and hash. Deleting or truncating
the log fails `receipts verify`. The transport is PSK-only, so identity is
asserted, not proven. Cookie values, secret values, and `localStorage` values
are never written. `payload_hash` is hashed, not confidential. `agentpantry
receipts verify` walks the chain, checks every MAC, and cross-checks the tip
(nonzero exit on failure). `agentpantry receipts show [--last N] [--json]`
prints metadata only. Receipt files are mode `0600`. This is tamper-evident
provenance against casual edits, not a defense against a compromised host that
already has the PSK.

`agentpantry status` reports the active role, peer, key path, surfaces, and the
configured allow/deny domains. It also reports the last sync: the time of the
most recent successful source cycle and the cookie, secret, and localStorage
counts in the last frame that was sent, or `never` if the source has not run
yet. Pass `--json` for machine-readable output.

`agentpantry inventory` reads a sidecar backup store and summarizes what it
holds: the total cookie count, the persistent vs session-only split, a per-host
breakdown sorted by count, the auth cookies that are near expiry, and the
localStorage item and origin counts. Where
`status` reports config and a last-sync count, `inventory` reads the store
itself, so you can see what a backup actually contains without querying the
SQLite schema by hand. Point it at a store with `--store` (default
`<config dir>/sidecar.db`), set the near-expiry window with `--expiry-days`
(default 14), and pass `--json` for a payload that downstream tools and
dashboards can consume. The JSON payload includes cookie `name` and `host` for
near-expiry rows (never values). It reports on existing stores only: if the path
does not exist it exits 2 rather than create an empty one.

`agentpantry status -all` summarizes every per-profile config instead of the
canonical one. A deployment that captures per browser profile keeps the real
state in `<config dir>/profiles/*.toml`, so reporting only `config.toml` can
show `last sync: never` on a box that captured this morning. It lists each
profile's role, lane URL, surfaces, adapter and domain counts, and the cookie
count of a configured store. A sink that relies on the default store path
reports that the path is unresolved rather than an empty count, because the
default resolves against that process's own config dir and cannot be inferred
from elsewhere. A store that exists but cannot be read, or a relative
`sidecar_path` (the sink resolves it against its own working directory), is
reported in the row's note rather than silently dropped. Use `-profiles <dir>`
to point at another directory.

`agentpantry verify` answers the `website_authentication` question that
`source --dry-run` can only report as `not_verified`, by checking whether a
running browser still has a working session for one domain:

    agentpantry verify -lane http://127.0.0.1:9224 -domain glassdoor.com \
      https://www.glassdoor.com/index.htm

It opens one tab in the lane browser you name, waits for the document to
finish loading, reads the title, final URL, and a bounded sample of rendered
text, then closes the tab. It exits 0 for usable content, 1 when a challenge, an
empty shell, or an off-domain page came back (`ok`, `challenge`, `empty`,
`off_domain`), and 2 when the check could not run, which includes a missing
`-lane` or any other usage error and a page that failed to load at all. Cookie
counts and expiry dates cannot answer this question: a clearance cookie is bound
to the TLS fingerprint and header order of the browser that earned it, so a
fresh cookie replayed from another client is refused even when its value and
User-Agent match. Only the browser that holds the session proves the session.
`-domain` is required and scopes the check, so the command cannot drive an
authenticated browser anywhere else. The scope covers where the page ends up as
well as where it starts: an expired session that redirects to an external
sign-in reports `off_domain` with only the host it landed on, polling stops
there, and that page's title is not printed. The lane URL must be loopback, and
URLs with embedded credentials are refused. `--json` emits `verdict`, `marker`,
`final_url`, `text_len`, and `checked_at`. Output includes the page title for an
on-domain result and the URL with its query string and fragment removed. Cookie
values, request headers, and page body text are never printed.

`agentpantry run -- <command>` is the sink-side, memory-only way to hand synced
secrets to a child process, in the style of 1Password `op run`. It reads the
already-synced files under the sink config's `secrets_dir`, applies the same
deny-wins `[secret_names]` policy, overlays the permitted values onto the
parent environment, and runs `<command>`. Values are never written to a
staging file. Names that sanitize to loader or interpreter variables such as
`PATH` or `LD_PRELOAD` are refused. `-secret NAME` (repeatable) injects only
those names, `-env NAME=ENVVAR` remaps a secret to a specific variable
(default: uppercase sanitized name), and `-dry-run` prints the env var names
that would be set without executing anything. Secret values are never logged. Prefer `run` when
the consumer can take environment variables. Keep the `secrets` surface for
tools that must read files. A local process that can inspect the child
(`/proc/<pid>/environ`, ptrace, or the Windows equivalent) can still see the
injected values while it runs. On Unix the wrapper forwards SIGINT and
SIGTERM to the child. On Windows signals are not forwarded.

    agentpantry run --config ./sink.toml -- your-agent --flag
    agentpantry run -secret gh_token -env gh_token=GH_TOKEN -- gh auth status
    agentpantry run --dry-run

`agentpantry restore` materializes cookies from an existing sidecar backup into
one explicit target. This is the capture-once-materialize-anywhere path: keep a
sidecar as the portable capture, then write it into the format a local tool or
browser target needs. Restore reads cookies from the sidecar, applies the
same suffix-style domain narrowing, skips already-expired persistent cookies,
and reports counts without printing cookie values. A `storagestate=` target also
reads captured `localStorage` from the sidecar and writes it into the file's
`origins`, narrowed by the same domain policy on each origin's host.

Examples:

    agentpantry restore -sidecar ~/.config/agentpantry/sidecar.db \
      --to netscape=/tmp/cookies.txt --domains example.com --dry-run

    agentpantry restore -config ./sink.toml \
      --to chromium=/tmp/agent-chrome-profile

    agentpantry restore -sidecar ./sidecar.db \
      --to storagestate=./state.json --domains github.com

    agentpantry restore -sidecar ./sidecar.db \
      --to cdp=http://127.0.0.1:9222 --verify

    agentpantry restore -sidecar ./sidecar.db \
      --to desktop-app=codex --dry-run

Use `-sidecar` to name the store directly, or `-config` to derive the sidecar
path the same way `sink` does. Targets are `netscape=<path>` for curl-family
`cookies.txt`, `chromium=<profile-dir>` for a not-running Chrome-compatible
profile directory, `storagestate=<path>` for a Playwright/Puppeteer
`storageState` JSON file (`browser.newContext({ storageState })`), consumed by
headless or headed automation, and `cdp=<http://127.0.0.1:PORT>` for a running
Chromium DevTools endpoint on loopback. A `cdp=` restore also writes captured
`localStorage` best-effort (see the [localStorage section](surfaces-and-adapters.md#localstorage)), and a `storagestate=` restore writes it
into the file's `origins`. `--verify` is CDP-only: after writing, it reads
back through `Storage.getCookies` and prints per-domain expected and present
counts plus cookie names. It exits nonzero if any expected cookie is absent.
`desktop-app=codex` and `desktop-app=claude` are inspection-only targets. They
require `--dry-run`, report the selected profile candidate, lock state, cookie
store candidate, domain and cookie counts, and the unavailable injection method.
Without a supported session-injection and read-back bridge, a non-dry-run call
fails before opening or writing an app profile. `--verify` is rejected for the
same reason.

### Desktop app inspection

Desktop app profiles often contain a Chromium-style `Network/Cookies` or
`Cookies` file. The filename does not prove that agentpantry can encrypt values
the way that app expects. `desktop-app=` checks the paths below, then reports a
cookie store only as a candidate. It uses read-only filesystem metadata calls
and never opens the cookie database.

The candidates come from Go's platform user-config lookup. They do not contain a
compiled-in home directory, and they are not vendor API contracts. A missing
path is reported as `not found`. A `SingletonLock`, `SingletonCookie`, or
`SingletonSocket` entry is reported as `possibly running`. An absent lock is
reported as `not detected`, which does not prove that the app is stopped.

#### Linux

Go resolves the user config directory from `$XDG_CONFIG_HOME`, or from the
current user's home when that variable is empty. The candidates are
`${XDG_CONFIG_HOME:-~/.config}/Codex` and
`${XDG_CONFIG_HOME:-~/.config}/Claude`.

#### macOS

Go resolves the user config directory from the current user's home. The
candidates are `~/Library/Application Support/Codex` and
`~/Library/Application Support/Claude`.

#### Windows

Go resolves the user config directory from `%AppData%`. The candidates are
`%AppData%\Codex` and `%AppData%\Claude`. The Windows build uses the same
metadata-only lock and cookie-file checks as Linux and macOS.

Offline desktop-app restore stays blocked until the implementation can prove all
of these conditions: the app is stopped, the cookie store is a regular file with
a supported schema, the host and app encryption scheme is compatible, a private
backup is created before the transaction, and read-back verification is
available. A detected Chromium layout alone does not clear that gate. The
portable sidecar remains the backup and can still be restored into `netscape=`,
`storagestate=`, `chromium=`, or a loopback `cdp=` target.

A refused write prints the recovery sequence: stop the app completely, remove
`--verify` if present, rerun the same target with `--dry-run`, and do not edit the
profile. Keep the sidecar backup. Until a supported bridge or proven offline
path exists, restore into `storagestate=<path>`, `chromium=<profile-dir>`, or
`cdp=<loopback-http-url>` instead.

Restore limitations:

| Limit | What happens |
| --- | --- |
| Encrypted or app-bound profile state | `chromium=<profile-dir>` writes a local cookie DB and cannot recreate another browser's encrypted profile state. Use CDP for a running browser that must encrypt its own cookies. |
| Partitioned or CHIPS cookies | The sidecar model does not preserve the partition key, so restore cannot recreate partitioned identity exactly. |
| Session storage | Cookies always restore. `localStorage` restores into a `storagestate=` target when a CDP source captured it (see the [localStorage section](surfaces-and-adapters.md#localstorage)). Other targets are cookie-only. `sessionStorage`, IndexedDB, service worker state, and cache data are out of scope. |
| `storagestate` overwrite guard | `storagestate=<path>` merges into an existing `storageState` JSON (preserving its `origins`). It refuses to overwrite a file that is not valid `storageState` JSON, so pointing `--to` at the wrong path fails loudly instead of clobbering it. |
| `SameSite=None` on import | Playwright's `storageState` loader hands cookies to Chromium, which requires `Secure` for `SameSite=None`. agentpantry writes the cookie's real attributes. An insecure `None` cookie may be dropped by the browser on import, as with CDP. |
| `SameSite=None` on CDP | Chromium requires `Secure` when setting `SameSite=None`. CDP may reject insecure cookies with that attribute. |
| Unreachable CDP | `cdp=` targets must be loopback HTTP(S) endpoints with a reachable DevTools websocket. Remote DevTools URLs are rejected. |
| Desktop app process state | `desktop-app=` treats a profile lock as possibly running. An absent lock does not prove the app is stopped. The target remains inspection-only in either case. |
| Desktop app cookie encryption | A Chromium cookie filename is only a layout candidate. Codex and Claude restore stays blocked because no supported injection/read-back bridge or encryption compatibility check is implemented. No app file is opened or written. |
| localStorage into a live browser | A `cdp=` restore writes `localStorage` without navigating the operator's browser, so an origin with no open tab is rejected by Chrome and skipped (counted, best-effort). To seed `localStorage` for any origin reliably, use a browser you own that can navigate to it. The `storagestate=` file path has no such limit. |
| Missing sidecar | Restore opens the sidecar read-only and exits 2 if the store is missing. It does not create an empty backup by accident. |
| Unwritable target | Netscape, Chromium, and CDP writes fail rather than silently dropping cookies when the target cannot be written. |
| Non-representable cookies | Cookies that CDP or a file format cannot represent may fail the restore. Expired cookies are skipped and counted. |

The transport can ride an SSH channel instead of a TCP listener. Run the source
with `--stdio` to stream sealed frames to stdout, and the sink with `--stdio` to
read them from stdin, then connect the two over SSH:

    agentpantry source --stdio | ssh sink.example agentpantry sink --stdio

In `--stdio` mode the source never dials the peer and the sink never binds a
port, so the encrypted link exists only inside the SSH channel. The same key
and framing apply.

For same-box captures driven by an external scheduler, use separate per-profile
source and sink config files and pass each path with `-config` from the script.
Set `peer = "none"` only on those source configs so `agentpantry doctor` can
validate the local setup without requiring a listener. Do not run
`agentpantry source` with that config. The scheduler is responsible for driving
each explicit capture pair.
For a one-shot stdio export, add `--once` on the source side:

    agentpantry source --once --stdio | ssh sink.example agentpantry sink --stdio

`--once` is useful in scripts because the source exits on its own after the
initial sync succeeds. Do not wrap a normal long-running `agentpantry source`
in `timeout` just to force it to stop: a healthy run killed by `timeout` exits
as 124, which can look like an agentpantry failure. Use `source --once` when
the expected result is "sync once, then exit."

### Source dry-run plan

Before a capture, `source --dry-run` prints a read-only plan of what that
source config would read and where it would send it. Pass the same `-config`,
`--stdio`, and `--once` flags you intend to run with, so the route and mode
match:

    agentpantry source --dry-run -config research.toml
    agentpantry source --dry-run --json --once --stdio -config research.toml

The plan reports:

- the config path, role, run mode (`watch` or `once`), and the effective resync interval (`0` in
  `once` mode)
- the route: `tcp` to the configured peer, `stdio`, or `peerless` for a
  `peer = "none"` config driven by an external scheduler
- the key path, whether it exists, and its mode
- one row per browser: kind, profile, read mechanism, cookie store path or
  loopback CDP URL, whether the store exists, `capture_localstorage`, and
  `account_identity`
- the effective `[domains]` and `[secret_names]` allow and deny lists, with the
  deny-wins rule
- whether `secrets_dir` and KeePass are enabled and present, the KeePass tag,
  and the `keepass_keyfile` and `keepass_pass_file` paths with their presence
  and mode
- the local files a real run would write (`state.json`, plus receipts when
  enabled)

The plan reads the config and file metadata (`stat`) only. It does not load the
key, read or decrypt cookies, localStorage, secret files, or KeePass entries,
query the keyring, contact a CDP endpoint, dial the peer, send a session salt or
frame, or write state or receipts.

`status` keeps three answers separate. `config_readiness` is `ready` when every
configured endpoint checks out on metadata alone. It is `not_ready` when, for
example, the key, a cookie store, or a configured secret source is missing, the
key mode is too open, `keepass_path` is set without `keepass_keyfile`, a KeePass
key or password file is not a regular file, is empty, or has a mode that is too
open, the role is not `source`, a browser kind is unsupported, a
CDP URL is not loopback, `capture_localstorage` is set on a non-CDP browser, or
a cookie store or KeePass vault is not a regular file, `secrets_dir` is not a
directory, or the TCP peer is not `host:port` with a port from 1 to 65535 (or a
known service name). `capture_coverage` is always `not_measured`
and `website_authentication` is always `not_verified`: only a real capture can
count what a profile holds, and only the site can confirm a login. A stored
cookie count never implies a working session. For the same reason
`account_identity` is `unknown`, and a successful backup of one profile does not
show coverage of a different profile.

The command prints the plan and exits 0 when `config_readiness` is `ready`, or 1
with the problems listed when it is not. `--json` without `--dry-run` is
rejected.

## Reliability

A TCP source reconnects automatically with capped backoff (1s up to 30s) if the
sink restarts or the link drops, and resends its full current state on each
reconnect. Set `resync_seconds` to have the source periodically re-sync on a
timer in addition to filesystem events (covers any missed event). A `kind=cdp`
source, which has no file to watch, defaults to a 60s poll when `resync_seconds`
is unset. `agentpantry source --once` uses the same initial connect, salt
handshake, read, diff, send, and state-update path, then closes the stream and
exits. It does not start the filesystem watcher, reconnect loop, or resync
timer. Dial, handshake, or initial sync failures return a nonzero exit status.

## Release packaging

Local release archives can be built into `dist/`:

    make package VERSION=v0.2.1

The package target runs `go test ./...`, `go vet ./...`, `gosec`, and
`govulncheck`, then cross-builds Linux, macOS, and Windows archives with build
metadata stamped into the `agentpantry version` output. `dist/checksums.txt`
contains SHA-256 checksums for the generated archives.

Tagged releases (`v*`) are built by GitHub Actions. The release workflow uploads
the platform archives, `checksums.txt`, a source SPDX SBOM, and GitHub artifact
provenance attestations.
