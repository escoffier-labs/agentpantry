# Spec: live-Chrome restore and launch helper (Slice 3)

Date: 2026-07-14
Status: draft (spec only)
Scope: finish the "authenticated live Chrome" story. Two deliverables plus an
anti-bot pass. Follows Slice 2 (localStorage capture + restore into a
storageState file / sidecar). Branch: `feat/live-cdp-localstorage` (stacked on
`feat/localstorage-sync`).

## Context

Slice 2 captures localStorage and materializes it into a storageState file and
the sidecar, but it does not write localStorage into a *running* browser, and it
has no one-command path to stand up an authenticated automation Chrome. Slice 3
closes both, tuned for the scraping / job-hunting use case (arrive already logged
in so the anti-bot-flagged login step is skipped).

The controlling insight: **who owns the browser decides whether we may navigate.**

- `restore --to cdp=` targets a browser *the operator launched*. We must not
  navigate or reload it (intrusive, and page loads are an anti-bot fingerprint
  signal). So localStorage there is best-effort and non-navigating.
- The **launch helper** spawns a *dedicated automation browser we own*. There,
  navigating to each origin to seed cookies and localStorage is fine and is the
  only reliable way to seed localStorage for an origin that has no open tab.

## Deliverables

### A. `restore --to cdp=` carries localStorage (best-effort, non-navigating)

Extend the existing `CDP.WriteCookies` path (`internal/cdpvault`) with
`WriteStorage`. It enables `DOMStorage` and issues
`DOMStorage.setDOMStorageItem` with
`storageId { securityOrigin, isLocalStorage: true }` per item. An origin with no
live frame in the target browser may be rejected by Chrome; that origin is
skipped and counted (count only, values withheld), never navigated. `restore`
reads localStorage from the sidecar (Slice 2), narrows by origin host, and writes
both cookies and localStorage; `--verify` (CDP-only) can extend to a localStorage
readback via `ReadStorage`. This is the completeness path; the launch helper is
the reliable one.

### B. Launch helper: `agentpantry browser`

One command to stand up an authenticated automation Chrome:

    agentpantry browser --sidecar ./sidecar.db --domains github.com \
      [--headless] [--profile <dir>] [--port 9222] [--keep-open]

Steps:

1. Resolve a Chrome/Chromium binary (config override, then a platform search
   list). Fail with an explicit install/point-at-binary message if none.
2. Launch it with a **dedicated, throwaway automation profile** (temp dir unless
   `--profile`), loopback `--remote-debugging-port`, and `--headless=new` when
   `--headless` is set (new headless, far less detectable than legacy). Never a
   real user profile.
3. Wait for the CDP endpoint (`/json/version`) with a timeout.
4. For each allowed origin present in the sidecar: create a tab, navigate to the
   origin, set cookies (browser-wide `Storage.setCookies`) and localStorage
   (`Runtime.evaluate` of `localStorage.setItem` in the loaded page). Navigation
   is legitimate here: it is our browser.
5. Either hand the CDP endpoint back and keep Chrome running (`--keep-open`, for
   a scraper to attach to) or verify-and-exit.

Testability: the launcher is an interface (`Launcher.Launch(ctx, opts) (endpoint,
stop, err)`) so orchestration (wait, navigate, seed, verify) is unit-tested
against the fake DevTools server, and the real `exec`-based launcher is a thin
shim smoke-tested against a locally installed Chrome. Cookie values and
localStorage values are never logged.

Anti-bot notes baked in: prefer `--headless=new`; dedicated profile; loopback
CDP; document that a session restored into a browser whose UA / timezone /
language differ from where it was minted may be flagged (fingerprint
consistency), and that headed real Chrome (`--headless` off) is the strongest
option for aggressive anti-bot targets.

### C. Anti-bot doctor + docs

- `doctor` / `browser` steer: warn on legacy headless, remind to use a dedicated
  profile and loopback CDP.
- README: a "scraping / job-hunting" recipe using `agentpantry browser`.

## Security

- No transport/framing change; this is all restore-side (sink/operator).
- `restore --to cdp=` still refuses non-loopback endpoints (`ValidateLoopbackURL`).
- The launch helper writes only to a throwaway profile, never a real one
  (mirrors the AGENTS.md rule); it binds CDP to loopback and treats the port as
  sensitive (already in the threat model).
- Values never logged, including CDP error messages (report codes/counts).
- Domain allow/deny still gates every cookie and origin.

## Phases

1. **A** - `CDP.WriteStorage` + `restore --to cdp=` localStorage (best-effort),
   fake-CDP tests. Self-contained; no real browser needed.
2. **B1** - launch orchestration behind a `Launcher` interface: wait, per-origin
   navigate + seed cookies/localStorage, verify. Unit-tested against fake CDP.
3. **B2** - real `exec` launcher (binary resolution, `--headless=new`, temp
   profile, process lifecycle) + `agentpantry browser` command. Smoke-tested
   against a locally installed Chrome.
4. **C** - anti-bot doctor checks and README recipe.

## Definition of Done

`./scripts/verify`, `go test -race`, `make windows`, `make gosec`, `make vuln`,
and fuzz for any new parser. Values-never-logged assertions on all new output and
error paths. Real Chrome smoke test for B2 recorded in the PR.

## Open questions

1. `--keep-open` default: foreground-and-wait vs. print endpoint and detach?
   Leaning foreground-and-wait (Ctrl-C stops Chrome), with a `--print-endpoint`
   for scripts.
2. Should `agentpantry browser` also accept `-config` (derive sidecar + domains
   from a sink config) like `restore`? Leaning yes, for parity.
3. Reuse `restore`'s narrowing/skip-expired helpers directly (they are already
   the right shape).
