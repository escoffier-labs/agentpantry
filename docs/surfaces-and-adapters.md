# Surfaces, secrets, and adapters

What the sink writes and where: surfaces, named secrets, localStorage, the automation browser, and adapters. Back to the [README](../README.md).

## Surfaces

The sink applies each synced diff to one or more surfaces, chosen by the
`surfaces` list in the sink config.

- `sidecar` (always available): a plaintext sidecar SQLite database holding the
  current cookie set, written mode 0600. This is the default and safest target.
- `chrome` (opt-in, fragile): writes synced cookies directly into an existing
  Chrome Cookies SQLite, re-encrypting each value with the sink machine's own
  keyring key. The table schema is introspected at open time so it tolerates
  Chrome version differences. This surface targets a profile that is not
  running. Writing a live profile is unsupported, and Chrome may ignore or
  overwrite the rows. It requires a `[[browsers]]` entry whose `cookie_path`
  points at the target store.
- `secrets`: writes synced secrets as individual files under the configured
  secrets directory, one file per secret, mode 0600.

Example sink config selecting multiple surfaces:

    role = "sink"
    peer = "127.0.0.1:8787"
    surfaces = ["sidecar", "secrets"]
    secrets_dir = "/home/agent/.config/agentpantry/secrets"

## Secrets

Beyond cookies, agentpantry can mirror a directory of secrets from source to
sink in the same encrypted frame. On the source, set `secrets_dir` to a
directory and each regular file becomes one secret (the file name is the secret
name, the file contents are the value). Dotfiles and subdirectories are skipped.

Instead of (or alongside) a plaintext directory, the source can read named
secrets straight from an encrypted KeePass vault:

    keepass_path = "/home/you/vault.kdbx"
    keepass_keyfile = "/home/you/.config/agentpantry/vault.key"
    # keepass_pass_file = "..."   # only for password+keyfile vaults
    # keepass_tag = "agentpantry" # the default

Only entries carrying the `keepass_tag` tag are exported (entry Title becomes
the secret name, Password the value), so tagging is the opt-in: the rest of
the vault never leaves the machine. `[secret_names]` still applies on top.
Untagging an entry propagates as a delete on the sink. Unlock is
non-interactive via a 0600 key file (add one in KeePassXC under Database
Security), so the source runs headless. If the same name comes from both
`secrets_dir` and the vault (or a name repeats within one source), that
cycle's secret read fails like an unreadable source: stderr names the colliding
secret and the sources involved (never values), and the sink keeps what it has
until you remove the duplicate. A vault that is temporarily unreadable leaves
already-synced secrets on the sink untouched for that cycle.

On the sink, enable the `secrets` surface and set `secrets_dir` to the
destination. Each secret is written as a 0600 file named after the secret.
Secret names are sanitized on the sink: any name containing a path separator,
a `..` element, or an absolute path is skipped rather than written outside the
secrets directory.

When a command can take secrets from the environment, `agentpantry run --
<command>` injects the same deny-wins set into that process only and does not
stage values to another file. The on-disk `secrets` surface stays available
for tools that must read files. `run` does not delete those files.

Cookies and secrets travel together inside one AES-256-GCM frame, so a single
peer connection carries both.

## localStorage

Modern logins increasingly keep session material (JWTs, refresh tokens, device
IDs) in `localStorage` rather than cookies, so a cookies-only restore can leave a
session signed out. A `kind = "cdp"` source can mirror `localStorage` so the
restored session is whole. It is opt-in and off by default:

    [[browsers]]
    kind = "cdp"
    url  = "http://127.0.0.1:9222"
    capture_localstorage = true

Capture is non-intrusive: agentpantry reads `localStorage` from the origins
already open in the browser's tabs and never navigates or reloads a page (which
would be visible to anti-bot fingerprinting). Each origin is gated by the same
`domains.allow` policy as cookies, values are never logged, and an oversized
store is bounded (per-item, per-origin, and per-cycle caps, with skipped items
counted). It rides the same AES-256-GCM frame as cookies and secrets and lands in
the `storagestate` surface (`origins[].localStorage`) and the sidecar, so both
live sync and `restore --to storagestate=` carry it.

Capture is CDP-only: disk Chromium and Firefox sources cannot read `localStorage`
while the browser holds the store, so `capture_localstorage` requires
`kind = "cdp"` and `doctor` fails it otherwise. `sessionStorage`, IndexedDB, and
service worker state stay out of scope.

## Launching an automation browser

`agentpantry browser` stands up a dedicated automation Chrome that is already
logged in, so a scraper attaches to a warm session instead of driving a login
(the step anti-bot systems flag hardest):

    agentpantry browser --sidecar ./sidecar.db --domains github.com --keep-open

    agentpantry browser -config ./sink.toml --keep-open

It launches Chrome with a throwaway profile (never a real one) on a loopback
debugging port, sets cookies browser-wide, seeds each origin's `localStorage`
after its tab or frame is ready, and hands the DevTools endpoint back. Headed
mode passes one startup tab per distinct storage origin. Headless mode starts
with a single `about:blank` target, waits for loopback CDP, then creates one
temporary target per distinct validated HTTP or HTTPS storage origin through the
CDP HTTP target endpoint, seeds `localStorage` once that origin's frame is ready,
and closes only those temporary targets. The original `about:blank` page stays
open for attachment. Cookies-only and empty-storage headless runs create no
origin targets. That sequencing avoids Chrome 151 rejecting multiple headless
startup targets with "Multiple targets are not supported in headless mode". Use
`-sidecar` to name the store directly, or `-config` to derive the sidecar path
and domain policy the same way `sink` and `restore` do (pass exactly one). Flags:
`--headless` uses new headless (`--headless=new`), `--profile` names a
persistent user-data-dir instead of a temp one, `--port` sets the debugging port,
`--chrome` points at a specific binary, `--verify` reads cookies back through
CDP, and `--keep-open` leaves the browser running (Ctrl-C to stop) for a scraper
to attach.

Because agentpantry owns this browser, it seeds `localStorage` reliably once
each storage origin has a live frame, then replays accepted cookies after that
hydration step. A replay failure warns but does not discard storage hydration.
By contrast, `restore --to cdp=` against a browser you already launched remains
best-effort. The launch
sets `--disable-blink-features=AutomationControlled` so `navigator.webdriver`
stays unset. That flag is the extent of agentpantry's anti-bot posture. It
delivers the authenticated session and gets out of the way. Fingerprint shims,
human-paced input, and captcha handling belong to the tool driving the tab (a
Playwright/Puppeteer stealth layer). A session restored into a browser whose user
agent, timezone, or language differ from where it was minted can still be
flagged, so match those.

For a long-running automation browser you already drive over CDP, keep its
session fresh in place with `agentpantry restore --to cdp=http://127.0.0.1:PORT`
instead of relaunching. That pairs with the capture direction: a `kind = "cdp"`
source can read cookies and `localStorage` back out of the same running browser,
so one browser stays synced with your daily driver in both directions.

## Adapters

Adapters are extra sink surfaces that write synced data into the native file a
specific CLI or agent harness already reads, so the tool wakes up authenticated
without any agentpantry-aware glue. They are declared with an optional
`[[adapters]]` block in the sink config, each entry chosen by `type`. An adapter
is layered on top of the regular `surfaces` list. You can run both at once.

Five adapter types ship:

- `netscape`: a cookie surface that writes a Netscape `cookies.txt` (the format
  curl, wget, and yt-dlp consume), mode 0600. It keeps an in-memory row set
  seeded from its own file on start, so a sink restart does not drop rows the
  source has not re-sent, and it rewrites the whole file on each apply.
- `storagestate`: a cookie surface that writes a Playwright/Puppeteer
  `storageState` JSON file, mode 0600, so a headless or headed automation
  browser wakes up authenticated via `browser.newContext({ storageState })`
  without replaying a login (the login step is what anti-bot systems flag
  hardest). Like `netscape` it seeds from its own file so a restart keeps rows
  the source has not re-sent. It writes `origins[].localStorage` when a CDP
  source captures it (see the localStorage section), so the restored session
  carries web-storage tokens alongside cookies. Also available as a `restore`
  target.
- `gh`: a secret surface that writes the GitHub token into the GitHub CLI's
  `hosts.yml`. It is merge-only, so unrelated hosts already in the file are
  preserved, and upsert-only, so a transient missing secret never deletes the
  token and logs you out. Set `secret` to the secret name holding the token,
  `host` (defaults to `github.com`), and optionally `user`.
- `openclaw`: a secret surface that merges provider profiles into an OpenClaw
  `auth-profiles.json`. The `profiles` field there is an OBJECT keyed by
  `<provider>:default`, not an array, so each `profiles` mapping entry maps a
  secret name to its profile key. The secret value must itself be the profile
  JSON object. A value that is not valid JSON is skipped rather than written, so
  a malformed secret never corrupts a working gateway file. Like `gh` it is
  merge-only and upsert-only.
- `hermes`: a cookie and secret surface that writes an Agent Pantry bundle under
  a Hermes-readable directory, usually `~/.hermes/agentpantry`. The bundle
  contains `cookies.txt`, `secrets/<name>`, and `agentpantry.json` describing the
  relative paths. This is an Agent Pantry-owned subtree, so deletes remove the
  corresponding bundled cookie or secret.

Example sink config with the common adapters:

    role = "sink"
    peer = "127.0.0.1:8787"
    surfaces = ["sidecar"]

    [[adapters]]
    type = "netscape"
    path = "/home/agent/.config/agentpantry/cookies.txt"

    [[adapters]]
    type = "storagestate"
    path = "/home/agent/.config/agentpantry/state.json"

    [[adapters]]
    type = "gh"
    path = "/home/agent/.config/gh/hosts.yml"
    secret = "gh_token"
    host = "github.com"
    user = "octocat"

    [[adapters]]
    type = "openclaw"
    path = "/home/agent/.openclaw/auth-profiles.json"

    [adapters.profiles]
    anthropic_secret = "anthropic:default"

    [[adapters]]
    type = "hermes"
    path = "/home/agent/.hermes/agentpantry"

`agentpantry doctor` checks each adapter: that its target directory is writable
or creatable, that a `gh` adapter names a secret, and that an `openclaw` adapter
carries a profiles mapping. For `hermes`, `path` is a bundle directory, not a
single file.

## Status

Current status: cookie sync to the plaintext sidecar remains the default path.
Additional shipped surfaces include real-Chrome re-encrypt, secrets, Netscape
`cookies.txt`, Playwright/Puppeteer `storageState`, `gh`, `openclaw`, and the
Hermes Agent bundle. Source support includes Linux Chromium, Firefox, Windows
Chromium, and Chrome DevTools Protocol export for app-bound Chrome profiles,
with optional `localStorage` capture over CDP.
