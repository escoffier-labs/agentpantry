# agentpantry GOAL roadmap: Phases 3 through 7

Status: roadmap / goal plan (autonomous draft, pending owner review)
Date: 2026-06-01
Repo: github.com/escoffier-labs/agentpantry (module `github.com/escoffier-labs/agentpantry`)
Builds on shipped: P1 (Linux Chromium cookies -> sidecar) and P2 (secrets bus + real-Chrome surface).

## GOAL

Take agentpantry from "Linux Chromium cookies + secrets, single tested path" to a
trustworthy, multi-browser, multi-platform session-mirroring tool: operable in
production (self-diagnosing, SSH-rideable), useful to real agent tooling
(per-CLI adapters), broader in browser coverage (Firefox), and cross-platform
(Windows, including the app-bound-encryption frontier).

Each phase ships independently, leaves the tool green and releasable, and gets
its own spec -> plan -> subagent-driven build -> adversarial review cycle, the
same loop that produced P1 and P2.

## Milestones (build order and dependency)

| Phase | Title | Depends on | Readiness | Risk |
|-------|-------|-----------|-----------|------|
| P3 | Operability core: `doctor`, real `status`, `--stdio` | P1/P2 | plan now | low |
| P4 | Per-CLI adapters (Netscape, gh, OpenClaw) | P2 secrets + P3 config patterns | plan now (needs adapter-config decision) | medium |
| P5 | Firefox support (source reader, optional sink writer) | P1 cookie model | plan now | low-medium |
| P6 | Windows source + sink (DPAPI, pre-app-bound Chrome) | P1 vault abstraction | plan after P3-P5; needs Windows test box | high |
| P7 | Windows app-bound encryption (Chrome v127+) | P6 | SPIKE FIRST, then plan | very high |

Recommended order: P3 -> P4 -> P5 -> P6 -> P7. P3 first because it makes every
later phase safer to operate and debug. P6/P7 last because they need a real
Windows host (the owner's Windows desktop) for validation and carry the most
unknowns.

Suggested release tags: cut `v0.2.0` now (P1+P2), then a tag per shipped phase
(`v0.3.0` after P3, etc.), per the release-only-on-request rule (nudge, do not
auto-publish).

---

## Phase 3 - Operability core

**Goal:** Make the tool self-diagnosing and SSH-rideable. Implement the three
CLI capabilities the design already names but P1/P2 deferred: `doctor`, a real
`status`, and `--stdio` transport.

**Why now:** Every later phase is easier to operate and debug if the tool can
tell the operator what is wrong (bad key perms, unreachable peer, locked Chrome,
missing keyring) and can run over an SSH channel without opening a TCP port.

**Scope (in):**
- `pantry doctor`: checks and reports (exit non-zero on hard failures):
  - PSK file exists and is `0600`; key decodes to 32 bytes.
  - Config role/peer present and parseable.
  - Source: each configured browser cookie store is readable; keyring
    passphrase resolves (warn if falling back to `peanuts`); secrets_dir, if
    set, exists.
  - Sink: bind address is loopback or a warning if wider; each enabled surface
    can initialize (sidecar writable, chrome target exists + not-running check,
    secrets_dir writable).
  - Peer reachability: source dials peer with a short timeout and reports
    reachable/unreachable (no data sent).
- `pantry status`: read a small persisted state file and report role, peer,
  surfaces, last successful sync time, and counts (cookies/secrets) from the
  last sync. Reachability probe like doctor's.
- Last-sync state file: `<config dir>/state.json` (`0600`), written by the
  source after each successful `SyncOnce` (timestamp + counts). Time is injected
  (a clock interface) because `Date.now()`/wallclock must stay testable; the CLI
  supplies the real clock.
- `--stdio` flag on `source` and `sink`: source writes frames to stdout and
  reads nothing; sink reads frames from stdin. Enables `ssh sink pantry sink
  --stdio` with the source piping over the SSH channel. Reuses the existing
  `io.Writer`/`io.Reader` seams (Syncer.Out, Server.Serve).

**Scope (out):** metrics export, a daemon control socket, multi-peer.

**Key components & files:**
- `internal/state/state.go` - load/save last-sync state (clock-injected).
- `internal/doctor/doctor.go` - pure check functions returning structured
  results (each check independently testable); the CLI renders them.
- `cmd/agentpantry/main.go` - `cmdDoctor`, rework `cmdStatus`, add `--stdio` to
  source/sink.
- Small `Clock` interface (probably in `internal/state`) so timestamps are
  testable.

**Design decisions:**
- doctor checks are pure functions (config + filesystem in, result structs out)
  so they unit-test without a live network; the network reachability probe is a
  separate, clearly-bounded function with a timeout.
- state.json is best-effort: a write failure warns but does not fail the sync.

**Risks & mitigations:** low. Main trap is making doctor depend on live network
or a real keyring in tests; keep those behind injectable seams.

**Acceptance criteria:**
- `doctor` on a healthy config exits 0; on a bad key perm / unreachable peer /
  missing surface it reports the specific failure and exits non-zero.
- `status` shows a real last-sync time after a sync, and "never synced" before.
- A source `--stdio | sink --stdio` pipe (in-process or over ssh) delivers a
  cookie end-to-end (integration test over an os.Pipe).

---

## Phase 4 - Per-CLI adapters

**Goal:** Write synced session material in the exact shape specific tools expect,
so unmodified CLIs wake up authenticated without pointing them at the sidecar.

**Why now:** This is the payoff for the secrets bus. It is what makes "my agent
box is authenticated" concretely true for `gh`, OpenClaw, and curl-family tools.

**Scope (in):** three adapters, each a sink surface, config-driven:
- **Netscape `cookies.txt`** (cookie surface): render the cookie set in the
  Netscape format curl/wget/yt-dlp accept. Pure transform of the cookie diff
  into a file (`0600`); full rewrite on each apply (simplest correct approach).
- **`gh` hosts** (secret surface): consume a named secret (the GitHub token) and
  write `~/.config/gh/hosts.yml` (or configured path) with `oauth_token`. Merge,
  do not clobber unrelated hosts.
- **OpenClaw `auth-profiles.json`** (secret surface): consume named secrets and
  write the auth-profiles file. NOTE the schema gotcha: `profiles` is an OBJECT
  keyed by `<provider>:default`, NOT an array (a known footgun). Merge into an
  existing file, preserve unrelated profiles.

**Scope (out):** adapters that require running the target tool; bidirectional
read-back; cloud-CLI adapters (future).

**Key components & files:**
- `internal/adapter/netscape.go`, `internal/adapter/gh.go`,
  `internal/adapter/openclaw.go` - each a small writer with one responsibility.
- Config: an `[[adapters]]` table - `type` (netscape|gh|openclaw), `path`
  (target file), and a mapping (for secret adapters: which secret Name feeds
  which field/provider; for netscape: which domains).
- `cmd/agentpantry/main.go` - build adapters from config into the sink's
  CookieSurfaces / SecretSurfaces.

**Design decisions (the one real call to make):** how operators declare adapters.
Recommended: a typed `[[adapters]]` config block with `type` + `path` +
adapter-specific fields, validated at sink startup (unknown type errors, like
surfaces do). Keep each adapter's mapping minimal and explicit.

**Risks & mitigations:** medium. Each target format must be exactly right and
must MERGE rather than overwrite a human's existing file. Mitigation: golden-file
tests per adapter (write into a fixture with pre-existing unrelated entries,
assert ours added and theirs preserved); never log secret values.

**Acceptance criteria:**
- Each adapter writes a correct, tool-loadable file at `0600`.
- Merges preserve pre-existing unrelated entries (gh other hosts, OpenClaw other
  profiles).
- OpenClaw adapter writes the OBJECT-keyed `profiles` shape, verified against the
  documented schema.

---

## Phase 5 - Firefox support

**Goal:** Read cookies from Firefox so non-Chromium daily drivers are covered.

**Why now:** Broadens reach with a low-risk, self-contained reader; Firefox
values are plaintext, so no new crypto.

**Scope (in):**
- Firefox **source reader** (`internal/vault` or a sibling `internal/ffvault`):
  read `cookies.sqlite` `moz_cookies` (host, name, value, path, expiry,
  isSecure, isHttpOnly, sameSite) into the normalized `cookie.Cookie` model.
  Copy-to-temp like the Chromium reader to dodge locks. No decrypt step.
  Map Firefox sameSite enum to the normalized value.
- Config: `kind = "firefox"` browser ref (profile + cookies.sqlite path).
- Profile discovery helper (Firefox profiles live under
  `~/.mozilla/firefox/<hash>.<name>/`); accept an explicit path in config,
  optionally auto-discover the default.

**Scope (out, candidate for a later mini-phase):** a Firefox SINK writer (writing
moz_cookies back); multi-account-container awareness. The existing sink surfaces
(sidecar, chrome, adapters) already consume the normalized model, so Firefox as a
SOURCE immediately benefits all of them. Defer Firefox-as-a-sink-target unless
requested.

**Key components & files:**
- `internal/ffvault/firefox.go` - Firefox reader implementing `source.CookieReader`.
- `internal/config/config.go` - allow `kind = "firefox"`.
- `cmd/agentpantry/main.go` - construct a Firefox reader when configured.

**Risks & mitigations:** low-medium. Trap: sameSite enum mapping and Firefox's
WAL-mode locking. Mitigation: fixture cookies.sqlite in tests; copy-to-temp.

**Acceptance criteria:**
- A Firefox `cookies.sqlite` fixture is read into normalized cookies, sameSite
  mapped correctly, and syncs end-to-end to the sidecar in an integration test.

---

## Phase 6 - Windows source + sink (DPAPI, pre-app-bound)

**Goal:** Run agentpantry on Windows for Chromium profiles that still use the
classic DPAPI-wrapped key (Chrome before app-bound encryption, or where it is
not enforced).

**Why now:** Largest reach expansion; the `BrowserVault` abstraction was built
for exactly this. Comes after P3-P5 because it needs a real Windows host (the
owner's Windows desktop) to validate, and after the operability and adapter work
that make it useful.

**Scope (in):**
- Windows Chromium `BrowserVault` (build-tagged `//go:build windows`):
  - Read the encrypted AES key from `Local State` JSON
    (`os_crypt.encrypted_key`, base64, strip the `DPAPI` prefix), unwrap it with
    `CryptUnprotectData` (DPAPI) via `golang.org/x/sys/windows` or a syscall
    wrapper.
  - Decrypt `v10` cookie values: AES-256-GCM (nonce = bytes 3..15, ciphertext +
    16-byte GCM tag) using the unwrapped key. (Different from Linux's
    AES-128-CBC; the `BrowserVault` interface already isolates this.)
  - Encrypt counterpart for the real-Chrome sink surface on Windows.
- Windows service install: replace/extend `install-service` to emit a Windows
  service definition (or a Scheduled Task) instead of a systemd unit, selected by
  GOOS.
- Keep the build cgo-free (modernc sqlite) so cross-compilation from Linux works.

**Scope (out):** app-bound encryption (that is P7).

**Key components & files:**
- `internal/vault/windows_chromium.go` (`//go:build windows`) + a DPAPI wrapper.
- `internal/vault/chrome_crypto_windows.go` - AES-256-GCM v10 decrypt/encrypt.
- `internal/service/windows.go` - Windows service/Task unit text (testable as
  string generation, like the systemd one).
- `cmd/agentpantry/main.go` - GOOS-aware service install and vault construction.

**Design decisions:**
- Decryption logic that does NOT need DPAPI (the AES-256-GCM step, given a key)
  is platform-neutral and unit-tested on Linux with a known key; only the DPAPI
  key-unwrap is Windows-only and tested on the Windows host.
- Use `golang.org/x/sys/windows` for DPAPI rather than hand-rolled syscalls.

**Risks & mitigations:** high. Real validation needs Windows; DPAPI is
user-context bound. Mitigation: split testable crypto from the Windows-only key
unwrap; do a smoke test on the owner's Windows desktop before claiming done;
gate behind build tags so Linux CI stays green.

**Acceptance criteria:**
- On Linux CI: the AES-256-GCM v10 codec round-trips with a known key (unit
  test).
- On the Windows host: a real Chrome (pre-app-bound) profile's cookies decrypt
  and sync to a Linux sink; a Windows sink writes to a Windows Chrome store.
- `install-service` emits a valid Windows service definition.

---

## Phase 7 - Windows app-bound encryption (Chrome v127+) spike

**Goal:** Support (or cleanly, honestly document the limits of) Chrome v127+
app-bound cookie encryption on Windows.

**Why now:** Last because it is the explicitly-flagged highest-risk item and may
be partially infeasible by design (Google hardened this specifically against
out-of-process key extraction).

**SPIKE FIRST (timeboxed research, output is a decision doc):**
- Document the app-bound mechanism: the cookie key is wrapped by an app-bound
  key retrievable only through Chrome's `IElevator` COM interface, intended to be
  callable only from a process Chrome trusts (path/signature-validated).
- Evaluate approaches and pick one:
  1. Call `IElevator` COM `DecryptData` from agentpantry (assess whether path
     validation blocks a non-Chrome caller).
  2. Run as the same user with the necessary context and accept the documented
     constraints.
  3. **Fallback (most likely shippable):** do NOT crack app-bound encryption.
     Instead export cookies via Chrome's own DevTools Protocol
     (`Network.getAllCookies`) by launching/attaching to Chrome with a remote
     debugging port, which yields plaintext cookies through a supported API.
     This sidesteps app-bound entirely and reuses the normalized model.
  4. Document as unsupported for v127+ with no fallback, if 1-3 all fail.

**Scope (in), after the spike picks an approach:** implement the chosen approach
behind the same `BrowserVault`/reader seams, with tests appropriate to it (CDP
export is testable against a headless Chrome fixture; COM is Windows-host only).

**Scope (out):** anything requiring patching or injecting into Chrome.

**Risks & mitigations:** very high; may end in "documented limitation + CDP
fallback." Mitigation: the spike's job is to fail fast and pick the honest
shippable option. The CDP fallback (approach 3) is the recommended default
target because it is supported, cross-version, and avoids fighting Google's
hardening.

**Acceptance criteria (approach-dependent):**
- Spike decision doc committed, naming the chosen approach and why.
- If CDP fallback: a v127+ Windows Chrome profile's cookies export via the
  debugging port and sync end-to-end.
- If unsupported: a clear `doctor` warning and README note when a v127+
  app-bound profile is detected, plus the recommended workaround.

---

## How to run this as a goal

Each phase above is sized to become its own spec -> plan -> build -> review
cycle. Recommended execution per phase:

1. Promote the phase section into a focused spec
   (`docs/superpowers/specs/<date>-agentpantry-phaseN-design.md`).
2. Write a full TDD plan (`docs/superpowers/plans/<date>-agentpantry-phaseN.md`)
   like P1/P2.
3. Build via subagent-driven-development (Opus implementers, final adversarial
   review), merge to master, push.
4. P7 only: run the research spike and commit the decision doc BEFORE writing the
   implementation plan.

P3, P4, P5 are ready to plan in detail immediately. P6 needs the Windows host
available for validation. P7 must start with the spike.
