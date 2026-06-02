# agentpantry Phase 7 - SPIKE decision: Windows app-bound encryption (Chrome v127+)

Status: spike decision (committed before the implementation plan, per the goal's SPECIAL CASE)
Date: 2026-06-01
Builds on: P6 (Windows v10/DPAPI source). This spike decides how to handle the
`v20` app-bound cookies that P6 skips.

## Problem

Chrome 127+ on Windows wraps the cookie-encryption key with an additional
"app-bound" key. Cookie values use a `v20` prefix and AES-256-GCM, but the key is
no longer recoverable from `Local State` + DPAPI alone. The app-bound key is held
by a Windows service (`Google Chrome Elevation Service`) and released only through
its `IElevator` COM interface, which validates the calling executable's path and
signature so that only Google-signed Chrome binaries in the expected install
location can retrieve it. P6's DPAPI/v10 path therefore returns nothing usable for
a v20 profile (those rows are skipped).

## Options evaluated

1. **Call `IElevator` COM `DecryptData` from agentpantry.**
   The elevation service validates the caller (path under Program Files, valid
   Google code signature). agentpantry is neither Google-signed nor installed in
   Chrome's directory, so the call is rejected. Community tooling that does this
   either runs code injected into a real Chrome process or spoofs the COM caller,
   both of which are brittle, version-fragile, and adversarial toward Chrome's
   hardening. REJECTED: not robust, not appropriate for an operator tool, breaks
   on every Chrome update.

2. **Run agentpantry as a process Chrome trusts (inject / impersonate).**
   Requires code injection or DLL hijacking into Chrome. Out of bounds for this
   project's non-goals (no scraping/injection; this is an operator tool for your
   own machines, not an evasion tool). REJECTED.

3. **Export cookies through Chrome's own DevTools Protocol (CDP).**
   Launch or attach to Chrome with `--remote-debugging-port` and call
   `Network.getAllCookies` (or `Storage.getCookies`). Chrome itself decrypts and
   returns the cookies in plaintext over a supported, documented API. This
   sidesteps app-bound encryption entirely (Chrome does the decryption, as the
   legitimate owner of the key), is cross-version and cross-platform, and reuses
   the normalized cookie model. The cost: it needs a Chrome instance reachable on
   a debugging port (the operator opts in by launching Chrome with the flag, or
   agentpantry launches a headless Chrome against the profile). CHOSEN.

4. **Document as unsupported with a warning.**
   Fallback if CDP proves infeasible: `doctor` detects a v20/app-bound profile and
   warns, README documents using a non-app-bound profile, Firefox, or the CDP
   approach manually. Retained as the safety net.

## Decision

**Adopt option 3 (CDP `Network.getAllCookies`) as the supported path for
app-bound (v20) profiles**, with option 4's detection + guidance as the
documented fallback when no debugging endpoint is available.

Rationale: it is the only approach that is robust across Chrome versions, uses a
supported API, does not fight Chrome's security model, and fits the project's
non-goals (no injection, no signature spoofing). Chrome decrypts its own cookies;
agentpantry just asks for them over a channel the operator explicitly enables.

## Implementation shape (for the follow-on plan)

- New `internal/cdpvault`: a `CDP` reader implementing `source.CookieReader`. Given
  a base URL (e.g. `http://127.0.0.1:9222`), it discovers a target's WebSocket
  debugger URL via `GET /json`, opens the WebSocket, sends
  `{"id":1,"method":"Network.getAllCookies"}`, and maps the returned cookies into
  the normalized model. CDP `expires` is Unix seconds (float, `-1` for session) ->
  `cookie.ExpiresFromUnix`. Works for v20 because Chrome returns decrypted values.
- Config: a new browser `kind = "cdp"` whose `cookie_path` field is repurposed as
  the CDP base URL (or a dedicated `cdp_url` field). The operator runs Chrome with
  `--remote-debugging-port=9222` (documented; ideally a dedicated automation
  profile/port bound to loopback).
- Testable in CI against a fake HTTP+WebSocket server that serves `/json` and
  answers the CDP command with a canned cookie list (no real Chrome needed).
- `doctor`: when a `cdp` browser is configured, check the endpoint is reachable;
  add a note that app-bound profiles need this path.
- Validate on the Windows host: launch real Chrome with `--remote-debugging-port`, point
  the CDP reader at it, confirm app-bound (v20) cookies export end-to-end.

## Security notes

- The debugging port exposes full browser control; bind it to loopback only and
  treat it like a secret. agentpantry connects locally on the source machine; only
  the resulting cookies cross the encrypted transport, as today.
- This does not weaken app-bound encryption; it uses Chrome's own authorized
  decryption path.

## Acceptance criteria for the P7 implementation

- This decision doc committed (done).
- CDP reader implemented and unit-tested against a fake CDP endpoint.
- A real app-bound (v20) Chrome profile on the Windows host exports cookies via the
  debugging port and syncs end-to-end; OR, if the live validation cannot be
  completed, the detection + `doctor` warning + README workaround fallback is in
  place and the CDP reader passes its fake-endpoint tests.
