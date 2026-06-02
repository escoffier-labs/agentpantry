# agentpantry Phase 5 - design (Firefox source reader)

Status: approved (autonomous scope per goal directive), ready for implementation planning
Date: 2026-06-01
Builds on: P1-P4 and the roadmap (docs/superpowers/specs/2026-06-01-agentpantry-roadmap-p3-p7.md).

## 1. Goal

Read cookies from Firefox on the source so non-Chromium daily drivers are
covered. Firefox stores cookie values in plaintext, so this is a distinct reader
with no decryption and no keyring. It plugs into the existing pipeline as another
`source.CookieReader`; all sink surfaces (sidecar, chrome, netscape, etc.)
benefit automatically.

## 2. Firefox reader

- New package `internal/ffvault` with `type Firefox struct { Profile, CookiePath string }`
  implementing `ReadCookies(ctx) ([]cookie.Cookie, error)`.
- Reads `cookies.sqlite`, table `moz_cookies`, copying the DB to a temp file
  first to avoid WAL/lock contention with a running Firefox (same approach as the
  Chromium reader).
- Query: `SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite
  FROM moz_cookies`.
- Field mapping into the normalized `cookie.Cookie`:
  - `host`, `name`, `value`, `path` map directly (value is already plaintext).
  - `expiry` is **Unix seconds** in Firefox; convert to the pinned contract
    (microseconds since 1601) via `cookie.ExpiresFromUnix(expiry)`. A 0/absent
    expiry stays a session cookie.
  - `isSecure`, `isHttpOnly` map to the bool flags.
  - `sameSite`: Firefox uses 0=None, 1=Lax, 2=Strict, matching the values the
    normalized model already carries for Chromium (Chromium also uses 0/1/2,
    plus -1 for unspecified which Firefox lacks). Store the raw int. Documented.

## 3. Config

`BrowserRef.Kind` already exists as a free string; allow `"firefox"` in addition
to `"chromium"`. No schema change. `CookiePath` points at the profile's
`cookies.sqlite`. Profile auto-discovery (under
`~/.mozilla/firefox/<hash>.<name>/`) is out of scope; the operator gives an
explicit path, consistent with how Chromium profiles are configured today.

## 4. CLI wiring

`buildVaults` in `cmd/agentpantry/main.go` currently errors on any non-`chromium`
kind. Extend it: `kind == "firefox"` constructs an `ffvault.Firefox` reader (no
KeyProvider); `kind == "chromium"` is unchanged; any other kind still errors. The
watched paths list includes the Firefox `cookies.sqlite` as today.

## 5. doctor

The existing source `vault:<profile>` check stats `CookiePath` regardless of
kind, so it already covers Firefox. The `keyring` check is Chromium-specific;
when ALL configured browsers are Firefox there is no Secret Service dependency,
but the keyring check is currently appended unconditionally for the source role.
Refine: only append the keyring check when at least one configured browser is
`chromium` (a pure-Firefox source does not touch the keyring, so a `peanuts`
warning there would be misleading).

## 6. Security

No new secrets or crypto. The Firefox reader is read-only and copies the DB to a
`0600`-equivalent temp file (os.CreateTemp default). Plaintext values flow into
the same normalized model and are subject to the same domain policy at the source.

## 7. Out of scope

- A Firefox SINK writer (writing `moz_cookies` back). The sink surfaces already
  consume the normalized model, so Firefox-as-a-source immediately benefits all
  of them; writing into a live Firefox profile is a separate, lower-demand effort
  deferred unless requested.
- Multi-account-container awareness (`originAttributes`); the reader ignores
  container partitioning and reads the default cookie set.
- Profile auto-discovery.

## 8. Testing

- `ffvault`: build a fake `cookies.sqlite` with a `moz_cookies` table and one
  row (unix expiry, sameSite=1, secure+httponly), assert the normalized cookie
  has the value verbatim, `ExpiresUTC == cookie.ExpiresFromUnix(unixExpiry)`,
  flags true, sameSite 1. A missing DB errors; an empty table yields no cookies.
- `buildVaults` (or an integration test): a `kind = "firefox"` browser ref
  produces a working reader and the cookie syncs end-to-end to the sidecar; an
  unknown kind still errors.
- doctor: a pure-Firefox source config does NOT emit a keyring check; a config
  with a chromium browser still does.
