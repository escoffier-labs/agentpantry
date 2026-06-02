# agentpantry Phase 4 - design (per-CLI adapters)

Status: approved (autonomous scope per goal directive), ready for implementation planning
Date: 2026-06-01
Builds on: P1-P3 and the roadmap (docs/superpowers/specs/2026-06-01-agentpantry-roadmap-p3-p7.md).

## 1. Goal

Write synced session material in the exact shape specific tools expect, so
unmodified CLIs wake up authenticated without being pointed at the sidecar.
Three adapters, each a sink surface, declared in config:

1. **Netscape `cookies.txt`** (cookie surface) - for curl/wget/yt-dlp.
2. **`gh` hosts** (secret surface) - writes the GitHub token into `gh`'s hosts file.
3. **OpenClaw `auth-profiles.json`** (secret surface) - merges a provider profile.

## 2. Config schema (additive, non-breaking)

A new optional `[[adapters]]` array of tables on `config.Config`. Existing
configs without it parse unchanged, so this is additive, not a breaking change.

```go
type AdapterRef struct {
    Type     string            `toml:"type"`     // "netscape" | "gh" | "openclaw"
    Path     string            `toml:"path"`     // target file
    Secret   string            `toml:"secret"`   // gh: secret Name holding the token
    Host     string            `toml:"host"`     // gh: default "github.com"
    User     string            `toml:"user"`     // gh: optional user field
    Profiles map[string]string `toml:"profiles"` // openclaw: secretName -> profileKey
}
// Config gains: Adapters []AdapterRef `toml:"adapters"`
```

Example:
```toml
[[adapters]]
type = "netscape"
path = "/home/u/.cache/agentpantry/cookies.txt"

[[adapters]]
type = "gh"
path = "/home/u/.config/gh/hosts.yml"
secret = "gh_token"
host = "github.com"
user = "octocat"

[[adapters]]
type = "openclaw"
path = "/home/u/.openclaw/agents/main/agent/auth-profiles.json"
[adapters.profiles]
anthropic_profile = "anthropic:default"   # secretName = profileKey
```

The sink builds adapters from `c.Adapters` in addition to `c.Surfaces`; an
unknown adapter `type` is a Fail. `doctor` validates each adapter (target parent
writable; gh/openclaw secret/profiles present).

## 3. Normalized expiry contract (pinned here)

The Netscape adapter forces a decision the model left implicit: cookie
`ExpiresUTC` in the normalized model is the **Chromium native value: microseconds
since 1601-01-01 UTC; 0 means a session cookie**. This matches what the Chromium
reader produces today and what the sidecar/chrome surfaces round-trip. The
Netscape adapter converts to Unix seconds for output:
`unix = micros/1_000_000 - 11644473600` (and 0 stays 0/session). When P5 adds the
Firefox reader, it MUST convert Firefox's native Unix-seconds expiry into this
microseconds-since-1601 contract so the model stays consistent. This contract is
documented in the cookie package.

## 4. Netscape adapter (cookie surface)

- A `CookieSurface` that maintains an in-memory map keyed by `cookie.Key`, with
  values stored as already-converted Netscape rows (domain, include-subdomains
  flag, path, secure flag, unix-expiry, name, value). On `Apply(diff)` it folds
  upserts (convert cookie -> row) and deletes (by key) into the map, then
  rewrites the whole file `0600`.
- Seeded at construction by parsing the existing target file (if present) so a
  sink-only restart does not lose cookies. Rows in the file are already in
  Netscape form, so seeding stores them directly (no epoch round-trip bug).
- Netscape line format (tab-separated):
  `domain<TAB>include_subdomains<TAB>path<TAB>secure<TAB>expiry<TAB>name<TAB>value`
  where include_subdomains is `TRUE` when the host begins with `.` else `FALSE`,
  and secure is `TRUE`/`FALSE` from the cookie flag. A leading `# Netscape HTTP
  Cookie File` header line is written.

## 5. gh adapter (secret surface)

- A `SecretSurface`. On `ApplySecrets(diff)`, if `Secret` (the configured secret
  Name) appears in `diff.Upserts`, load the existing `hosts.yml` (YAML; empty if
  absent), set `hosts[Host].oauth_token = <secret value>` (and `user` if
  configured), preserving every other host and field, and write `0600`.
- **Upsert-only**: deletes are ignored. A transient source-side secret blip must
  not log the user out of `gh`. Documented.
- Uses `gopkg.in/yaml.v3` (new dependency; agentpantry already depends on sqlite,
  toml, dbus, so this is consistent).

## 6. OpenClaw adapter (secret surface)

- A `SecretSurface`. The OpenClaw `auth-profiles.json` `profiles` field is an
  OBJECT keyed by `<provider>:default` (a known footgun: it is NOT an array).
- The adapter is provider-schema-agnostic: for each `secretName -> profileKey`
  mapping, when that secret is in `diff.Upserts`, its value is expected to be a
  JSON object (the full profile for that key). The adapter loads the existing
  file (`{"profiles":{...}}`, empty if absent), sets
  `profiles[profileKey] = <parsed JSON>`, preserving all other profiles, and
  writes `0600`. A secret whose value is not valid JSON is skipped with a
  one-line stderr warning (count only).
- **Upsert-only**: deletes are ignored (do not nuke a working gateway profile on
  a transient blip). Documented.

## 7. Sink wiring

The sink surface builder additionally iterates `c.Adapters`:
- `netscape` -> a `surface.Netscape` cookie surface.
- `gh` -> a `surface.GHHosts` secret surface.
- `openclaw` -> a `surface.OpenClawAuth` secret surface.
Unknown type -> Fail. These are appended to the existing `CookieSurfaces` /
`SecretSurfaces` slices alongside sidecar/chrome/secrets.

## 8. Security

- Adapter outputs are `0600`; targets' parent dirs are created `0700` if missing.
- Secret values never logged (only skip counts).
- Merges preserve unrelated entries (other gh hosts, other OpenClaw profiles,
  other Netscape cookies) so the tool never clobbers a human's file.

## 9. Testing

- cookie package: an exported expiry helper round-trips micros-1601 <-> unix
  seconds (and 0 stays session); table test including a known epoch.
- Netscape: upsert writes a correct tab-delimited 0600 file; delete removes a
  line; re-construct from an existing file seeds state (sink-restart case);
  include-subdomains and secure flags correct; session cookie expiry 0.
- gh: writes oauth_token under the host into an existing hosts.yml with an
  unrelated host present, asserting the other host survives; upsert-only (a
  delete does nothing); 0600.
- OpenClaw: merges a profile JSON under `profiles["anthropic:default"]` into a
  file that already has another profile, asserting the other profile survives
  and `profiles` stays an object; invalid-JSON secret is skipped; 0600.
- config: `[[adapters]]` round-trips through Save/Load including the profiles map.
- doctor: an adapter with a non-writable parent dir Fails; unknown adapter type
  Fails.
- integration: a secret syncs end-to-end and lands in a gh hosts.yml; a cookie
  syncs end-to-end and lands in a Netscape file decodable back to the value.

## 10. Out of scope

Adapters that require running the target tool; reading adapter files back to the
source; cloud-CLI adapters; per-adapter domain filters (the global domain policy
already gates which cookies arrive).
