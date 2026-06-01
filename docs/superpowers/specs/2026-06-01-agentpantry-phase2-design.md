# agentpantry Phase 2 - design (real-Chrome surface + secrets bus)

Status: approved (autonomous scope per project owner), ready for implementation planning
Date: 2026-06-01
Builds on: docs/superpowers/specs/2026-06-01-agentpantry-design.md (Phase 2 section)

## 1. Goal

Add the two Phase 2 capabilities from the master design:

1. **Secrets bus** - carry bearer tokens, API keys, and auth blobs from source to
   sink, separately from cookies, and write them to a secrets directory on the
   sink.
2. **Real-Chrome re-encrypt surface** - on the sink, re-encrypt synced cookies
   with the sink machine's own browser keyring key and write them into the
   sink's real Chrome `Cookies` SQLite, so unmodified Chrome and agents that
   drive real Chrome wake up authenticated.

Phase 1 surfaces (plaintext sidecar) and the transport/crypto core are unchanged
except for the wire-payload envelope described below.

## 2. Wire payload change

Phase 1 put a bare JSON `cookie.Diff` inside each AES-256-GCM frame. Phase 2
introduces a single envelope so one frame can carry both cookies and secrets:

```go
package wire

type Payload struct {
    Cookies cookie.Diff `json:"cookies"`
    Secrets secret.Diff `json:"secrets"`
}
```

The source marshals a `wire.Payload`; the sink unmarshals it and routes
`Cookies` to cookie surfaces and `Secrets` to secret surfaces. Both ends are the
same binary and upgrade together, so this is a clean break with no migration
shim. A frame with both diffs empty is not sent.

## 3. Secrets model

`internal/secret` mirrors `internal/cookie` so the two pipelines are uniform:

```go
type Secret struct {
    Name  string `json:"name"`
    Value string `json:"value"` // raw secret bytes as a string
}
func Key(s Secret) string        // == s.Name
type Snapshot struct{ Secrets map[string]Secret }
func NewSnapshot(ss []Secret) Snapshot
type Diff struct {
    Upserts []Secret `json:"upserts"`
    Deletes []string `json:"deletes"` // Names
}
func (s Snapshot) DiffFrom(prev Snapshot) Diff
func (d Diff) IsEmpty() bool
```

Secrets support deletes (a file removed on the source removes it on the sink),
matching cookie semantics. The sink secrets directory is owned by agentpantry,
so delete is safe.

## 4. Source side

- **Secret reader** (`internal/secretsrc`): reads a secrets directory. Each
  regular file is one secret: `Name` = file base name, `Value` = file contents.
  Subdirectories and dotfiles are skipped. Interface:
  `SecretReader interface { ReadSecrets(ctx) ([]secret.Secret, error) }`.
- **Syncer** gains `Secrets []SecretReader` and a `prevSecrets secret.Snapshot`.
  `SyncOnce` builds a cookie diff (as today, policy-filtered) and a secret diff,
  packs them into a `wire.Payload`, and sends one frame if either diff is
  non-empty. `Watch` adds the secrets directory to its watched paths.

The domain policy applies only to cookies. Secrets are opt-in by virtue of the
operator configuring a `secrets_dir`; if no secrets dir is configured, the
secret diff is always empty.

## 5. Sink side

- **Surface interfaces** (`internal/surface`):
  - `CookieSurface interface { Apply(d cookie.Diff) error }` (rename of the
    existing `Surface`).
  - `SecretSurface interface { ApplySecrets(d secret.Diff) error }`.
- **Server** (`internal/sink`) gains two slices, `CookieSurfaces` and
  `SecretSurfaces`, and routes the unmarshaled `wire.Payload` accordingly.
- **Secret directory surface** (`internal/surface/secretdir.go`): `SecretDir`
  writes each secret to `<dir>/<name>` as a `0600` file (dir created `0700`),
  and removes the file on delete. **Filename sanitization is mandatory**: a
  secret name that is not a single path element (contains a separator, is `.`
  or `..`, or differs from its `filepath.Base`) is rejected and skipped with a
  one-line stderr warning (count only, never the value). This prevents path
  traversal from a malicious or buggy source.
- **Real-Chrome surface** (`internal/surface/chromestore.go`): `ChromeStore` is
  a `CookieSurface` that writes into an existing Chrome-schema `Cookies` SQLite.

## 6. Chrome re-encrypt details

- **Encrypt** (`internal/vault/chrome_crypto.go`): add
  `EncryptValue(plaintext, keyringPass string) ([]byte, error)` that produces a
  `v11`-prefixed AES-128-CBC ciphertext with PKCS7 padding, using the same key
  derivation as `DecryptValue`. It is the exact inverse of `DecryptValue` for
  `v11`. The existing `EncryptForTest` helper is reimplemented to delegate to
  the production code path so tests and production share one implementation.
- **Writer** (`ChromeStore`): the target Chrome `Cookies` DB already exists
  (Chrome owns its creation); `ChromeStore` errors clearly if it does not.
  Chrome's `cookies` table schema varies by version and has many `NOT NULL`
  columns, so the writer **introspects the table** with `PRAGMA table_info(cookies)`
  at open time and builds its INSERT dynamically:
  - Mapped columns it sets explicitly when present: `host_key`, `name`,
    `value` (empty string), `encrypted_value` (our `v11` ciphertext), `path`,
    `expires_utc`, `is_secure`, `is_httponly`, `samesite`, `has_expires`,
    `is_persistent`, `creation_utc`, `last_access_utc`, `last_update_utc`,
    `priority` (1), `source_scheme` (2), `source_port` (-1), `top_frame_site_key`
    (empty), `source_type` (0), `has_cross_site_ancestor` (0).
  - Any other present column gets a type-appropriate zero default (`0` for
    INTEGER, `''` for TEXT/BLOB) so `NOT NULL` constraints are satisfied across
    versions.
  - Upserts use `INSERT OR REPLACE INTO cookies(...)` over the present mapped
    columns; deletes use `DELETE FROM cookies WHERE host_key=? AND name=? AND path=?`.
  - **Liveness guard**: at open, if a `SingletonLock` entry exists in the
    profile directory (the cookie file's directory or its parent), log a
    one-time warning that writing a running Chrome profile is unsupported and
    may be ignored or overwritten by Chrome; proceed anyway (best effort). A
    busy/locked DB returns a clear error rather than hanging.

This surface is opt-in and documented as fragile; the plaintext sidecar remains
the recommended always-on baseline.

## 7. Config additions

`internal/config`:

- `SecretsDir string` (`toml:"secrets_dir"`): role-dependent, like `Peer`. On a
  source it is the directory read for secrets; on a sink it is the directory
  secrets are written to. Empty disables the secrets pipeline for that role.
- Surfaces list may now include `"chrome"` and `"secrets"` in addition to
  `"sidecar"`.
- The sink's Chrome write target reuses `Browsers[0]` (its `CookiePath` points
  at the sink Chrome's `Cookies` file; the keyring passphrase comes from the
  same `SecretServiceKey{Label: "Chrome Safe Storage"}` used on the source).

`Default` is unchanged (sidecar-only, no secrets dir) so existing configs keep
working.

## 8. CLI wiring

- `cmdSource`: if `SecretsDir` is set, add a `secretsrc` reader to the Syncer and
  add the dir to the watch paths.
- `cmdSink`: build surfaces from `c.Surfaces`:
  - `"sidecar"` -> `Sidecar` (cookie surface)
  - `"chrome"` -> `ChromeStore` from `Browsers[0]` + `SecretServiceKey` (cookie
    surface)
  - `"secrets"` -> `SecretDir` from `c.SecretsDir` (secret surface)
  Unknown surface names error.

## 9. Security

- Secret values are never logged at any level (only counts).
- Secret dir files and Chrome writes inherit the existing `0600`/`0700` rules;
  secret-name sanitization blocks path traversal.
- Re-encryption uses the sink's own keyring key, so plaintext secrets/cookies do
  not cross the sink's process boundary onto disk except through explicitly
  enabled surfaces.

## 10. Testing

Test-driven throughout, same style as Phase 1:

- `secret` model/diff (mirror cookie tests).
- `secretsrc` reader against a temp dir (files become secrets, subdirs/dotfiles
  skipped).
- `SecretDir` surface: write + delete, `0600` perms, and a traversal name
  (`../evil`, `a/b`) is rejected.
- `wire.Payload` JSON round trip.
- `vault.EncryptValue` round-trips with `DecryptValue`; `EncryptForTest`
  delegates to it.
- `ChromeStore`: against a synthesized modern Chrome-schema DB, an upsert writes
  a row whose `encrypted_value` decrypts (with the sink key) back to the
  plaintext; a delete removes it; missing DB errors.
- `source.SyncOnce` with secrets: payload carries both diffs; cookie policy
  still filters; unchanged state sends nothing.
- `sink.Serve` routes a `wire.Payload` to both surface types.
- Integration: end-to-end source -> sink for a secret (source secrets dir to
  sink secrets dir) and for a cookie via the Chrome store surface.

## 11. Out of scope (later phases)

Per-CLI adapters (P3), Firefox (P4), Windows (P5), the standalone `doctor`
command, and writing secrets into the OS keyring (this phase writes a secrets
directory only).
