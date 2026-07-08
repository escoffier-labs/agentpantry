# Spec: source-side KeePass secret reader

Date: 2026-07-08
Status: approved 2026-07-08 (plan: `docs/plans/2026-07-08-keepass-secret-reader.md`)
Scope: one feature. A new `internal/keepass` package that implements the existing
`source.SecretReader` interface, so a source can read named secrets from an encrypted
KeePass (.kdbx) vault instead of a plaintext `secrets_dir`.

## Context

agentpantry's named-secrets path is plaintext-at-rest on the source: `secretsrc.DirReader`
(`internal/secretsrc/secretsrc.go`) reads each file in `secrets_dir` as one secret. Solomon
now keeps his credentials in an encrypted KeePass vault (the "Marauders Map"), so the source
can pull named secrets straight from that vault and the plaintext directory can go away. This
gives agentpantry an **encrypted source of truth** for the secrets it distributes, with no new
transport work: secrets still flow into the same AES-256-GCM frame.

This is the source half only. A sink-side encrypted surface is a separate future spec.

## Goal / success criteria

1. A source configured with a KeePass vault + key file syncs the vault's tagged entries as
   named secrets, with no plaintext secrets directory required.
2. Drop-in: implements `source.SecretReader`; no changes to transport, diffing, or the sink.
3. Only entries the operator opts in (by tag) are exposed; the existing `[secret_names]`
   allow/deny policy still applies on top.
4. Unlock is non-interactive (key file, optional password file) so the source runs headless.
5. A transient vault read failure never deletes already-synced secrets on the sink.
6. Secret values are never logged. Key material handling mirrors `internal/keyfile` hardening.

## Approach (decided): native Go reader via gokeepasslib

New package `internal/keepass` with a `Reader` implementing
`source.SecretReader.ReadSecrets(ctx) ([]secret.Secret, error)`. Pure-Go KDBX via
`github.com/tobischo/gokeepasslib/v3` (Argon2 support through `golang.org/x/crypto`, already a
dep; no cgo). Rejected: shelling to `keepassxc-cli` (adds a runtime dependency, fragile
parsing) and exporting the vault to a plaintext dir (defeats encryption-at-rest).

### Dependency de-risk (DONE 2026-07-08)
Spike result: gokeepasslib v3.6.2 opened key-file-only test vaults in both KDBX 4.0/Argon2d
(pykeepass-built) and KDBX 3.1/AES-KDF (keepassxc-cli-built), listed entries, read protected
passwords, and surfaced tags as a ";"-joined string. Correction: the live vault's header says
KDBX 4.1 + AES-KDF, not Argon2 (pykeepass preserved the original DB's KDF when building it);
that is the simpler case for the library. Credentials API: `NewKeyDataCredentials(bytes)` and
`NewPasswordAndKeyDataCredentials(password, bytes)`.

## Design

### New package `internal/keepass/keepass.go`
```go
type Reader struct {
    Path    string // .kdbx path
    Keyfile string // key file path (required)
    PassFile string // optional file holding the DB password (for password+keyfile vaults)
    Tag     string // only entries carrying this tag are exported (e.g. "agentpantry")

    mu      sync.Mutex
    lastMod time.Time
    cached  []secret.Secret
}

func (r *Reader) ReadSecrets(ctx context.Context) ([]secret.Secret, error)
```
Behavior of `ReadSecrets`:
1. `os.Stat` the kdbx. If mtime equals `lastMod` and `cached != nil`, return `cached`
   (avoids re-running the deliberately-slow Argon2 KDF every sync tick).
2. Otherwise load credentials: read the key file (and pass file if set) through a **hardened
   loader** that mirrors `internal/keyfile.Load` (stat-on-open-fd 0600 check on non-Windows,
   refuse symlinks/FIFOs, size cap) but accepts arbitrary bytes rather than 64 hex chars.
   Build `gokeepasslib` credentials from the bytes (do not let the library open the paths
   itself, so the hardening is ours).
3. Open + decode the kdbx, `UnlockProtectedEntries`, walk all groups/entries recursively.
4. Select entries carrying `Tag`. KeePass stores `Entry.Tags` as one string with `;`/`,`
   separators, so split and **exact-match** a tag element (a substring test would let tag
   `api` match `rapidapi`). Map `Title -> secret.Name`, `Password -> secret.Value`. Skip
   entries with an empty Title.
5. **Duplicate names fail closed**: if two selected entries share a Title, return an error
   naming the collision (a silent last-writer-wins would ship the wrong secret). Nothing is
   cached on error.
6. Cache result + mtime, return.

Notes:
- Tag scoping is the safety gate: a vault has hundreds of web-login entries; exporting all of
  them as "secrets" would be a foot-gun. Only tagged entries are eligible, and `[secret_names]`
  narrows further.
- Untagging an entry removes it from the exported set, which the snapshot diff then propagates
  as a **delete on the sink**. That is the intended way to stop distributing a secret; call it
  out in docs so it is not surprising.
- The reader never logs Title values at info level and never logs Password values at all.

### Config (`internal/config/config.go`)
Add to `Config`:
```go
KeepassPath    string `toml:"keepass_path"`     // source: read named secrets from this .kdbx
KeepassKeyfile string `toml:"keepass_keyfile"`  // unlock key file (0600)
KeepassPassFile string `toml:"keepass_pass_file"` // optional: file with the DB password (0600)
KeepassTag     string `toml:"keepass_tag"`      // export only entries carrying this tag
```
- `LoadChecked` already surfaces unknown keys, so typos here are caught.
- Add commented lines to the source branch of `WriteTemplate` documenting the four fields and
  that `keepass_tag` defaults to `agentpantry` if empty.
- Default `KeepassTag` to `agentpantry` when `KeepassPath` is set and tag is empty.

### Wiring (`cmd/agentpantry/main.go`, `cmdSource`, ~lines 309-315)
Mirror the existing `SecretsDir` branch:
```go
if c.KeepassPath != "" {
    secretReaders = append(secretReaders, &keepass.Reader{
        Path: c.KeepassPath, Keyfile: c.KeepassKeyfile,
        PassFile: c.KeepassPassFile, Tag: keepassTagOrDefault(c),
    })
    if _, err := os.Stat(c.KeepassPath); err == nil {
        paths = append(paths, c.KeepassPath) // fsnotify triggers a resync when the vault changes
    }
}
```
`secrets_dir` and `keepass_path` may both be set (readers compose); results merge and the
existing name policy filters. If both surface the same name, that is a duplicate-name error at
the snapshot layer, so document "pick one source per name."

### Doctor (`agentpantry doctor`)
When `keepass_path` is set, validate early and clearly: kdbx exists and is readable; key file
exists and is 0600 (mirror keyfile checks); pass file (if set) is 0600; then attempt one
decrypt + count tagged entries, reporting `N secrets from <path> (tag: <tag>)`. Surface a
clear message on wrong key / bad perms rather than failing later mid-sync.

### Failure handling
A read error from `ReadSecrets` propagates to `Syncer.SyncOnce`, which already sets
`secretsUnavailable` and leaves synced secrets on the sink untouched for that cycle (source.go
lines 99-118). So a locked/half-written/rotated vault degrades to "no update this cycle," never
a mass delete. No new handling needed; call this out in a test.

## Operational setup (docs)
The live vault is password-protected. To let the headless source read it, add a **key file** as
an additional credential in KeePassXC (Database Security -> add key file), store it 0600 on the
source (not beside the .kdbx), and point `keepass_keyfile` at it. Tag the specific entries to
distribute with `agentpantry`. This same key-file addition is what the standalone `withsecrets`
resolver uses, so the vault gets one automation credential, not two.

## Testing / verification
- `internal/keepass` unit tests **generate a temp .kdbx at test time** with gokeepasslib (no
  committed secret fixture): assert tagged entries map to Name/Value, untagged are skipped,
  empty-title skipped, duplicate tagged Titles error, and unchanged mtime returns the cache
  without re-decrypting (spy via a decrypt counter).
- Hardened-loader tests: reject 0644 key file, reject symlink/FIFO, reject oversize.
- Config round-trip test for the four new fields + an unknown-key test.
- A `Syncer` test with a Reader stub that errors confirms secrets are left untouched
  (`secretsUnavailable` path).
- Manual: `agentpantry doctor` against Solomon's real vault + key file reports the tagged count;
  `agentpantry source --stdio` emits a frame carrying the tagged secrets.
- Run verifications through Brigade per repo policy:
  `brigade work verify run --target . --command "go test ./internal/keepass/... ./internal/config/..."`.

## Out of scope
- Sink-side encrypted KeePass surface (future spec).
- Cookies in KeePass (they churn too fast; they stay in the sidecar).
- Any change to production `.env` or the gateway.

## Open questions
- ~~Confirm gokeepasslib v3 opens our KDBX vault~~ - resolved by the de-risk spike (see above).
- Key-file-only vs password+key-file for the live vault: spec supports both; Solomon picks the
  operational posture when we wire his real vault.
