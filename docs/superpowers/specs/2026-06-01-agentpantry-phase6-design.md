# agentpantry Phase 6 - design (Windows source, DPAPI / pre-app-bound)

Status: approved (autonomous scope per goal directive), ready for implementation planning
Date: 2026-06-01
Builds on: P1-P5 and the roadmap. SPECIAL CASE: the Windows-only pieces cannot be
validated on Linux CI; this phase ships Linux-green code behind build tags and is
explicitly blocked on a smoke test on the owner's Windows desktop before being
called fully done.

## 1. Goal

Run agentpantry as a SOURCE on Windows for Chromium profiles that use the classic
DPAPI-wrapped AES key (Chrome before app-bound encryption, or where it is not
enforced). Pull authenticated sessions from a Windows daily-driver to a Linux
sink. Plus a Windows "service" install path (Scheduled Task, since agentpantry is
a console app).

App-bound encryption (Chrome v127+, `v20` cookies) is explicitly OUT of scope and
is Phase 7.

## 2. Scope

In:
- Windows Chromium SOURCE reader (decrypt `v10` AES-256-GCM cookies using the
  DPAPI-unwrapped key from `Local State`).
- A platform-neutral, Linux-testable crypto codec and Local State key parser.
- A Windows install path via Scheduled Task (string/command generation, testable).

Out (deferred, noted):
- Windows SINK "real-Chrome re-encrypt" surface (would need Windows GCM encrypt
  into the live store). A Windows SINK already works for the sidecar, secrets, and
  adapter surfaces today because those are pure Go with no platform crypto; only
  the chrome re-encrypt surface is Windows-unsupported for now.
- App-bound `v20` cookies (Phase 7).
- Legacy pre-`v10` direct-DPAPI cookie values (rare on modern Chrome); documented.

## 3. Crypto split (testable vs Windows-only)

Platform-neutral, fully unit-tested on Linux (`internal/wincrypto`, no build tag):
- `ParseLocalStateKey(localStateJSON []byte) ([]byte, error)`: read
  `os_crypt.encrypted_key`, base64-decode, strip the 5-byte `DPAPI` prefix, return
  the still-DPAPI-wrapped key bytes. Errors if the field is missing or the prefix
  is wrong.
- `DecryptV10GCM(enc, key []byte) (string, error)`: require a `v10` prefix, split
  the 12-byte nonce and the ciphertext+tag, AES-256-GCM open with `key` (must be
  32 bytes). Errors clearly on short input or wrong key.
- `EncryptV10GCM(plaintext string, key []byte) ([]byte, error)`: inverse, random
  12-byte nonce, returns `v10 || nonce || ciphertext+tag`. (Used by a future
  Windows sink surface; included now because it is trivially testable and the
  inverse of the decrypt.)

Windows-only (`//go:build windows`), validated on the Windows host:
- `UnwrapDPAPI(wrapped []byte) ([]byte, error)`: call `CryptUnprotectData` via
  `golang.org/x/sys/windows` to turn the wrapped key into the 32-byte AES key.
- A non-Windows stub (`//go:build !windows`) returns a clear "DPAPI is only
  available on Windows" error so the package builds everywhere.

## 4. Windows source vault

`internal/vault/windows_chromium.go` (`//go:build windows`): `WindowsChromium`
implements `source.CookieReader`. It copies the `Cookies` SQLite to a temp file,
reads the `cookies` table, loads `Local State` from the profile's parent dir,
derives the key (`ParseLocalStateKey` then `UnwrapDPAPI`), and decrypts each
`encrypted_value` with `DecryptV10GCM`. Per-row decrypt failures are skipped and
counted (matching the Linux reader), so one `v20`/app-bound row does not abort the
whole read (it is simply skipped until Phase 7). This file compiles only on
Windows; its logic relies on the Linux-tested codec.

## 5. CLI wiring (OS dispatch via build tags)

`buildVaults` must compile on all platforms but pick the OS-appropriate Chromium
reader. Introduce a small build-tagged constructor:
- `cmd/agentpantry/chromium_other.go` (`//go:build !windows`):
  `newChromiumReader(b) source.CookieReader` returns `*vault.LinuxChromium`.
- `cmd/agentpantry/chromium_windows.go` (`//go:build windows`): returns
  `*vault.WindowsChromium`.
`buildVaults`'s `case "chromium":` calls `newChromiumReader(b)`. The `firefox`
case is unchanged (Firefox plaintext reading is cross-platform already).

## 6. Windows service install

agentpantry is a console app, not a Windows service binary, so a true SCM service
would need a service control handler (out of scope). Instead, `install-service`
on Windows emits a **Scheduled Task** registration (logon trigger, restart on
failure) via a generated `schtasks` command (and a Task XML), printed for the
operator to run. `internal/service` gains `WindowsTaskCommand(role, binPath,
configPath) string` (and a task name helper), generated as a string and unit-
tested on Linux. The existing `install-service` selects systemd vs Scheduled Task
by GOOS.

## 7. doctor

doctor's existing checks are platform-neutral and already cover the Windows
source (key perms, config, `vault:<profile>` cookie-store stat, keyring check is
chromium-gated). On Windows there is no Secret Service; the keyring check is
Chromium-specific and Linux-oriented. For this phase, gate the keyring check to
non-Windows builds as well (a tiny build-tagged helper `keyringRelevant()` that is
false on Windows), so a Windows source does not emit a misleading keyring line.

## 8. Security

No new secrets on disk. The DPAPI-unwrapped key lives only in memory. v10 GCM
provides authenticated decryption. Temp copies are `0600`-equivalent. Values never
logged; skip counts only.

## 9. Testing

Linux CI (must stay green):
- `wincrypto`: `EncryptV10GCM`/`DecryptV10GCM` round-trip with a known 32-byte
  key; wrong-key fails authentication; short/no-`v10` input errors;
  `ParseLocalStateKey` extracts and strips `DPAPI` from a synthesized Local State
  JSON and errors on a missing field / wrong prefix.
- `service`: `WindowsTaskCommand` contains the binary path, role, config path, and
  a restart directive.
- The non-Windows `UnwrapDPAPI` stub returns an error.
- `go build ./...` and `GOOS=windows go build ./...` BOTH succeed (cross-compile
  check that the build-tagged Windows files compile).

Windows host (the blocked smoke test, performed by the owner):
- A real pre-app-bound Chrome profile's `v10` cookies decrypt and sync to a Linux
  sink. `agentpantry doctor` is clean. `install-service` registers a working
  Scheduled Task.

## 10. Definition of done for this phase

Linux: all unit tests green AND `GOOS=windows go build ./...` succeeds. Then this
phase is merged but explicitly marked BLOCKED on the owner's Windows-host smoke
test (per the goal's SPECIAL CASE). The owner runs the smoke test to close it.
