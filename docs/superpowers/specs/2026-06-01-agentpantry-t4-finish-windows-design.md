# agentpantry T4 - design (finish Windows)

Status: approved (autonomous scope per goal directive), ready for implementation planning
Date: 2026-06-01
Builds on: P6 (Windows DPAPI source), P7 (CDP). Hardening track 4 of 4. SPECIAL CASE:
the Windows pieces are validated on the Windows host (ssh alias); if live cookie
validation cannot complete, T4 is merged with a clear "blocked on host" note.

## 1. Goal

1. **Windows sink real-Chrome re-encrypt surface**: let a Windows sink write
   synced cookies into a real Chrome `Cookies` store, encrypted as `v10`
   AES-256-GCM with the sink machine's DPAPI-unwrapped key (the Windows
   counterpart to the Linux v11 CBC re-encrypt surface from P2).
2. **Real-cookie CDP validation**: prove the CDP reader (P7) exports a real,
   non-empty cookie from a live Chrome on the Windows host (P7 only proved the
   mechanism against an empty profile).

## 2. ChromeStore encryptor abstraction

`surface.ChromeStore` currently hardcodes the Linux scheme
(`vault.EncryptValue` = v11 AES-128-CBC). Make the encryption pluggable so the
same writer serves both platforms:

- Add an `encrypt func(plaintext string) ([]byte, error)` to `ChromeStore`;
  `mappedValues` calls `s.encrypt(c.Value)` for `encrypted_value`.
- `NewChromeStoreEnc(cookiePath string, enc func(string) ([]byte, error)) (*ChromeStore, error)`
  is the low-level constructor (introspects the table, stores `enc`).
- `NewChromeStore(cookiePath string, kp KeyProvider) (*ChromeStore, error)`
  keeps its signature and behavior (resolves the keyring passphrase and wires the
  Linux v11 CBC encryptor via `vault.EncryptValue`), now implemented on top of
  `NewChromeStoreEnc`. Existing P2 tests/usage are unchanged.

The `surface` package stays platform-neutral (it only holds a func).

## 3. Windows chrome key + OS dispatch

- `vault` (windows-tagged): `func WindowsChromeKey(cookiePath string) ([]byte, error)`
  discovers `Local State` (the same walk-up used by `WindowsChromium`), then
  `wincrypto.ParseLocalStateKey` + `wincrypto.UnwrapDPAPI` to return the 32-byte
  AES key. (Factor the Local State discovery into a shared helper used by both
  `WindowsChromium` and this function.)
- The sink's chrome surface is built via an OS-dispatched constructor, mirroring
  `newChromiumReader`:
  - `cmd/agentpantry/chromesurface_other.go` (`!windows`): `newChromeSurface(path)`
    returns `surface.NewChromeStore(path, &vault.SecretServiceKey{Label: "Chrome Safe Storage"})`.
  - `cmd/agentpantry/chromesurface_windows.go` (`windows`): derives the key via
    `vault.WindowsChromeKey(path)` and returns
    `surface.NewChromeStoreEnc(path, func(v string)([]byte,error){ return wincrypto.EncryptV10GCM(v, key) })`.
- `cmdSink`'s `case "chrome":` calls `newChromeSurface(c.Browsers[0].CookiePath)`.

## 4. App-bound caveat (documented)

On Chrome 127+ the live store uses app-bound `v20` cookies; a `v10` value written
by this surface is readable by Chrome's legacy path but a freshly app-bound
profile may prefer/expect `v20`, so the Windows re-encrypt surface is best used
against a not-running, pre-app-bound, or dedicated automation profile. Documented
in the README and a `doctor`/runtime note; this surface is opt-in (like the Linux
one).

## 5. Real-cookie CDP validation (Windows host)

On the Windows host over SSH, using the P6/P7 cross-compile-test-binary recipe:
launch a headless Chrome with an isolated `--user-data-dir` and a
`--remote-debugging-port`, drive it to acquire a real cookie (navigate to a
cookie-setting URL or set one via CDP), then run the CDP reader (env-gated test)
and assert it returns that cookie with the expected value. Kill only the captured
PID (never `taskkill /im chrome.exe`). If the host run cannot be completed
cleanly, record T4 as merged-but-blocked-on-host-validation with the exact reason.

## 6. Testing

- Linux: `NewChromeStoreEnc` round-trips with an injected encryptor (write into a
  synthesized Chrome-schema DB, read `encrypted_value` back, decrypt with the
  matching decoder); existing `NewChromeStore` Linux tests still pass.
- `GOOS=windows go build ./...` compiles the windows surface constructor + key
  helper.
- wincrypto v10 GCM round-trip already covers the encrypt/decrypt pair.
- Windows host: the real-cookie CDP export (section 5).

## 7. Out of scope

A Windows SCM service (Scheduled Task path from P6 stands); cracking app-bound
`v20` write (Chrome owns that); Firefox-on-Windows specifics.
