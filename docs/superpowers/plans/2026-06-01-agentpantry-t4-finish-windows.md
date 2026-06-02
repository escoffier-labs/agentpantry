# agentpantry T4 Implementation Plan (finish Windows)

> REQUIRED SUB-SKILL: subagent-driven-development / executing-plans. SPECIAL CASE: validate the Windows pieces on the Windows host; if live cookie validation cannot complete, merge with a clear blocked note. Base branch `t4-finish-windows` off master.

---

### Task 1: ChromeStore encryptor abstraction

**Files:** Modify `internal/surface/chromestore.go`; Test `internal/surface/chromestore_test.go`

- [ ] **Step 1: Add a failing test** for `NewChromeStoreEnc` with an injected encryptor: write a cookie, read `encrypted_value` back, assert it equals what the injected encryptor produced (e.g. an encryptor that returns `[]byte("ENC:"+value)`), confirming the writer uses the injected func. Keep the existing `NewChromeStore` round-trip test (Linux v11) unchanged.

- [ ] **Step 2: Implement** — in `chromestore.go`:
  - Replace the `keyPass string` field with `encrypt func(string) ([]byte, error)`.
  - `mappedValues`: `enc, err := s.encrypt(c.Value)`.
  - Add:
    ```go
    func NewChromeStoreEnc(cookiePath string, encrypt func(string) ([]byte, error)) (*ChromeStore, error) {
        if _, err := os.Stat(cookiePath); err != nil {
            return nil, fmt.Errorf("chrome cookie store not found at %s: %w", cookiePath, err)
        }
        warnIfChromeRunning(cookiePath)
        db, err := sql.Open("sqlite", cookiePath)
        if err != nil {
            return nil, err
        }
        cols, err := introspectCookieColumns(db)
        if err != nil {
            db.Close()
            return nil, err
        }
        if len(cols) == 0 {
            db.Close()
            return nil, fmt.Errorf("no cookies table in %s", cookiePath)
        }
        return &ChromeStore{db: db, encrypt: encrypt, cols: cols}, nil
    }
    ```
  - Reimplement `NewChromeStore(cookiePath, kp)` on top of it (Linux v11 CBC):
    ```go
    func NewChromeStore(cookiePath string, kp KeyProvider) (*ChromeStore, error) {
        pass, err := kp.Passphrase()
        if err != nil {
            return nil, err
        }
        return NewChromeStoreEnc(cookiePath, func(v string) ([]byte, error) {
            return vault.EncryptValue(v, pass)
        })
    }
    ```

- [ ] **Step 3: Build/test** — `go test ./internal/surface/ && go build ./... && go vet ./... && GOOS=windows go build ./...`.

- [ ] **Step 4: Commit** — `git commit -m "refactor: make chromestore encryptor pluggable"`.

---

### Task 2: Windows chrome key helper + OS-dispatched chrome surface

**Files:** Modify `internal/vault/windows_chromium.go` (factor Local State discovery + add `WindowsChromeKey`); Create `cmd/agentpantry/chromesurface_other.go` (`!windows`), `cmd/agentpantry/chromesurface_windows.go` (`windows`); Modify `cmd/agentpantry/main.go`

- [ ] **Step 1: Factor + export the key helper** — in `internal/vault/windows_chromium.go`, extract the Local State path walk-up into a package func `localStatePath(cookiePath string) string` (the method becomes a thin wrapper or is replaced), and add:
  ```go
  // WindowsChromeKey returns the profile's AES key (DPAPI-unwrapped) for v10 GCM.
  func WindowsChromeKey(cookiePath string) ([]byte, error) {
      b, err := os.ReadFile(localStatePath(cookiePath))
      if err != nil {
          return nil, fmt.Errorf("read Local State: %w", err)
      }
      wrapped, err := wincrypto.ParseLocalStateKey(b)
      if err != nil {
          return nil, err
      }
      return wincrypto.UnwrapDPAPI(wrapped)
  }
  ```
  Update `WindowsChromium.key()` to call `WindowsChromeKey(v.CookiePath)` (or the shared `localStatePath`).

- [ ] **Step 2: OS-dispatched constructor**:
  - `cmd/agentpantry/chromesurface_other.go`:
    ```go
    //go:build !windows
    package main
    import (
        "github.com/escoffier-labs/agentpantry/internal/sink"
        "github.com/escoffier-labs/agentpantry/internal/surface"
        "github.com/escoffier-labs/agentpantry/internal/vault"
    )
    func newChromeSurface(cookiePath string) (sink.CookieSurface, func() error, error) {
        cs, err := surface.NewChromeStore(cookiePath, &vault.SecretServiceKey{Label: "Chrome Safe Storage"})
        if err != nil {
            return nil, nil, err
        }
        return cs, cs.Close, nil
    }
    ```
  - `cmd/agentpantry/chromesurface_windows.go`:
    ```go
    //go:build windows
    package main
    import (
        "github.com/escoffier-labs/agentpantry/internal/sink"
        "github.com/escoffier-labs/agentpantry/internal/surface"
        "github.com/escoffier-labs/agentpantry/internal/vault"
        "github.com/escoffier-labs/agentpantry/internal/wincrypto"
    )
    func newChromeSurface(cookiePath string) (sink.CookieSurface, func() error, error) {
        key, err := vault.WindowsChromeKey(cookiePath)
        if err != nil {
            return nil, nil, err
        }
        cs, err := surface.NewChromeStoreEnc(cookiePath, func(v string) ([]byte, error) {
            return wincrypto.EncryptV10GCM(v, key)
        })
        if err != nil {
            return nil, nil, err
        }
        return cs, cs.Close, nil
    }
    ```

- [ ] **Step 3: Wire cmdSink** — in `cmd/agentpantry/main.go` `case "chrome":`, replace the direct `surface.NewChromeStore(...)` construction with:
  ```go
  case "chrome":
      if len(c.Browsers) == 0 {
          return fmt.Errorf("chrome surface requires a [[browsers]] entry with cookie_path")
      }
      cs, closeFn, err := newChromeSurface(c.Browsers[0].CookiePath)
      if err != nil {
          return err
      }
      cookieSurfaces = append(cookieSurfaces, cs)
      closers = append(closers, closeFn)
  ```
  (Drop the now-unused direct `&vault.SecretServiceKey{...}` here; `vault` is still imported elsewhere in main.go.)

- [ ] **Step 4: Build both platforms** — `go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...`.

- [ ] **Step 5: Commit** — `git commit -m "feat: windows sink chrome re-encrypt surface (v10 gcm, build-tagged)"`.

---

### Task 3: docs + Windows-host real-cookie CDP validation

**Files:** `README.md`, `CHANGELOG.md`; add an env-gated real-cookie test to `internal/cdpvault`

- [ ] **Step 1: Docs** — README: the Windows sink can write the real-Chrome surface (`v10` GCM via the sink's DPAPI key), best against a not-running/pre-app-bound/dedicated profile (app-bound `v20` profiles may prefer v20). CHANGELOG Unreleased/Added: Windows sink chrome re-encrypt surface. No em dashes/private IPs/hostnames.

- [ ] **Step 2: Real-cookie CDP validation on the Windows host** — extend `internal/cdpvault`'s env-gated real test (or reuse `TestRealCDP`) to assert a specific cookie value when `AGENTPANTRY_CDP_EXPECT` is set. On the host: launch a headless Chrome (isolated `--user-data-dir`, `--remote-debugging-port`), drive it to acquire a real cookie (navigate to a cookie-setting URL, or set one via CDP `Network.setCookie`), then run the reader and assert the cookie is returned. Cross-compile the test binary, scp to `C:\scp`, run over ssh with equals-form flags, kill the captured PID only. Record the result; if it cannot complete cleanly, note T4 as merged-but-blocked-on-host with the reason.

- [ ] **Step 3: Final verify** — `go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...`.

- [ ] **Step 4: Commit** — `git commit -m "docs: document windows sink chrome surface; test: real-cookie cdp probe"`.

---

## Self-Review Notes

- **Spec coverage:** encryptor abstraction (spec 2) -> Task 1; windows key + dispatch (spec 3) -> Task 2; app-bound caveat (spec 4) + validation (spec 5) -> Task 3.
- **Type consistency:** `NewChromeStoreEnc(path, func(string)([]byte,error))` and `NewChromeStore(path, kp)` (Task 1); `vault.WindowsChromeKey` (Task 2, windows); `newChromeSurface(path) (sink.CookieSurface, func() error, error)` build-tagged (Task 2) used in cmdSink (Task 2).
- **Linux green + windows cross-build** both verified each task; the windows-only files are covered by `GOOS=windows go build`.
- **No placeholders.**
