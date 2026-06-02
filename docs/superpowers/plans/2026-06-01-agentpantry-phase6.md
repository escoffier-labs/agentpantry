# agentpantry Phase 6 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. SPECIAL CASE: this phase ships Linux-green code with Windows-only pieces behind build tags; it is merged but BLOCKED on a Windows-host smoke test before being called fully done. Steps use checkbox (`- [ ]`).

**Goal:** Windows Chromium SOURCE support (DPAPI-unwrapped key + `v10` AES-256-GCM cookie decrypt) plus a Windows Scheduled-Task install path, structured so Linux CI stays green and `GOOS=windows go build ./...` compiles.

**Architecture:** A platform-neutral `internal/wincrypto` holds the Local State key parser and the v10 GCM codec (fully Linux-tested). `UnwrapDPAPI` is build-tagged (Windows real via `golang.org/x/sys/windows`; non-Windows stub errors). `vault.WindowsChromium` (Windows-only) is the reader. `buildVaults` picks the reader through a build-tagged `newChromiumReader`. `install-service` emits a Scheduled Task on Windows.

**Tech Stack:** Go 1.25; adds `golang.org/x/sys` (Windows DPAPI). Module `github.com/escoffier-labs/agentpantry`.

Base branch: `phase-6` (create off master).

---

### Task 1: wincrypto codec + Local State key parser (Linux-tested)

**Files:** Create `internal/wincrypto/wincrypto.go`; Test `internal/wincrypto/wincrypto_test.go`

- [ ] **Step 1: Failing test**

`internal/wincrypto/wincrypto_test.go`:
```go
package wincrypto

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func key32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestV10GCMRoundTrip(t *testing.T) {
	enc, err := EncryptV10GCM("session-token", key32())
	if err != nil {
		t.Fatal(err)
	}
	if string(enc[:3]) != "v10" {
		t.Fatalf("want v10 prefix, got %q", string(enc[:3]))
	}
	got, err := DecryptV10GCM(enc, key32())
	if err != nil {
		t.Fatal(err)
	}
	if got != "session-token" {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestV10GCMWrongKeyFails(t *testing.T) {
	enc, _ := EncryptV10GCM("secret", key32())
	bad := key32()
	bad[0] ^= 0xff
	if _, err := DecryptV10GCM(enc, bad); err == nil {
		t.Fatal("wrong key must fail authentication")
	}
}

func TestV10GCMRejectsShortOrNonV10(t *testing.T) {
	if _, err := DecryptV10GCM([]byte("xx"), key32()); err == nil {
		t.Fatal("short input must error")
	}
	if _, err := DecryptV10GCM([]byte("v11abc"), key32()); err == nil {
		t.Fatal("non-v10 prefix must error")
	}
}

func TestParseLocalStateKey(t *testing.T) {
	wrapped := []byte("WRAPPED-KEY-BYTES")
	raw := append([]byte("DPAPI"), wrapped...)
	ls := map[string]any{"os_crypt": map[string]any{"encrypted_key": base64.StdEncoding.EncodeToString(raw)}}
	b, _ := json.Marshal(ls)

	got, err := ParseLocalStateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wrapped) {
		t.Fatalf("want %q, got %q", wrapped, got)
	}
}

func TestParseLocalStateKeyErrors(t *testing.T) {
	if _, err := ParseLocalStateKey([]byte(`{}`)); err == nil {
		t.Fatal("missing key must error")
	}
	noPrefix := map[string]any{"os_crypt": map[string]any{"encrypted_key": base64.StdEncoding.EncodeToString([]byte("NODPAPIhere"))}}
	b, _ := json.Marshal(noPrefix)
	if _, err := ParseLocalStateKey(b); err == nil {
		t.Fatal("missing DPAPI prefix must error")
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/wincrypto/`
Expected: FAIL `undefined: EncryptV10GCM`.

- [ ] **Step 3: Implement**

`internal/wincrypto/wincrypto.go`:
```go
package wincrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ParseLocalStateKey extracts os_crypt.encrypted_key from a Chromium Local State
// JSON, base64-decodes it, and strips the 5-byte "DPAPI" prefix, returning the
// still-DPAPI-wrapped key. Unwrapping (Windows-only) is UnwrapDPAPI.
func ParseLocalStateKey(localStateJSON []byte) ([]byte, error) {
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(localStateJSON, &ls); err != nil {
		return nil, err
	}
	if ls.OSCrypt.EncryptedKey == "" {
		return nil, errors.New("os_crypt.encrypted_key missing in Local State")
	}
	raw, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted_key: %w", err)
	}
	if len(raw) < 5 || string(raw[:5]) != "DPAPI" {
		return nil, errors.New("encrypted_key missing DPAPI prefix")
	}
	return raw[5:], nil
}

// DecryptV10GCM decrypts a Windows Chromium v10 cookie value:
// "v10" || 12-byte nonce || ciphertext+tag, AES-256-GCM with a 32-byte key.
func DecryptV10GCM(enc, key []byte) (string, error) {
	if len(enc) < 3 || string(enc[:3]) != "v10" {
		return "", errors.New("not a v10 GCM value")
	}
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	body := enc[3:]
	if len(body) < 12+16 {
		return "", errors.New("v10 value too short")
	}
	nonce, ct := body[:12], body[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// EncryptV10GCM is the inverse of DecryptV10GCM.
func EncryptV10GCM(plaintext string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, []byte(plaintext), nil)
	out := make([]byte, 0, 3+len(nonce)+len(ct))
	out = append(out, "v10"...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/wincrypto/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wincrypto/wincrypto.go internal/wincrypto/wincrypto_test.go
git commit -m "feat: add windows chromium v10 gcm codec and local state key parser"
```

---

### Task 2: DPAPI unwrap (build-tagged) + non-Windows stub

**Files:** Create `internal/wincrypto/dpapi_windows.go`, `internal/wincrypto/dpapi_other.go`; Test `internal/wincrypto/dpapi_other_test.go`

- [ ] **Step 1: Add the x/sys dependency**

Run: `go get golang.org/x/sys/windows@latest`
Expected: go.mod/go.sum updated.

- [ ] **Step 2: Failing test (non-Windows stub)**

`internal/wincrypto/dpapi_other_test.go`:
```go
//go:build !windows

package wincrypto

import "testing"

func TestUnwrapDPAPIUnsupportedOffWindows(t *testing.T) {
	if _, err := UnwrapDPAPI([]byte("x")); err == nil {
		t.Fatal("DPAPI must be unsupported off Windows")
	}
}
```

- [ ] **Step 3: Run, verify fail**

Run: `go test ./internal/wincrypto/ -run UnwrapDPAPI`
Expected: FAIL `undefined: UnwrapDPAPI`.

- [ ] **Step 4: Implement both files**

`internal/wincrypto/dpapi_other.go`:
```go
//go:build !windows

package wincrypto

import "errors"

// UnwrapDPAPI is unsupported off Windows.
func UnwrapDPAPI(wrapped []byte) ([]byte, error) {
	return nil, errors.New("DPAPI is only available on Windows")
}
```

`internal/wincrypto/dpapi_windows.go`:
```go
//go:build windows

package wincrypto

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// UnwrapDPAPI turns a DPAPI-wrapped key into the raw AES key via CryptUnprotectData.
func UnwrapDPAPI(wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 {
		return nil, windows.ERROR_INVALID_PARAMETER
	}
	in := windows.DataBlob{Size: uint32(len(wrapped)), Data: &wrapped[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	key := make([]byte, out.Size)
	copy(key, unsafe.Slice(out.Data, out.Size))
	return key, nil
}
```

- [ ] **Step 5: Run, verify pass + cross-compile**

Run: `go test ./internal/wincrypto/ && GOOS=windows go build ./internal/wincrypto/`
Expected: PASS; the Windows build of the package compiles.

- [ ] **Step 6: Commit**

```bash
git add internal/wincrypto/dpapi_windows.go internal/wincrypto/dpapi_other.go internal/wincrypto/dpapi_other_test.go go.mod go.sum
git commit -m "feat: add dpapi key unwrap (windows) with non-windows stub"
```

---

### Task 3: Windows Chromium reader (Windows-only)

**Files:** Create `internal/vault/windows_chromium.go` (`//go:build windows`)

No Linux unit test is possible (the file only compiles on Windows); it is validated by `GOOS=windows go build` and the owner's smoke test. Its crypto dependency (`wincrypto`) is already Linux-tested in Tasks 1-2.

- [ ] **Step 1: Implement**

`internal/vault/windows_chromium.go`:
```go
//go:build windows

package vault

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/wincrypto"
	_ "modernc.org/sqlite"
)

// WindowsChromium reads a Chromium-family cookie store on Windows (pre-app-bound).
type WindowsChromium struct {
	Profile    string
	CookiePath string
	// LocalStatePath overrides the default (two dirs up from CookiePath / "Local State").
	LocalStatePath string
}

func (v *WindowsChromium) Name() string { return "chromium-win:" + v.Profile }

func (v *WindowsChromium) localStatePath() string {
	if v.LocalStatePath != "" {
		return v.LocalStatePath
	}
	// CookiePath is typically <UserData>/<Profile>/Network/Cookies; Local State
	// lives in <UserData>. Walk up to find it.
	dir := filepath.Dir(v.CookiePath)
	for i := 0; i < 3; i++ {
		cand := filepath.Join(dir, "Local State")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	return filepath.Join(filepath.Dir(v.CookiePath), "Local State")
}

func (v *WindowsChromium) key() ([]byte, error) {
	b, err := os.ReadFile(v.localStatePath())
	if err != nil {
		return nil, fmt.Errorf("read Local State: %w", err)
	}
	wrapped, err := wincrypto.ParseLocalStateKey(b)
	if err != nil {
		return nil, err
	}
	return wincrypto.UnwrapDPAPI(wrapped)
}

func copyToTempWin(src string) (string, func(), error) {
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "agentpantry-wincookies-*.db")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}

func (v *WindowsChromium) ReadCookies(ctx context.Context) ([]cookie.Cookie, error) {
	key, err := v.key()
	if err != nil {
		return nil, err
	}
	tmp, cleanup, err := copyToTempWin(v.CookiePath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", filepath.ToSlash(tmp)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, `SELECT host_key, name, value, encrypted_value,
		path, expires_utc, is_secure, is_httponly, samesite FROM cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []cookie.Cookie
	skipped := 0
	for rows.Next() {
		var (
			host, name, plain, path    string
			enc                        []byte
			expires                    int64
			secure, httpOnly, samesite int
		)
		if err := rows.Scan(&host, &name, &plain, &enc, &path, &expires, &secure, &httpOnly, &samesite); err != nil {
			return nil, err
		}
		value := plain
		if len(enc) > 0 {
			dv, derr := wincrypto.DecryptV10GCM(enc, key)
			if derr != nil {
				// app-bound (v20) or otherwise undecryptable: skip until phase 7.
				skipped++
				continue
			}
			value = dv
		}
		out = append(out, cookie.Cookie{
			Host: host, Name: name, Value: value, Path: path,
			ExpiresUTC: expires, IsSecure: secure != 0,
			IsHTTPOnly: httpOnly != 0, SameSite: samesite,
		})
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "agentpantry: skipped %d cookie(s) not decryptable as v10 (app-bound v20 needs phase 7)\n", skipped)
	}
	return out, rows.Err()
}
```

- [ ] **Step 2: Cross-compile check**

Run: `GOOS=windows go build ./internal/vault/`
Expected: compiles.

- [ ] **Step 3: Commit**

```bash
git add internal/vault/windows_chromium.go
git commit -m "feat: add windows chromium source reader (build-tagged)"
```

---

### Task 4: build-tagged chromium reader constructor + buildVaults

**Files:** Create `cmd/agentpantry/chromium_other.go` (`//go:build !windows`), `cmd/agentpantry/chromium_windows.go` (`//go:build windows`); Modify `cmd/agentpantry/main.go`

- [ ] **Step 1: Implement the two constructors**

`cmd/agentpantry/chromium_other.go`:
```go
//go:build !windows

package main

import (
	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/source"
	"github.com/escoffier-labs/agentpantry/internal/vault"
)

func newChromiumReader(b config.BrowserRef) source.CookieReader {
	return &vault.LinuxChromium{
		Profile:     b.Profile,
		CookiePath:  b.CookiePath,
		KeyProvider: &vault.SecretServiceKey{Label: "Chrome Safe Storage"},
	}
}
```

`cmd/agentpantry/chromium_windows.go`:
```go
//go:build windows

package main

import (
	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/source"
	"github.com/escoffier-labs/agentpantry/internal/vault"
)

func newChromiumReader(b config.BrowserRef) source.CookieReader {
	return &vault.WindowsChromium{Profile: b.Profile, CookiePath: b.CookiePath}
}
```

- [ ] **Step 2: Use it in buildVaults**

In `cmd/agentpantry/main.go`, change the `case "chromium":` in `buildVaults` to:
```go
		case "chromium":
			vs = append(vs, newChromiumReader(b))
```
Remove the now-unused direct `vault.LinuxChromium{...}` construction there. Keep the `firefox` and `default` cases. If `vault` is no longer referenced elsewhere in main.go, remove its import (it likely IS still used by the sink chrome surface `&vault.SecretServiceKey{...}`, so leave it).

- [ ] **Step 3: Build both platforms + vet + test**

Run:
```bash
go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...
```
Expected: all PASS; Windows cross-build compiles.

- [ ] **Step 4: Commit**

```bash
git add cmd/agentpantry/chromium_other.go cmd/agentpantry/chromium_windows.go cmd/agentpantry/main.go
git commit -m "feat: select os-appropriate chromium reader via build tags"
```

---

### Task 5: Windows Scheduled-Task install + doctor keyring OS gate

**Files:** Modify `internal/service/systemd.go` (or add `internal/service/windows.go`); `cmd/agentpantry/main.go`; add `internal/doctor` build-tagged `keyringRelevant`; Tests for service + (existing) doctor

- [ ] **Step 1: Failing test for the Windows task command**

`internal/service/windows_test.go`:
```go
package service

import (
	"strings"
	"testing"
)

func TestWindowsTaskCommand(t *testing.T) {
	cmd := WindowsTaskCommand("source", `C:\bin\agentpantry.exe`, `C:\cfg\config.toml`)
	for _, want := range []string{"schtasks", "agentpantry-source", `C:\bin\agentpantry.exe`, "source", `C:\cfg\config.toml`} {
		if !strings.Contains(cmd, want) {
			t.Errorf("task command missing %q\n%s", want, cmd)
		}
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/service/ -run Windows`
Expected: FAIL `undefined: WindowsTaskCommand`.

- [ ] **Step 3: Implement WindowsTaskCommand**

Add to `internal/service/systemd.go` (or a new `internal/service/windows.go`):
```go
// WindowsTaskName is the Scheduled Task name for a role.
func WindowsTaskName(role string) string { return "agentpantry-" + role }

// WindowsTaskCommand renders a schtasks command registering a logon-triggered
// task that runs the role and restarts on failure. agentpantry is a console app,
// so a Scheduled Task (not an SCM service) is used.
func WindowsTaskCommand(role, binPath, configPath string) string {
	return fmt.Sprintf(`schtasks /create /tn "%s" /sc onlogon /rl highest /f ^
  /tr "\"%s\" %s --config \"%s\""`,
		WindowsTaskName(role), binPath, role, configPath)
}
```
(Ensure `"fmt"` is imported in that file.)

- [ ] **Step 4: doctor keyring OS gate**

Create `internal/doctor/keyring_other.go`:
```go
//go:build !windows

package doctor

func keyringRelevant() bool { return true }
```
Create `internal/doctor/keyring_windows.go`:
```go
//go:build windows

package doctor

func keyringRelevant() bool { return false }
```
In `internal/doctor/doctor.go`, change the keyring gate to `if hasChromium && keyringRelevant() {`.

- [ ] **Step 5: install-service GOOS switch**

In `cmd/agentpantry/main.go` `cmdInstallService`, branch on `runtime.GOOS`:
```go
	if runtime.GOOS == "windows" {
		cfgPath := filepath.Join(config.Dir(), "config.toml")
		bin, _ := os.Executable()
		fmt.Println("Register a Scheduled Task by running:")
		fmt.Println(service.WindowsTaskCommand(c.Role, bin, cfgPath))
		return nil
	}
```
placed at the top of the function body (after loading config), leaving the existing systemd path for non-Windows. Add `"runtime"` to imports.

- [ ] **Step 6: Build both platforms + vet + test**

Run:
```bash
go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...
```
Expected: all PASS; Windows cross-build compiles.

- [ ] **Step 7: Commit**

```bash
git add internal/service/ internal/doctor/ cmd/agentpantry/main.go
git commit -m "feat: windows scheduled-task install and os-gated keyring check"
```

---

### Task 6: docs + cross-compile guard in tests

**Files:** `README.md`, `CHANGELOG.md`

- [ ] **Step 1: Docs**

In `README.md`, add a "Windows (source)" note: `kind = "chromium"` works on Windows for pre-app-bound profiles (decrypts `v10` cookies via DPAPI); app-bound `v20` cookies are skipped pending a later release; `install-service` prints a Scheduled Task command. Note the Windows SINK supports sidecar/secrets/adapter surfaces but not yet chrome re-encrypt. In `CHANGELOG.md` `## Unreleased` -> `### Added`, add the Windows-source bullet, marked "(needs validation on a Windows host)". No em dashes, no private IPs, no machine hostnames.

- [ ] **Step 2: Final verification**

Run: `go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...`
Expected: all green; Windows cross-build compiles.

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: document windows source support (pending host validation)"
```

---

## Self-Review Notes

- **Spec coverage:** codec+parser (spec 3) -> Task 1; DPAPI build-tagged (spec 3) -> Task 2; Windows reader (spec 4) -> Task 3; OS dispatch (spec 5) -> Task 4; Scheduled Task + doctor gate (spec 6,7) -> Task 5; docs+cross-compile (spec 9) -> Task 6. Windows sink chrome re-encrypt + v20 explicitly deferred.
- **Linux stays green:** all new logic with tests (`wincrypto`, `service`) is platform-neutral; Windows-only files are build-tagged and covered by `GOOS=windows go build`. `WindowsChromium` has no Linux test by necessity (documented; its crypto is tested via `wincrypto`).
- **Type consistency:** `wincrypto.ParseLocalStateKey/DecryptV10GCM/EncryptV10GCM/UnwrapDPAPI` (Tasks 1-2) used by `vault.WindowsChromium` (Task 3). `newChromiumReader(config.BrowserRef) source.CookieReader` defined twice (build-tagged) and called in `buildVaults` (Task 4). `service.WindowsTaskCommand/WindowsTaskName` (Task 5). `doctor.keyringRelevant()` build-tagged (Task 5).
- **SPECIAL CASE:** after Task 6, merge with Linux green + `GOOS=windows go build` passing, then mark BLOCKED on the owner's Windows-host smoke test (do not claim fully done).
- **No placeholders:** all code complete.
