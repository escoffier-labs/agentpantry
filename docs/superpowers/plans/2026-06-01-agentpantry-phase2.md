# agentpantry Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the secrets bus (source secrets dir -> sink secrets dir) and the real-Chrome re-encrypt surface (sink writes synced cookies into a real Chrome Cookies SQLite, re-encrypted with the sink's own keyring key), introducing a `wire.Payload` envelope that carries cookies and secrets in one frame.

**Architecture:** A new `secret` package mirrors `cookie` (model + diff). A `wire.Payload{Cookies, Secrets}` is what now travels inside each AES-256-GCM frame. The source `Syncer` reads cookie vaults and secret readers, packs a Payload, and sends it. The sink `Server` routes the Payload to `CookieSurface`s (sidecar, chrome) and `SecretSurface`s (secretdir). `vault.EncryptValue` is the inverse of `DecryptValue`; `ChromeStore` introspects the Chrome cookies table schema and writes rows dynamically.

**Tech Stack:** Go 1.25 toolchain (auto-selected), `modernc.org/sqlite`, `golang.org/x/crypto/pbkdf2`, `github.com/godbus/dbus/v5`, existing internal packages.

Base branch: `phase-2` (already created off `master`). Module: `github.com/escoffier-labs/agentpantry`.

---

## File Structure

```
internal/secret/model.go            # Secret, Snapshot, Key, NewSnapshot
internal/secret/diff.go             # Diff, DiffFrom, IsEmpty
internal/wire/wire.go               # Payload{Cookies, Secrets}
internal/secretsrc/secretsrc.go     # DirReader: dir -> []secret.Secret
internal/vault/chrome_crypto.go     # + EncryptValue, pkcs7Pad
internal/vault/testsupport.go       # EncryptForTest delegates to EncryptValue
internal/surface/surface.go         # CookieSurface + SecretSurface + KeyProvider
internal/surface/secretdir.go       # SecretDir (SecretSurface)
internal/surface/chromestore.go     # ChromeStore (CookieSurface)
internal/sink/sink.go               # Server: CookieSurfaces + SecretSurfaces, wire.Payload
internal/source/source.go           # Syncer: + Secrets readers, wire.Payload, prevSecrets
internal/config/config.go           # + SecretsDir field
cmd/agentpantry/main.go             # wire secrets + surface builder
test/integration_test.go            # + secret e2e + chrome-store e2e
README.md / CHANGELOG.md            # docs
```

---

### Task 1: secret model and diff

**Files:** Create `internal/secret/model.go`, `internal/secret/diff.go`; Test `internal/secret/secret_test.go`

- [ ] **Step 1: Write the failing test**

`internal/secret/secret_test.go`:
```go
package secret

import "testing"

func TestDiffFromUpsertsAndDeletes(t *testing.T) {
	prev := NewSnapshot([]Secret{{Name: "gh", Value: "1"}, {Name: "npm", Value: "2"}})
	cur := NewSnapshot([]Secret{{Name: "gh", Value: "CHANGED"}, {Name: "aws", Value: "3"}})
	d := cur.DiffFrom(prev)
	if len(d.Upserts) != 2 {
		t.Fatalf("want 2 upserts, got %d", len(d.Upserts))
	}
	if len(d.Deletes) != 1 || d.Deletes[0] != "npm" {
		t.Fatalf("want delete npm, got %v", d.Deletes)
	}
}

func TestIsEmpty(t *testing.T) {
	if !(Diff{}).IsEmpty() {
		t.Fatal("zero diff must be empty")
	}
}
```

- [ ] **Step 2: Run, verify it fails**

Run: `go test ./internal/secret/`
Expected: FAIL `undefined: NewSnapshot`.

- [ ] **Step 3: Implement**

`internal/secret/model.go`:
```go
package secret

// Secret is a named secret value carried separately from cookies.
type Secret struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Key identifies a secret by name.
func Key(s Secret) string { return s.Name }

// Snapshot is the set of secrets at one point in time, keyed by Name.
type Snapshot struct {
	Secrets map[string]Secret
}

// NewSnapshot builds a Snapshot from a slice.
func NewSnapshot(ss []Secret) Snapshot {
	m := make(map[string]Secret, len(ss))
	for _, s := range ss {
		m[Key(s)] = s
	}
	return Snapshot{Secrets: m}
}
```

`internal/secret/diff.go`:
```go
package secret

// Diff describes the change from a previous snapshot to the current one.
type Diff struct {
	Upserts []Secret `json:"upserts"`
	Deletes []string `json:"deletes"` // Names
}

// IsEmpty reports whether the diff carries no changes.
func (d Diff) IsEmpty() bool {
	return len(d.Upserts) == 0 && len(d.Deletes) == 0
}

// DiffFrom returns the changes needed to turn prev into s.
func (s Snapshot) DiffFrom(prev Snapshot) Diff {
	var d Diff
	for k, v := range s.Secrets {
		old, ok := prev.Secrets[k]
		if !ok || old != v {
			d.Upserts = append(d.Upserts, v)
		}
	}
	for k := range prev.Secrets {
		if _, ok := s.Secrets[k]; !ok {
			d.Deletes = append(d.Deletes, k)
		}
	}
	return d
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/secret/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/secret/
git commit -m "feat: add secret model and diff"
```

---

### Task 2: wire Payload envelope

**Files:** Create `internal/wire/wire.go`; Test `internal/wire/wire_test.go`

- [ ] **Step 1: Failing test**

`internal/wire/wire_test.go`:
```go
package wire

import (
	"encoding/json"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func TestPayloadRoundTripAndEmpty(t *testing.T) {
	p := Payload{
		Cookies: cookie.Diff{Upserts: []cookie.Cookie{{Host: "a.com", Name: "x", Path: "/", Value: "v"}}},
		Secrets: secret.Diff{Upserts: []secret.Secret{{Name: "gh", Value: "tok"}}},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got Payload
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Cookies.Upserts[0].Value != "v" || got.Secrets.Upserts[0].Value != "tok" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if (Payload{}).IsEmpty() != true {
		t.Fatal("zero payload must be empty")
	}
	if p.IsEmpty() {
		t.Fatal("populated payload must not be empty")
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/wire/`
Expected: FAIL `undefined: Payload`.

- [ ] **Step 3: Implement**

`internal/wire/wire.go`:
```go
package wire

import (
	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// Payload is the single envelope carried inside each transport frame.
type Payload struct {
	Cookies cookie.Diff `json:"cookies"`
	Secrets secret.Diff `json:"secrets"`
}

// IsEmpty reports whether neither diff carries changes.
func (p Payload) IsEmpty() bool {
	return p.Cookies.IsEmpty() && p.Secrets.IsEmpty()
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/wire/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wire/
git commit -m "feat: add wire payload envelope for cookies and secrets"
```

---

### Task 3: vault EncryptValue (inverse of DecryptValue)

**Files:** Modify `internal/vault/chrome_crypto.go`, `internal/vault/testsupport.go`; Test `internal/vault/chrome_crypto_test.go`

- [ ] **Step 1: Add failing test**

Append to `internal/vault/chrome_crypto_test.go`:
```go
func TestEncryptValueRoundTripsWithDecrypt(t *testing.T) {
	enc, err := EncryptValue("session-token-xyz", "keyring-pass")
	if err != nil {
		t.Fatal(err)
	}
	if string(enc[:3]) != "v11" {
		t.Fatalf("want v11 prefix, got %q", string(enc[:3]))
	}
	got, err := DecryptValue(enc, "keyring-pass")
	if err != nil {
		t.Fatal(err)
	}
	if got != "session-token-xyz" {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestEncryptForTestStillMatchesDecrypt(t *testing.T) {
	// v10 fixture path must still decrypt under peanuts.
	enc := EncryptForTest("v10", "peanuts", "abc")
	got, err := DecryptValue(enc, "ignored")
	if err != nil || got != "abc" {
		t.Fatalf("v10 fixture broke: got %q err %v", got, err)
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/vault/ -run Encrypt`
Expected: FAIL `undefined: EncryptValue`.

- [ ] **Step 3: Implement EncryptValue and reimplement EncryptForTest**

Append to `internal/vault/chrome_crypto.go`:
```go
func pkcs7Pad(b []byte) []byte {
	pad := 16 - len(b)%16
	return append(b, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

// EncryptValue produces a v11-prefixed AES-128-CBC ciphertext for a Chromium
// Linux store, using keyringPass. It is the inverse of DecryptValue for v11.
func EncryptValue(plaintext, keyringPass string) ([]byte, error) {
	block, err := aes.NewCipher(deriveKey(keyringPass))
	if err != nil {
		return nil, err
	}
	iv := bytes.Repeat([]byte{' '}, 16)
	padded := pkcs7Pad([]byte(plaintext))
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append([]byte("v11"), ct...), nil
}
```

Replace the body of `internal/vault/testsupport.go` so `EncryptForTest` delegates to the production code path (keep the exported signature `EncryptForTest(prefix, passphrase, value string) []byte`):
```go
package vault

// EncryptForTest mirrors Chromium's Linux scheme so other packages' tests can
// build fixtures. It delegates the crypto to EncryptValue and only swaps the
// 3-byte prefix; v10 fixtures derive their key from the fixed "peanuts" pass.
func EncryptForTest(prefix, passphrase, value string) []byte {
	pass := passphrase
	if prefix == "v10" {
		pass = "peanuts"
	}
	enc, err := EncryptValue(value, pass)
	if err != nil {
		panic(err)
	}
	out := append([]byte(prefix), enc[3:]...)
	return out
}
```
Remove the now-unused imports from `testsupport.go` (it no longer needs `bytes`, `crypto/aes`, `crypto/cipher`, `crypto/sha1`, `pbkdf2`).

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/vault/`
Expected: PASS (including the pre-existing decrypt and skip-row tests).

- [ ] **Step 5: Commit**

```bash
git add internal/vault/chrome_crypto.go internal/vault/testsupport.go internal/vault/chrome_crypto_test.go
git commit -m "feat: add chromium value encryption inverse of decrypt"
```

---

### Task 4: secrets directory reader (source)

**Files:** Create `internal/secretsrc/secretsrc.go`; Test `internal/secretsrc/secretsrc_test.go`

- [ ] **Step 1: Failing test**

`internal/secretsrc/secretsrc_test.go`:
```go
package secretsrc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDirReaderReadsFilesSkipsDirsAndDotfiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "gh_token"), []byte("ghp_abc"), 0o600)
	os.WriteFile(filepath.Join(dir, ".hidden"), []byte("nope"), 0o600)
	os.MkdirAll(filepath.Join(dir, "subdir"), 0o700)

	r := &DirReader{Dir: dir}
	secs, err := r.ReadSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(secs) != 1 {
		t.Fatalf("want 1 secret, got %d (%+v)", len(secs), secs)
	}
	if secs[0].Name != "gh_token" || secs[0].Value != "ghp_abc" {
		t.Fatalf("unexpected secret: %+v", secs[0])
	}
}

func TestDirReaderMissingDirIsEmpty(t *testing.T) {
	r := &DirReader{Dir: filepath.Join(t.TempDir(), "nope")}
	secs, err := r.ReadSecrets(context.Background())
	if err != nil || len(secs) != 0 {
		t.Fatalf("missing dir should yield no secrets and no error, got %v / %d", err, len(secs))
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/secretsrc/`
Expected: FAIL `undefined: DirReader`.

- [ ] **Step 3: Implement**

`internal/secretsrc/secretsrc.go`:
```go
package secretsrc

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// DirReader reads each regular file in Dir as one secret (name=file, value=contents).
type DirReader struct {
	Dir string
}

func (r *DirReader) ReadSecrets(ctx context.Context) ([]secret.Secret, error) {
	entries, err := os.ReadDir(r.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []secret.Secret
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(r.Dir, name))
		if err != nil {
			return nil, err
		}
		out = append(out, secret.Secret{Name: name, Value: string(data)})
	}
	return out, nil
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/secretsrc/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/secretsrc/
git commit -m "feat: add secrets directory reader for source"
```

---

### Task 5: surface interfaces + SecretDir surface

**Files:** Modify `internal/surface/surface.go`; Create `internal/surface/secretdir.go`; Test `internal/surface/secretdir_test.go`

- [ ] **Step 1: Failing test**

`internal/surface/secretdir_test.go`:
```go
package surface

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func TestSecretDirWriteDeleteAndPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	s, err := NewSecretDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "gh", Value: "tok"}}}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "gh")
	data, err := os.ReadFile(p)
	if err != nil || string(data) != "tok" {
		t.Fatalf("secret not written: %v / %q", err, data)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file must be 0600, got %v", info.Mode().Perm())
	}
	if err := s.ApplySecrets(secret.Diff{Deletes: []string{"gh"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("secret file should be deleted")
	}
}

func TestSecretDirRejectsUnsafeNames(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	s, _ := NewSecretDir(dir)
	// traversal attempt must be skipped, not written outside the dir.
	err := s.ApplySecrets(secret.Diff{Upserts: []secret.Secret{
		{Name: "../evil", Value: "x"},
		{Name: "a/b", Value: "y"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil")); !os.IsNotExist(err) {
		t.Fatal("traversal escaped the secrets dir")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("no unsafe-named secrets should be written, found %d", len(entries))
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/surface/ -run SecretDir`
Expected: FAIL `undefined: NewSecretDir`.

- [ ] **Step 3: Implement**

Replace `internal/surface/surface.go` with:
```go
package surface

import (
	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// CookieSurface is a sink-side destination for synced cookies.
type CookieSurface interface {
	Apply(d cookie.Diff) error
}

// SecretSurface is a sink-side destination for synced secrets.
type SecretSurface interface {
	ApplySecrets(d secret.Diff) error
}

// KeyProvider supplies a keyring passphrase (used by ChromeStore).
type KeyProvider interface {
	Passphrase() (string, error)
}
```

`internal/surface/secretdir.go`:
```go
package surface

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// SecretDir writes secrets as 0600 files under Dir.
type SecretDir struct {
	Dir string
}

func NewSecretDir(dir string) (*SecretDir, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &SecretDir{Dir: dir}, nil
}

// safeName accepts only a single, non-dotdot path element.
func safeName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if filepath.IsAbs(name) {
		return false
	}
	if strings.ContainsRune(name, '/') || strings.ContainsRune(name, os.PathSeparator) {
		return false
	}
	return name == filepath.Base(name)
}

func (s *SecretDir) ApplySecrets(d secret.Diff) error {
	skipped := 0
	for _, sec := range d.Upserts {
		if !safeName(sec.Name) {
			skipped++
			continue
		}
		if err := os.WriteFile(filepath.Join(s.Dir, sec.Name), []byte(sec.Value), 0o600); err != nil {
			return err
		}
	}
	for _, name := range d.Deletes {
		if !safeName(name) {
			skipped++
			continue
		}
		if err := os.Remove(filepath.Join(s.Dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "agentpantry: skipped %d secret(s) with unsafe names\n", skipped)
	}
	return nil
}
```

Note: `Sidecar.Apply` already satisfies `CookieSurface` (its method set is unchanged), so renaming the interface does not require touching `sidecar.go`.

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/surface/`
Expected: PASS (sidecar tests still pass under the renamed interface).

- [ ] **Step 5: Commit**

```bash
git add internal/surface/surface.go internal/surface/secretdir.go internal/surface/secretdir_test.go
git commit -m "feat: split cookie/secret surfaces and add secret dir surface"
```

---

### Task 6: ChromeStore real-Chrome surface

**Files:** Create `internal/surface/chromestore.go`; Test `internal/surface/chromestore_test.go`

- [ ] **Step 1: Failing test**

`internal/surface/chromestore_test.go`:
```go
package surface

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/vault"
	_ "modernc.org/sqlite"
)

type fakeKP struct{ p string }

func (k fakeKP) Passphrase() (string, error) { return k.p, nil }

// makeChromeDB creates a modern Chrome-schema cookies table.
func makeChromeDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE cookies(
		creation_utc INTEGER NOT NULL,
		host_key TEXT NOT NULL,
		top_frame_site_key TEXT NOT NULL,
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		encrypted_value BLOB NOT NULL,
		path TEXT NOT NULL,
		expires_utc INTEGER NOT NULL,
		is_secure INTEGER NOT NULL,
		is_httponly INTEGER NOT NULL,
		last_access_utc INTEGER NOT NULL,
		has_expires INTEGER NOT NULL,
		is_persistent INTEGER NOT NULL,
		priority INTEGER NOT NULL,
		samesite INTEGER NOT NULL,
		source_scheme INTEGER NOT NULL,
		source_port INTEGER NOT NULL,
		last_update_utc INTEGER NOT NULL,
		source_type INTEGER NOT NULL DEFAULT 0,
		has_cross_site_ancestor INTEGER NOT NULL DEFAULT 0,
		UNIQUE(host_key, top_frame_site_key, name, path, source_scheme, source_port))`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestChromeStoreWriteThenDecrypt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies")
	makeChromeDB(t, path)

	cs, err := NewChromeStore(path, fakeKP{"sink-keyring"})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	c := cookie.Cookie{Host: "github.com", Name: "sid", Path: "/", Value: "real-session", IsSecure: true, IsHTTPOnly: true, ExpiresUTC: 13300000000000000}
	if err := cs.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}

	// Read encrypted_value back and decrypt with the sink key.
	db, _ := sql.Open("sqlite", path)
	defer db.Close()
	var enc []byte
	var emptyVal string
	err = db.QueryRow(`SELECT value, encrypted_value FROM cookies WHERE host_key=? AND name=? AND path=?`,
		"github.com", "sid", "/").Scan(&emptyVal, &enc)
	if err != nil {
		t.Fatalf("row not written: %v", err)
	}
	if emptyVal != "" {
		t.Fatalf("plaintext value column should be empty, got %q", emptyVal)
	}
	got, err := vault.DecryptValue(enc, "sink-keyring")
	if err != nil || got != "real-session" {
		t.Fatalf("re-encrypt round trip failed: got %q err %v", got, err)
	}

	// Delete removes it.
	if err := cs.Apply(cookie.Diff{Deletes: []string{cookie.Key(c)}}); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM cookies WHERE host_key=?`, "github.com").Scan(&n)
	if n != 0 {
		t.Fatalf("delete failed, %d rows remain", n)
	}
}

func TestChromeStoreMissingDBErrors(t *testing.T) {
	_, err := NewChromeStore(filepath.Join(t.TempDir(), "nope", "Cookies"), fakeKP{"k"})
	if err == nil {
		t.Fatal("missing chrome store must error")
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/surface/ -run ChromeStore`
Expected: FAIL `undefined: NewChromeStore`.

- [ ] **Step 3: Implement**

`internal/surface/chromestore.go`:
```go
package surface

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/vault"
	_ "modernc.org/sqlite"
)

var chromeWarnOnce sync.Once

// ChromeStore re-encrypts cookies with the sink's keyring key and writes them
// into an existing Chrome-schema Cookies SQLite. Targets a not-running profile.
type ChromeStore struct {
	db      *sql.DB
	keyPass string
	cols    map[string]string // present column name -> upper-cased declared type
}

func NewChromeStore(cookiePath string, kp KeyProvider) (*ChromeStore, error) {
	if _, err := os.Stat(cookiePath); err != nil {
		return nil, fmt.Errorf("chrome cookie store not found at %s: %w", cookiePath, err)
	}
	warnIfChromeRunning(cookiePath)

	pass, err := kp.Passphrase()
	if err != nil {
		return nil, err
	}
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
	return &ChromeStore{db: db, keyPass: pass, cols: cols}, nil
}

func (s *ChromeStore) Close() error { return s.db.Close() }

func introspectCookieColumns(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`PRAGMA table_info(cookies)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]string{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = strings.ToUpper(ctype)
	}
	return cols, rows.Err()
}

func (s *ChromeStore) mappedValues(c cookie.Cookie) (map[string]interface{}, error) {
	enc, err := vault.EncryptValue(c.Value, s.keyPass)
	if err != nil {
		return nil, err
	}
	persistent := 0
	if c.ExpiresUTC > 0 {
		persistent = 1
	}
	return map[string]interface{}{
		"host_key":                c.Host,
		"name":                    c.Name,
		"value":                   "",
		"encrypted_value":         enc,
		"path":                    c.Path,
		"expires_utc":             c.ExpiresUTC,
		"is_secure":               b2i(c.IsSecure),
		"is_httponly":             b2i(c.IsHTTPOnly),
		"samesite":                c.SameSite,
		"has_expires":             persistent,
		"is_persistent":           persistent,
		"creation_utc":            int64(0),
		"last_access_utc":         int64(0),
		"last_update_utc":         int64(0),
		"priority":                1,
		"source_scheme":           2,
		"source_port":             -1,
		"top_frame_site_key":      "",
		"source_type":             0,
		"has_cross_site_ancestor": 0,
	}, nil
}

func zeroForType(t string) interface{} {
	switch {
	case strings.Contains(t, "INT"):
		return 0
	case strings.Contains(t, "BLOB"):
		return []byte{}
	default:
		return ""
	}
}

func (s *ChromeStore) Apply(d cookie.Diff) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, c := range d.Upserts {
		mapped, err := s.mappedValues(c)
		if err != nil {
			return err
		}
		var colNames, placeholders []string
		var args []interface{}
		for col, typ := range s.cols {
			colNames = append(colNames, col)
			placeholders = append(placeholders, "?")
			if v, ok := mapped[col]; ok {
				args = append(args, v)
			} else {
				args = append(args, zeroForType(typ))
			}
		}
		q := fmt.Sprintf("INSERT OR REPLACE INTO cookies(%s) VALUES(%s)",
			strings.Join(colNames, ","), strings.Join(placeholders, ","))
		if _, err := tx.Exec(q, args...); err != nil {
			return err
		}
	}
	for _, k := range d.Deletes {
		host, name, path := keyParts(k)
		if _, err := tx.Exec(`DELETE FROM cookies WHERE host_key=? AND name=? AND path=?`, host, name, path); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// warnIfChromeRunning logs once if a SingletonLock suggests Chrome is live.
func warnIfChromeRunning(cookiePath string) {
	dir := filepath.Dir(cookiePath)
	for _, c := range []string{
		filepath.Join(dir, "SingletonLock"),
		filepath.Join(filepath.Dir(dir), "SingletonLock"),
	} {
		if _, err := os.Lstat(c); err == nil {
			chromeWarnOnce.Do(func() {
				fmt.Fprintln(os.Stderr, "agentpantry: a Chrome SingletonLock is present; the target profile may be running. Writing a live profile is unsupported and Chrome may ignore or overwrite these cookies.")
			})
			return
		}
	}
}
```

Note: `b2i` and `keyParts` already exist in `sidecar.go` in package `surface`; reuse them, do not redefine.

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/surface/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/surface/chromestore.go internal/surface/chromestore_test.go
git commit -m "feat: add real-chrome re-encrypt cookie surface"
```

---

### Task 7: sink Server routes wire.Payload to both surface kinds

**Files:** Modify `internal/sink/sink.go`; Modify `internal/sink/sink_test.go`

- [ ] **Step 1: Update the test to the new shape (write failing test)**

Replace `internal/sink/sink_test.go` with:
```go
package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

type capCookie struct{ applied []cookie.Diff }

func (c *capCookie) Apply(d cookie.Diff) error { c.applied = append(c.applied, d); return nil }

type capSecret struct{ applied []secret.Diff }

func (c *capSecret) ApplySecrets(d secret.Diff) error { c.applied = append(c.applied, d); return nil }

func TestServeRoutesPayloadToBothSurfaces(t *testing.T) {
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key)
	var w bytes.Buffer

	p := wire.Payload{
		Cookies: cookie.Diff{Upserts: []cookie.Cookie{{Host: "a.com", Name: "x", Path: "/", Value: "1"}}},
		Secrets: secret.Diff{Upserts: []secret.Secret{{Name: "gh", Value: "tok"}}},
	}
	b, _ := json.Marshal(p)
	frame, _ := sealer.Seal(b)
	transport.WriteFrame(&w, frame)

	opener, _ := transport.NewOpener(key)
	cc := &capCookie{}
	ss := &capSecret{}
	srv := &Server{Opener: opener, CookieSurfaces: []CookieSurface{cc}, SecretSurfaces: []SecretSurface{ss}}

	if err := srv.Serve(context.Background(), &w); err != nil {
		t.Fatal(err)
	}
	if len(cc.applied) != 1 || len(cc.applied[0].Upserts) != 1 {
		t.Fatalf("cookie surface not called: %+v", cc.applied)
	}
	if len(ss.applied) != 1 || len(ss.applied[0].Upserts) != 1 {
		t.Fatalf("secret surface not called: %+v", ss.applied)
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/sink/`
Expected: FAIL (compile error: `Server` has no `CookieSurfaces`, undefined `SecretSurface`).

- [ ] **Step 3: Implement**

Replace `internal/sink/sink.go` with:
```go
package sink

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

// CookieSurface is a sink-side destination for synced cookies.
type CookieSurface interface {
	Apply(d cookie.Diff) error
}

// SecretSurface is a sink-side destination for synced secrets.
type SecretSurface interface {
	ApplySecrets(d secret.Diff) error
}

// Server opens frames from a stream and routes payloads to surfaces.
type Server struct {
	Opener         *transport.Opener
	CookieSurfaces []CookieSurface
	SecretSurfaces []SecretSurface
}

// Serve reads frames until EOF, routing each payload to all surfaces.
func (s *Server) Serve(ctx context.Context, r io.Reader) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		frame, err := transport.ReadFrame(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		raw, err := s.Opener.Open(frame)
		if err != nil {
			return err
		}
		var p wire.Payload
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		if !p.Cookies.IsEmpty() {
			for _, cs := range s.CookieSurfaces {
				if err := cs.Apply(p.Cookies); err != nil {
					return err
				}
			}
		}
		if !p.Secrets.IsEmpty() {
			for _, ss := range s.SecretSurfaces {
				if err := ss.ApplySecrets(p.Secrets); err != nil {
					return err
				}
			}
		}
	}
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/sink/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sink/sink.go internal/sink/sink_test.go
git commit -m "feat: route wire payload to cookie and secret surfaces in sink"
```

---

### Task 8: source Syncer packs wire.Payload with secrets

**Files:** Modify `internal/source/source.go`; Modify `internal/source/source_test.go`; Modify `internal/source/watch_test.go`

- [ ] **Step 1: Update tests to the new wire format (write failing tests)**

Replace `internal/source/source_test.go` with:
```go
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

type fakeVault struct{ cs []cookie.Cookie }

func (f fakeVault) ReadCookies(context.Context) ([]cookie.Cookie, error) { return f.cs, nil }

type fakeSecrets struct{ ss []secret.Secret }

func (f fakeSecrets) ReadSecrets(context.Context) ([]secret.Secret, error) { return f.ss, nil }

func decodePayload(t *testing.T, buf *bytes.Buffer) wire.Payload {
	t.Helper()
	frame, err := transport.ReadFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	opener, _ := transport.NewOpener(make([]byte, 32))
	raw, err := opener.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	var p wire.Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSyncOnceFiltersCookiesAndCarriesSecrets(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	syncer := &Syncer{
		Vaults: []CookieReader{fakeVault{cs: []cookie.Cookie{
			{Host: "github.com", Name: "sid", Path: "/", Value: "keep"},
			{Host: "bank.com", Name: "t", Path: "/", Value: "drop"},
		}}},
		Secrets: []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "gh", Value: "tok"}}}},
		Policy:  policy.Domain{Allow: []string{"github.com"}},
		Sealer:  sealer,
		Out:     &buf,
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := decodePayload(t, &buf)
	if len(p.Cookies.Upserts) != 1 || p.Cookies.Upserts[0].Host != "github.com" {
		t.Fatalf("cookie filter failed: %+v", p.Cookies.Upserts)
	}
	if len(p.Secrets.Upserts) != 1 || p.Secrets.Upserts[0].Name != "gh" {
		t.Fatalf("secret not carried: %+v", p.Secrets.Upserts)
	}
}

func TestSyncOnceNoChangeSendsNothing(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	syncer := &Syncer{
		Vaults: []CookieReader{fakeVault{cs: []cookie.Cookie{{Host: "github.com", Name: "s", Path: "/", Value: "v"}}}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := buf.Len()
	if first == 0 {
		t.Fatal("first sync should send")
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != first {
		t.Fatalf("unchanged state must not resend")
	}
}
```

In `internal/source/watch_test.go`, the `countingVault` already satisfies `CookieReader`; no secret reader is needed there. Leave it, but if it references removed types, update the `Syncer` literal to keep only `Vaults`, `Policy`, `Sealer`, `Out` (all still valid). No change should be required.

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/source/`
Expected: FAIL (undefined `SecretReader`, `Syncer` has no `Secrets`).

- [ ] **Step 3: Implement**

Edit `internal/source/source.go`:

Update imports to add `secret` and `wire`, drop nothing:
```go
import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)
```

Add the SecretReader interface and extend Syncer:
```go
// SecretReader yields the current secrets from one source.
type SecretReader interface {
	ReadSecrets(ctx context.Context) ([]secret.Secret, error)
}

// Syncer turns successive vault and secret reads into sealed payload frames.
type Syncer struct {
	Vaults  []CookieReader
	Secrets []SecretReader
	Policy  policy.Domain
	Sealer  *transport.Sealer
	Out     io.Writer

	prev        cookie.Snapshot
	prevSecrets secret.Snapshot
}
```

Replace `SyncOnce` with:
```go
func (s *Syncer) SyncOnce(ctx context.Context) error {
	var allCookies []cookie.Cookie
	for _, v := range s.Vaults {
		cs, err := v.ReadCookies(ctx)
		if err != nil {
			return err
		}
		for _, c := range cs {
			if s.Policy.Permit(c.Host) {
				allCookies = append(allCookies, c)
			}
		}
	}
	curCookies := cookie.NewSnapshot(allCookies)
	cookieDiff := curCookies.DiffFrom(s.prev)

	var allSecrets []secret.Secret
	for _, r := range s.Secrets {
		ss, err := r.ReadSecrets(ctx)
		if err != nil {
			return err
		}
		allSecrets = append(allSecrets, ss...)
	}
	curSecrets := secret.NewSnapshot(allSecrets)
	secretDiff := curSecrets.DiffFrom(s.prevSecrets)

	s.prev = curCookies
	s.prevSecrets = curSecrets

	p := wire.Payload{Cookies: cookieDiff, Secrets: secretDiff}
	if p.IsEmpty() {
		return nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	frame, err := s.Sealer.Seal(raw)
	if err != nil {
		return err
	}
	return transport.WriteFrame(s.Out, frame)
}
```

`Watch` is unchanged.

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/source/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/source/source.go internal/source/source_test.go internal/source/watch_test.go
git commit -m "feat: pack cookies and secrets into wire payload on source"
```

---

### Task 9: config SecretsDir field

**Files:** Modify `internal/config/config.go`; Modify `internal/config/config_test.go`

- [ ] **Step 1: Add failing test**

Append to `internal/config/config_test.go`:
```go
func TestSecretsDirRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("source")
	in.SecretsDir = "/etc/agentpantry/secrets"
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.SecretsDir != in.SecretsDir {
		t.Fatalf("secrets dir lost: %q", out.SecretsDir)
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/config/ -run SecretsDir`
Expected: FAIL `in.SecretsDir undefined`.

- [ ] **Step 3: Implement**

In `internal/config/config.go`, add the field to `Config` (after `Browsers`):
```go
	Browsers   []BrowserRef  `toml:"browsers"`
	SecretsDir string        `toml:"secrets_dir"` // source: read from; sink: write to
	Domains    policy.Domain `toml:"domains"`
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/config/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add secrets_dir config field"
```

---

### Task 10: CLI wiring for secrets and surfaces

**Files:** Modify `cmd/agentpantry/main.go`

This is integration glue, verified by build + the integration test in Task 11. No new unit test.

- [ ] **Step 1: Update imports**

Ensure `cmd/agentpantry/main.go` imports include:
```go
	"github.com/escoffier-labs/agentpantry/internal/secretsrc"
```
(alongside the existing config, keyfile, service, sink, source, surface, transport, vault imports).

- [ ] **Step 2: Wire secrets into cmdSource**

In `cmdSource`, after `vs, paths, err := buildVaults(c)` and before constructing the `Syncer`, add:
```go
	var secretReaders []source.SecretReader
	if c.SecretsDir != "" {
		secretReaders = append(secretReaders, &secretsrc.DirReader{Dir: c.SecretsDir})
		if _, statErr := os.Stat(c.SecretsDir); statErr == nil {
			paths = append(paths, c.SecretsDir)
		}
	}
```
and set the new field on the Syncer literal:
```go
	syncer := &source.Syncer{
		Vaults:  vs,
		Secrets: secretReaders,
		Policy:  c.Domains,
		Sealer:  sealer,
		Out:     conn,
	}
```

- [ ] **Step 3: Replace cmdSink surface construction**

Replace the body of `cmdSink` that builds the single sidecar surface and the accept loop with a surface builder plus per-connection opener. The full new `cmdSink`:
```go
func cmdSink(args []string) error {
	c, err := loadConfig(args)
	if err != nil {
		return err
	}
	key, err := keyfile.Load(c.KeyPath)
	if err != nil {
		return err
	}

	var cookieSurfaces []sink.CookieSurface
	var secretSurfaces []sink.SecretSurface
	var closers []func() error

	for _, name := range c.Surfaces {
		switch name {
		case "sidecar":
			sc, err := surface.NewSidecar(filepath.Join(config.Dir(), "sidecar.db"))
			if err != nil {
				return err
			}
			cookieSurfaces = append(cookieSurfaces, sc)
			closers = append(closers, sc.Close)
		case "chrome":
			if len(c.Browsers) == 0 {
				return fmt.Errorf("chrome surface requires a [[browsers]] entry with cookie_path")
			}
			cs, err := surface.NewChromeStore(c.Browsers[0].CookiePath, &vault.SecretServiceKey{Label: "Chrome Safe Storage"})
			if err != nil {
				return err
			}
			cookieSurfaces = append(cookieSurfaces, cs)
			closers = append(closers, cs.Close)
		case "secrets":
			if c.SecretsDir == "" {
				return fmt.Errorf("secrets surface requires secrets_dir in config")
			}
			sd, err := surface.NewSecretDir(c.SecretsDir)
			if err != nil {
				return err
			}
			secretSurfaces = append(secretSurfaces, sd)
		default:
			return fmt.Errorf("unknown surface %q", name)
		}
	}
	defer func() {
		for _, cl := range closers {
			cl()
		}
	}()

	ln, err := net.Listen("tcp", c.Peer)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("sink: listening on %s, surfaces %v\n", c.Peer, c.Surfaces)

	ctx := signalCtx()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// Fresh opener per connection so a reconnecting source (whose Sealer
		// counter restarts at 1) is not rejected as a replay.
		opener, oerr := transport.NewOpener(key)
		if oerr != nil {
			conn.Close()
			return oerr
		}
		srv := &sink.Server{Opener: opener, CookieSurfaces: cookieSurfaces, SecretSurfaces: secretSurfaces}
		if err := srv.Serve(ctx, conn); err != nil {
			fmt.Fprintln(os.Stderr, "connection ended:", err)
		}
		conn.Close()
	}
}
```

- [ ] **Step 4: Build, vet, smoke test**

Run:
```bash
go build ./... && go vet ./...
export XDG_CONFIG_HOME=$(mktemp -d)
go run ./cmd/agentpantry init --role sink
go run ./cmd/agentpantry status
```
Expected: build/vet clean; status prints role sink, surfaces `[sidecar]`.

- [ ] **Step 5: Commit**

```bash
git add cmd/agentpantry/main.go
git commit -m "feat: wire secrets reader and chrome/secrets surfaces into cli"
```

---

### Task 11: Phase 2 end-to-end integration tests

**Files:** Modify `test/integration_test.go` (add two tests; keep the existing Phase 1 test but update it to the wire.Payload format)

- [ ] **Step 1: Update the existing e2e test and add Phase 2 e2e tests**

The existing `TestEndToEndSourceToSink` builds a `sink.Server{... Surfaces: ...}`; update it to `CookieSurfaces`. Then add a secret e2e and a chrome-store e2e. Add to `test/integration_test.go`:

First, fix the existing sink construction in `TestEndToEndSourceToSink`:
```go
	srv := &sink.Server{Opener: opener, CookieSurfaces: []sink.CookieSurface{sc}}
```
(the `sc` sidecar and the rest of that test are unchanged; it still asserts the github cookie lands and bank.com does not).

Then append:
```go
func TestEndToEndSecret(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src-secrets")
	sinkDir := filepath.Join(dir, "sink-secrets")
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "gh_token"), []byte("ghp_live"), 0o600); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key)
	opener, _ := transport.NewOpener(key)
	sd, err := surface.NewSecretDir(sinkDir)
	if err != nil {
		t.Fatal(err)
	}

	pr, pw := newPipe()
	syncer := &source.Syncer{
		Secrets: []source.SecretReader{&secretsrc.DirReader{Dir: srcDir}},
		Sealer:  sealer,
		Out:     pw,
	}
	srv := &sink.Server{Opener: opener, SecretSurfaces: []sink.SecretSurface{sd}}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), pr) }()
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(sinkDir, "gh_token"))
	if err != nil || string(got) != "ghp_live" {
		t.Fatalf("secret did not sync: %v / %q", err, got)
	}
}

func TestEndToEndChromeStore(t *testing.T) {
	dir := t.TempDir()
	chromePath := filepath.Join(dir, "Cookies")
	makeSinkChromeDB(t, chromePath)

	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key)
	opener, _ := transport.NewOpener(key)

	cs, err := surface.NewChromeStore(chromePath, sinkKP{"sink-key"})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	pr, pw := newPipe()
	syncer := &source.Syncer{
		Vaults: []source.CookieReader{fixedCookie{c: cookie.Cookie{
			Host: "github.com", Name: "sid", Path: "/", Value: "real-session", IsSecure: true,
		}}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    pw,
	}
	srv := &sink.Server{Opener: opener, CookieSurfaces: []sink.CookieSurface{cs}}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), pr) }()
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	db, _ := sql.Open("sqlite", chromePath)
	defer db.Close()
	var enc []byte
	if err := db.QueryRow(`SELECT encrypted_value FROM cookies WHERE host_key=?`, "github.com").Scan(&enc); err != nil {
		t.Fatalf("cookie not written to chrome store: %v", err)
	}
	got, err := vault.DecryptValue(enc, "sink-key")
	if err != nil || got != "real-session" {
		t.Fatalf("chrome re-encrypt failed: %q / %v", got, err)
	}
}

type sinkKP struct{ p string }

func (k sinkKP) Passphrase() (string, error) { return k.p, nil }

type fixedCookie struct{ c cookie.Cookie }

func (f fixedCookie) ReadCookies(context.Context) ([]cookie.Cookie, error) {
	return []cookie.Cookie{f.c}, nil
}

func makeSinkChromeDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE cookies(
		creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL,
		name TEXT NOT NULL, value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL,
		expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL,
		last_access_utc INTEGER NOT NULL, has_expires INTEGER NOT NULL, is_persistent INTEGER NOT NULL,
		priority INTEGER NOT NULL, samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL,
		source_port INTEGER NOT NULL, last_update_utc INTEGER NOT NULL,
		UNIQUE(host_key, top_frame_site_key, name, path, source_scheme, source_port))`)
	if err != nil {
		t.Fatal(err)
	}
}
```

Update the import block of `test/integration_test.go` to include `os`, `github.com/escoffier-labs/agentpantry/internal/secretsrc`, and `github.com/escoffier-labs/agentpantry/internal/secret` if not already present (it already imports cookie, policy, sink, source, surface, transport, vault, sql, filepath, context, testing).

- [ ] **Step 2: Run, verify (fails before Tasks 1-10 land, passes after)**

Run: `go test ./test/`
Expected: PASS once all prior tasks are implemented.

- [ ] **Step 3: Run the whole suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all PASS, vet clean.

- [ ] **Step 4: Commit**

```bash
git add test/integration_test.go
git commit -m "test: add end-to-end secret and chrome-store integration tests"
```

---

### Task 12: docs and changelog

**Files:** Modify `README.md`; Create `CHANGELOG.md`

- [ ] **Step 1: Update README**

Add a "Surfaces" subsection documenting the three sink surfaces (sidecar always-on; chrome opt-in and fragile, targets a not-running profile; secrets writes a 0600 secrets dir) and a "Secrets" subsection (source `secrets_dir` -> sink `secrets_dir`, one file per secret, names sanitized). Update the Status section to note Phase 2 (secrets bus + real-Chrome surface) is shipped. No em dashes, no machine hostnames, no `localhost` or private IPs in examples (use loopback `127.0.0.1` only, which is allowed, or a hostname like `sink.example`).

- [ ] **Step 2: Create CHANGELOG.md**

```markdown
# Changelog

## Unreleased

### Added
- Secrets bus: sync a secrets directory from source to sink (one file per secret), with strict secret-name sanitization on the sink.
- Real-Chrome re-encrypt surface: the sink can write synced cookies into an existing Chrome Cookies SQLite, re-encrypted with the sink's own keyring key. Schema is introspected so it tolerates Chrome version differences. Targets a not-running profile.
- `wire.Payload` envelope carrying cookies and secrets in one encrypted frame.
- `secrets_dir` config field and `chrome` / `secrets` sink surfaces.

## v0.1.0

### Added
- Linux Chromium cookie sync (source) to a plaintext sidecar SQLite (sink).
- Transport-agnostic AES-256-GCM framed push with replay protection.
- Opt-in domain allow/deny policy.
- systemd user unit generation.
```

- [ ] **Step 3: Verify build and tests green**

Run: `go build ./... && go test ./...`
Expected: exit 0, all PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: document secrets bus and chrome surface, add changelog"
```

---

## Self-Review Notes

- **Spec coverage:** §2 wire payload -> Task 2 (+ wiring in 7,8); §3 secret model -> Task 1; §4 source (secret reader + Syncer) -> Tasks 4,8; §5 surfaces (split + secretdir) -> Tasks 5,7; §6 Chrome encrypt + ChromeStore -> Tasks 3,6; §7 config -> Task 9; §8 CLI -> Task 10; §9 security (0600, name sanitization, no value logs) -> Tasks 5,6; §10 testing -> every task + Task 11. P3-P5 out of scope.
- **Type consistency:** `secret.Secret/Snapshot/Diff/NewSnapshot/Key/DiffFrom/IsEmpty` defined Task 1, used in 2,4,5,7,8,11. `wire.Payload`/`IsEmpty` defined Task 2, used 7,8,11. `vault.EncryptValue` defined Task 3, used 6,11. `surface.CookieSurface/SecretSurface/KeyProvider` defined Task 5; `sink.CookieSurface/SecretSurface` defined Task 7 (intentionally identical method sets so the same concrete surfaces satisfy both). `source.CookieReader` (Phase 1, exported) reused; `source.SecretReader` defined Task 8. `b2i`/`keyParts` reused from sidecar.go, not redefined (Task 6 note).
- **Wire-format break is intentional:** Tasks 7 and 8 change the frame contents from bare `cookie.Diff` to `wire.Payload`; both ends and the integration test (Task 11) are updated together, so there is no mixed-version window within this plan.
- **Existing tests updated, not duplicated:** sink_test (Task 7), source_test (Task 8), and integration_test (Task 11) are rewritten to the new shapes; watch_test needs no change.
- **No placeholders:** every code step contains complete code; Task 12 is the only prose task and enumerates required sections.
