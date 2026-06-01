# agentpantry Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship agentpantry v0.1: a Linux source daemon that watches Chromium cookies, decrypts them, filters by domain policy, and pushes encrypted deltas over a transport-agnostic AES-256-GCM link to a Linux sink that writes them into a plaintext sidecar SQLite, with a systemd user unit and an end-to-end loopback test.

**Architecture:** One Go binary, role chosen by subcommand. A `BrowserVault` reads and decrypts Chromium cookies on the source. A normalized cookie `Snapshot` is diffed against the previous snapshot, filtered by a domain allow/deny policy, JSON-serialized, sealed in AES-256-GCM frames (with a monotonic replay counter), and written length-prefixed over a stream (TCP or stdio). The sink opens frames and applies the diff to pluggable `Surface` writers; Phase 1 ships the plaintext sidecar surface.

**Tech Stack:** Go 1.22, `modernc.org/sqlite` (pure-Go SQLite, no cgo), `golang.org/x/crypto/pbkdf2`, `github.com/godbus/dbus/v5` (Secret Service), `github.com/BurntSushi/toml`, `github.com/fsnotify/fsnotify`, stdlib `crypto/aes`+`crypto/cipher`+`flag`.

---

## File Structure

```
agentpantry/
  go.mod
  cmd/agentpantry/main.go              # CLI subcommand dispatch
  internal/cookie/model.go             # Cookie, Snapshot, Key()
  internal/cookie/diff.go              # Diff, Snapshot.DiffFrom()
  internal/policy/domain.go            # Domain.Permit()
  internal/transport/envelope.go       # Sealer/Opener (AES-256-GCM + replay)
  internal/transport/frame.go          # WriteFrame/ReadFrame (length-prefixed)
  internal/vault/vault.go              # BrowserVault interface, KeyProvider
  internal/vault/chrome_crypto.go      # DecryptValue (v10/v11 AES-128-CBC)
  internal/vault/linux_chromium.go     # LinuxChromium vault: ReadCookies
  internal/vault/secretservice.go      # D-Bus Secret Service KeyProvider + peanuts fallback
  internal/surface/surface.go          # Surface interface
  internal/surface/sidecar.go          # plaintext sidecar SQLite writer
  internal/config/config.go            # TOML config load/save + defaults
  internal/keyfile/keyfile.go          # PSK generate/load (0600)
  internal/source/source.go            # SyncOnce + Watch loop
  internal/sink/sink.go                # Serve loop
  internal/service/systemd.go          # systemd user unit generation
  test/integration_test.go             # source -> sink loopback
```

Each `internal` package has one responsibility and a small surface so it can be tested in isolation.

---

### Task 1: Initialize Go module and skeleton

**Files:**
- Create: `go.mod`
- Create: `cmd/agentpantry/main.go`

- [ ] **Step 1: Initialize the module and add dependencies**

Run:
```bash
cd ~/repos/agentpantry
go mod init github.com/solomonneas/agentpantry
go get modernc.org/sqlite@latest
go get golang.org/x/crypto/pbkdf2@latest
go get github.com/godbus/dbus/v5@latest
go get github.com/BurntSushi/toml@latest
go get github.com/fsnotify/fsnotify@latest
```
Expected: `go.mod` and `go.sum` created with the five dependencies.

- [ ] **Step 2: Create a minimal main that compiles**

`cmd/agentpantry/main.go`:
```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agentpantry <command>")
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
	os.Exit(2)
}
```

- [ ] **Step 3: Verify it builds**

Run: `go build ./...`
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum cmd/agentpantry/main.go
git commit -m "chore: initialize go module and skeleton"
```

---

### Task 2: Cookie model and key

**Files:**
- Create: `internal/cookie/model.go`
- Test: `internal/cookie/model_test.go`

- [ ] **Step 1: Write the failing test**

`internal/cookie/model_test.go`:
```go
package cookie

import "testing"

func TestKeyIsStableAndUnique(t *testing.T) {
	a := Cookie{Host: "example.com", Name: "sid", Path: "/"}
	b := Cookie{Host: "example.com", Name: "sid", Path: "/"}
	c := Cookie{Host: "example.com", Name: "sid", Path: "/app"}

	if Key(a) != Key(b) {
		t.Fatalf("identical cookies must share a key: %q vs %q", Key(a), Key(b))
	}
	if Key(a) == Key(c) {
		t.Fatalf("different path must change key")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cookie/`
Expected: FAIL, `undefined: Cookie` / `undefined: Key`.

- [ ] **Step 3: Write minimal implementation**

`internal/cookie/model.go`:
```go
package cookie

// Cookie is the normalized, decrypted form that crosses the vault boundary.
type Cookie struct {
	Host       string `json:"host"`
	Name       string `json:"name"`
	Value      string `json:"value"`
	Path       string `json:"path"`
	ExpiresUTC int64  `json:"expires_utc"`
	IsSecure   bool   `json:"is_secure"`
	IsHTTPOnly bool   `json:"is_httponly"`
	SameSite   int    `json:"samesite"`
}

// Key uniquely identifies a cookie slot by host, name, and path.
func Key(c Cookie) string {
	return c.Host + "\x00" + c.Name + "\x00" + c.Path
}

// Snapshot is the set of cookies observed at one point in time, keyed by Key.
type Snapshot struct {
	Cookies map[string]Cookie
}

// NewSnapshot builds a Snapshot from a slice of cookies.
func NewSnapshot(cs []Cookie) Snapshot {
	m := make(map[string]Cookie, len(cs))
	for _, c := range cs {
		m[Key(c)] = c
	}
	return Snapshot{Cookies: m}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cookie/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cookie/model.go internal/cookie/model_test.go
git commit -m "feat: add normalized cookie model and snapshot"
```

---

### Task 3: Snapshot diff

**Files:**
- Create: `internal/cookie/diff.go`
- Test: `internal/cookie/diff_test.go`

- [ ] **Step 1: Write the failing test**

`internal/cookie/diff_test.go`:
```go
package cookie

import "testing"

func TestDiffFromDetectsUpsertsAndDeletes(t *testing.T) {
	prev := NewSnapshot([]Cookie{
		{Host: "a.com", Name: "x", Path: "/", Value: "1"},
		{Host: "b.com", Name: "y", Path: "/", Value: "2"},
	})
	cur := NewSnapshot([]Cookie{
		{Host: "a.com", Name: "x", Path: "/", Value: "CHANGED"}, // upsert (value changed)
		{Host: "c.com", Name: "z", Path: "/", Value: "3"},       // upsert (new)
		// b.com/y removed -> delete
	})

	d := cur.DiffFrom(prev)

	if len(d.Upserts) != 2 {
		t.Fatalf("want 2 upserts, got %d", len(d.Upserts))
	}
	if len(d.Deletes) != 1 || d.Deletes[0] != Key(Cookie{Host: "b.com", Name: "y", Path: "/"}) {
		t.Fatalf("want delete of b.com/y, got %v", d.Deletes)
	}
}

func TestDiffFromNilPrevTreatsAllAsUpserts(t *testing.T) {
	cur := NewSnapshot([]Cookie{{Host: "a.com", Name: "x", Path: "/"}})
	d := cur.DiffFrom(Snapshot{})
	if len(d.Upserts) != 1 || len(d.Deletes) != 0 {
		t.Fatalf("want 1 upsert 0 deletes, got %d/%d", len(d.Upserts), len(d.Deletes))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cookie/`
Expected: FAIL, `cur.DiffFrom undefined`.

- [ ] **Step 3: Write minimal implementation**

`internal/cookie/diff.go`:
```go
package cookie

// Diff describes the change from a previous snapshot to the current one.
type Diff struct {
	Upserts []Cookie `json:"upserts"`
	Deletes []string `json:"deletes"` // Key() values
}

// IsEmpty reports whether the diff carries no changes.
func (d Diff) IsEmpty() bool {
	return len(d.Upserts) == 0 && len(d.Deletes) == 0
}

// DiffFrom returns the changes needed to turn prev into s.
func (s Snapshot) DiffFrom(prev Snapshot) Diff {
	var d Diff
	for k, c := range s.Cookies {
		old, ok := prev.Cookies[k]
		if !ok || old != c {
			d.Upserts = append(d.Upserts, c)
		}
	}
	for k := range prev.Cookies {
		if _, ok := s.Cookies[k]; !ok {
			d.Deletes = append(d.Deletes, k)
		}
	}
	return d
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cookie/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cookie/diff.go internal/cookie/diff_test.go
git commit -m "feat: add snapshot diff with upserts and deletes"
```

---

### Task 4: Domain policy

**Files:**
- Create: `internal/policy/domain.go`
- Test: `internal/policy/domain_test.go`

Rule: deny wins over allow. A host matches an entry if it equals the entry or is a subdomain of it (suffix match on a dot boundary). An empty allow list permits nothing (opt-in per domain, per spec).

- [ ] **Step 1: Write the failing test**

`internal/policy/domain_test.go`:
```go
package policy

import "testing"

func TestPermit(t *testing.T) {
	d := Domain{
		Allow: []string{"github.com", "example.com"},
		Deny:  []string{"secret.example.com"},
	}
	cases := map[string]bool{
		"github.com":        true,
		"api.github.com":    true,  // subdomain of allowed
		"example.com":       true,
		"secret.example.com": false, // denied explicitly
		"bank.com":          false, // not in allow
		"notgithub.com":     false, // not a dot-boundary subdomain
	}
	for host, want := range cases {
		if got := d.Permit(host); got != want {
			t.Errorf("Permit(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestEmptyAllowPermitsNothing(t *testing.T) {
	if (Domain{}).Permit("github.com") {
		t.Fatal("empty allow list must permit nothing")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/`
Expected: FAIL, `undefined: Domain`.

- [ ] **Step 3: Write minimal implementation**

`internal/policy/domain.go`:
```go
package policy

import "strings"

// Domain is an allow/deny policy over cookie host names.
type Domain struct {
	Allow []string `toml:"allow"`
	Deny  []string `toml:"deny"`
}

func matches(host, entry string) bool {
	host = strings.TrimPrefix(host, ".")
	entry = strings.TrimPrefix(entry, ".")
	if host == entry {
		return true
	}
	return strings.HasSuffix(host, "."+entry)
}

func anyMatch(host string, entries []string) bool {
	for _, e := range entries {
		if matches(host, e) {
			return true
		}
	}
	return false
}

// Permit reports whether cookies for host may sync. Deny overrides Allow.
func (d Domain) Permit(host string) bool {
	if anyMatch(host, d.Deny) {
		return false
	}
	return anyMatch(host, d.Allow)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/domain.go internal/policy/domain_test.go
git commit -m "feat: add opt-in domain allow/deny policy"
```

---

### Task 5: Transport envelope (AES-256-GCM + replay)

**Files:**
- Create: `internal/transport/envelope.go`
- Test: `internal/transport/envelope_test.go`

Frame layout: `counter(8 bytes, big-endian) || nonce(12 bytes) || ciphertext`. The counter is bound as AEAD additional data so it cannot be altered. The Opener rejects any frame whose counter is not strictly greater than the last accepted one.

- [ ] **Step 1: Write the failing test**

`internal/transport/envelope_test.go`:
```go
package transport

import (
	"bytes"
	"testing"
)

func key32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := NewSealer(key32())
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewOpener(key32())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello cookies")
	frame, err := s.Seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := o.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, msg) {
		t.Fatalf("round trip mismatch: %q", out)
	}
}

func TestOpenRejectsReplay(t *testing.T) {
	s, _ := NewSealer(key32())
	o, _ := NewOpener(key32())
	f1, _ := s.Seal([]byte("one"))
	if _, err := o.Open(f1); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Open(f1); err == nil {
		t.Fatal("replayed frame must be rejected")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	s, _ := NewSealer(key32())
	bad := key32()
	bad[0] ^= 0xff
	o, _ := NewOpener(bad)
	f, _ := s.Seal([]byte("secret"))
	if _, err := o.Open(f); err == nil {
		t.Fatal("frame under wrong key must fail authentication")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/transport/`
Expected: FAIL, `undefined: NewSealer`.

- [ ] **Step 3: Write minimal implementation**

`internal/transport/envelope.go`:
```go
package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const counterLen = 8

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Sealer encrypts outbound frames with a monotonically increasing counter.
type Sealer struct {
	aead    cipher.AEAD
	counter uint64
}

func NewSealer(key []byte) (*Sealer, error) {
	a, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: a}, nil
}

// Seal produces counter || nonce || ciphertext.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	s.counter++
	hdr := make([]byte, counterLen)
	binary.BigEndian.PutUint64(hdr, s.counter)

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := s.aead.Seal(nil, nonce, plaintext, hdr)

	frame := make([]byte, 0, counterLen+len(nonce)+len(ct))
	frame = append(frame, hdr...)
	frame = append(frame, nonce...)
	frame = append(frame, ct...)
	return frame, nil
}

// Opener decrypts inbound frames and rejects replays.
type Opener struct {
	aead        cipher.AEAD
	lastCounter uint64
}

func NewOpener(key []byte) (*Opener, error) {
	a, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Opener{aead: a}, nil
}

func (o *Opener) Open(frame []byte) ([]byte, error) {
	ns := o.aead.NonceSize()
	if len(frame) < counterLen+ns {
		return nil, errors.New("frame too short")
	}
	hdr := frame[:counterLen]
	nonce := frame[counterLen : counterLen+ns]
	ct := frame[counterLen+ns:]

	counter := binary.BigEndian.Uint64(hdr)
	if counter <= o.lastCounter {
		return nil, fmt.Errorf("replay detected: counter %d <= last %d", counter, o.lastCounter)
	}
	pt, err := o.aead.Open(nil, nonce, ct, hdr)
	if err != nil {
		return nil, err
	}
	o.lastCounter = counter
	return pt, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/transport/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/transport/envelope.go internal/transport/envelope_test.go
git commit -m "feat: add AES-256-GCM transport envelope with replay protection"
```

---

### Task 6: Length-prefixed framing over a stream

**Files:**
- Create: `internal/transport/frame.go`
- Test: `internal/transport/frame_test.go`

- [ ] **Step 1: Write the failing test**

`internal/transport/frame_test.go`:
```go
package transport

import (
	"bytes"
	"testing"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := [][]byte{[]byte("alpha"), []byte("beta"), {}}
	for _, f := range want {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatal(err)
		}
	}
	for i, w := range want {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, w) {
			t.Fatalf("frame %d: got %q want %q", i, got, w)
		}
	}
}

func TestReadFrameRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	// length prefix claiming 5 GiB
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("oversized frame must be rejected")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/transport/ -run Frame`
Expected: FAIL, `undefined: WriteFrame`.

- [ ] **Step 3: Write minimal implementation**

`internal/transport/frame.go`:
```go
package transport

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxFrame caps a single frame to guard against malicious length prefixes.
const maxFrame = 64 << 20 // 64 MiB

// WriteFrame writes a uint32 big-endian length prefix then the payload.
func WriteFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed payload.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, fmt.Errorf("frame size %d exceeds max %d", n, maxFrame)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/transport/`
Expected: PASS (all transport tests).

- [ ] **Step 5: Commit**

```bash
git add internal/transport/frame.go internal/transport/frame_test.go
git commit -m "feat: add length-prefixed stream framing"
```

---

### Task 7: Chromium value decryption (v10/v11)

**Files:**
- Create: `internal/vault/chrome_crypto.go`
- Test: `internal/vault/chrome_crypto_test.go`

Linux Chromium encrypts values as `"v10"|"v11" + AES-128-CBC(value)`. Key = PBKDF2-SHA1(passphrase, salt `"saltysalt"`, iterations 1, length 16). IV = 16 space bytes. v10 always uses passphrase `"peanuts"`; v11 uses the keyring passphrase. Unprefixed values are already plaintext.

- [ ] **Step 1: Write the failing test**

`internal/vault/chrome_crypto_test.go`:
```go
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// encryptChrome mirrors Chromium's Linux scheme, for test fixtures only.
func encryptChrome(prefix, passphrase, value string) []byte {
	key := pbkdf2.Key([]byte(passphrase), []byte("saltysalt"), 1, 16, sha1.New)
	block, _ := aes.NewCipher(key)
	iv := bytes.Repeat([]byte{' '}, 16)
	pad := 16 - len(value)%16
	padded := append([]byte(value), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append([]byte(prefix), ct...)
}

func TestDecryptValueV11(t *testing.T) {
	enc := encryptChrome("v11", "keyring-pass", "session-token-123")
	got, err := DecryptValue(enc, "keyring-pass")
	if err != nil {
		t.Fatal(err)
	}
	if got != "session-token-123" {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptValueV10UsesPeanuts(t *testing.T) {
	enc := encryptChrome("v10", "peanuts", "abc")
	got, err := DecryptValue(enc, "ignored-for-v10")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptValuePlaintextPassthrough(t *testing.T) {
	got, err := DecryptValue([]byte("plainvalue"), "x")
	if err != nil {
		t.Fatal(err)
	}
	if got != "plainvalue" {
		t.Fatalf("got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run DecryptValue`
Expected: FAIL, `undefined: DecryptValue`.

- [ ] **Step 3: Write minimal implementation**

`internal/vault/chrome_crypto.go`:
```go
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

func deriveKey(passphrase string) []byte {
	return pbkdf2.Key([]byte(passphrase), []byte("saltysalt"), 1, 16, sha1.New)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%16 != 0 {
		return nil, errors.New("invalid padded length")
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > 16 || pad > len(b) {
		return nil, errors.New("invalid pkcs7 padding")
	}
	return b[:len(b)-pad], nil
}

// DecryptValue decrypts a Chromium Linux encrypted_value. v10 uses the fixed
// "peanuts" passphrase; v11 uses keyringPass. Unprefixed input is plaintext.
func DecryptValue(enc []byte, keyringPass string) (string, error) {
	if len(enc) < 3 {
		return string(enc), nil
	}
	prefix := string(enc[:3])
	var passphrase string
	switch prefix {
	case "v10":
		passphrase = "peanuts"
	case "v11":
		passphrase = keyringPass
	default:
		return string(enc), nil // not encrypted
	}

	ct := enc[3:]
	if len(ct) == 0 || len(ct)%16 != 0 {
		return "", errors.New("ciphertext not a multiple of block size")
	}
	block, err := aes.NewCipher(deriveKey(passphrase))
	if err != nil {
		return "", err
	}
	iv := bytes.Repeat([]byte{' '}, 16)
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	pt, err = pkcs7Unpad(pt)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vault/ -run DecryptValue`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/chrome_crypto.go internal/vault/chrome_crypto_test.go
git commit -m "feat: decrypt chromium linux v10/v11 cookie values"
```

---

### Task 8: BrowserVault interface and LinuxChromium reader

**Files:**
- Create: `internal/vault/vault.go`
- Create: `internal/vault/linux_chromium.go`
- Test: `internal/vault/linux_chromium_test.go`

The vault copies the `Cookies` SQLite to a temp file (to avoid lock contention), reads the `cookies` table, and decrypts each `encrypted_value`. A `KeyProvider` supplies the v11 passphrase so the reader is testable without a keyring.

- [ ] **Step 1: Write the failing test**

`internal/vault/linux_chromium_test.go`:
```go
package vault

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

type staticKey struct{ pass string }

func (s staticKey) Passphrase() (string, error) { return s.pass, nil }

// writeFakeChromeDB creates a minimal Chromium cookies DB with one encrypted row.
func writeFakeChromeDB(t *testing.T, dir, pass string) string {
	t.Helper()
	path := filepath.Join(dir, "Cookies")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE cookies(
		host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB,
		path TEXT, expires_utc INTEGER, is_secure INTEGER,
		is_httponly INTEGER, samesite INTEGER)`)
	if err != nil {
		t.Fatal(err)
	}
	enc := encryptChrome("v11", pass, "tok-abc")
	_, err = db.Exec(`INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?)`,
		"example.com", "sid", "", enc, "/", int64(0), 1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLinuxChromiumReadCookies(t *testing.T) {
	dir := t.TempDir()
	writeFakeChromeDB(t, dir, "keyring-pass")

	v := &LinuxChromium{
		Profile:     "test",
		CookiePath:  filepath.Join(dir, "Cookies"),
		KeyProvider: staticKey{"keyring-pass"},
	}
	cs, err := v.ReadCookies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cs))
	}
	got := cs[0]
	if got.Host != "example.com" || got.Name != "sid" || got.Value != "tok-abc" {
		t.Fatalf("unexpected cookie: %+v", got)
	}
	if !got.IsSecure || !got.IsHTTPOnly {
		t.Fatalf("flags not parsed: %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run LinuxChromiumReadCookies`
Expected: FAIL, `undefined: LinuxChromium`.

- [ ] **Step 3: Write minimal implementation**

`internal/vault/vault.go`:
```go
package vault

import (
	"context"

	"github.com/solomonneas/agentpantry/internal/cookie"
)

// KeyProvider supplies the v11 keyring passphrase for a browser.
type KeyProvider interface {
	Passphrase() (string, error)
}

// BrowserVault reads and decrypts cookies from one browser profile.
type BrowserVault interface {
	Name() string
	ReadCookies(ctx context.Context) ([]cookie.Cookie, error)
}
```

`internal/vault/linux_chromium.go`:
```go
package vault

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/solomonneas/agentpantry/internal/cookie"
	_ "modernc.org/sqlite"
)

// LinuxChromium reads a Chromium-family cookie store on Linux.
type LinuxChromium struct {
	Profile     string
	CookiePath  string
	KeyProvider KeyProvider
}

func (v *LinuxChromium) Name() string { return "chromium:" + v.Profile }

// copyToTemp copies the (possibly locked) cookie DB to a temp file.
func copyToTemp(src string) (string, func(), error) {
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "agentpantry-cookies-*.db")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	cleanup := func() { os.Remove(tmp.Name()) }
	return tmp.Name(), cleanup, nil
}

func (v *LinuxChromium) ReadCookies(ctx context.Context) ([]cookie.Cookie, error) {
	pass, err := v.KeyProvider.Passphrase()
	if err != nil {
		return nil, fmt.Errorf("keyring passphrase: %w", err)
	}
	tmp, cleanup, err := copyToTemp(v.CookiePath)
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
	for rows.Next() {
		var (
			host, name, plain, path  string
			enc                      []byte
			expires                  int64
			secure, httpOnly, samesite int
		)
		if err := rows.Scan(&host, &name, &plain, &enc, &path, &expires, &secure, &httpOnly, &samesite); err != nil {
			return nil, err
		}
		value := plain
		if len(enc) > 0 {
			value, err = DecryptValue(enc, pass)
			if err != nil {
				return nil, fmt.Errorf("decrypt %s/%s: %w", host, name, err)
			}
		}
		out = append(out, cookie.Cookie{
			Host: host, Name: name, Value: value, Path: path,
			ExpiresUTC: expires, IsSecure: secure != 0,
			IsHTTPOnly: httpOnly != 0, SameSite: samesite,
		})
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vault/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/vault.go internal/vault/linux_chromium.go internal/vault/linux_chromium_test.go
git commit -m "feat: add browservault interface and linux chromium reader"
```

---

### Task 9: Secret Service key provider with peanuts fallback

**Files:**
- Create: `internal/vault/secretservice.go`
- Test: `internal/vault/secretservice_test.go`

The real key provider queries the Secret Service over D-Bus for the "Chrome Safe Storage" secret. When no session bus or no entry is available, it falls back to the fixed `"peanuts"` passphrase (Chromium's no-keyring default).

- [ ] **Step 1: Write the failing test**

`internal/vault/secretservice_test.go`:
```go
package vault

import "testing"

func TestPeanutsFallback(t *testing.T) {
	p := &SecretServiceKey{Label: "Chrome Safe Storage", fetch: func(string) (string, error) {
		return "", errNoSecret
	}}
	got, err := p.Passphrase()
	if err != nil {
		t.Fatal(err)
	}
	if got != "peanuts" {
		t.Fatalf("want peanuts fallback, got %q", got)
	}
}

func TestSecretServiceReturnsFoundSecret(t *testing.T) {
	p := &SecretServiceKey{Label: "Chrome Safe Storage", fetch: func(string) (string, error) {
		return "real-keyring-secret", nil
	}}
	got, err := p.Passphrase()
	if err != nil {
		t.Fatal(err)
	}
	if got != "real-keyring-secret" {
		t.Fatalf("got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run Secret`
Expected: FAIL, `undefined: SecretServiceKey`.

- [ ] **Step 3: Write minimal implementation**

`internal/vault/secretservice.go`:
```go
package vault

import (
	"errors"

	"github.com/godbus/dbus/v5"
)

var errNoSecret = errors.New("secret not found")

// SecretServiceKey fetches the browser keyring passphrase via the freedesktop
// Secret Service, falling back to "peanuts" when unavailable.
type SecretServiceKey struct {
	Label string
	// fetch is injectable for testing; nil means use the real D-Bus lookup.
	fetch func(label string) (string, error)
}

func (k *SecretServiceKey) Passphrase() (string, error) {
	f := k.fetch
	if f == nil {
		f = dbusFetch
	}
	secret, err := f(k.Label)
	if err != nil {
		if errors.Is(err, errNoSecret) {
			return "peanuts", nil
		}
		return "", err
	}
	if secret == "" {
		return "peanuts", nil
	}
	return secret, nil
}

// dbusFetch searches the Secret Service for a stored item whose label matches.
func dbusFetch(label string) (string, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return "", errNoSecret
	}
	svc := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")

	var unlocked, locked []dbus.ObjectPath
	call := svc.Call("org.freedesktop.Secret.Service.SearchItems", 0,
		map[string]string{"application": "chrome", "xdg:schema": "chrome_libsecret_os_crypt_password_v2"})
	if call.Err != nil {
		return "", errNoSecret
	}
	if err := call.Store(&unlocked, &locked); err != nil {
		return "", errNoSecret
	}
	if len(unlocked) == 0 {
		return "", errNoSecret
	}

	// Open a session for plain (unencrypted) secret transfer.
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := svc.Call("org.freedesktop.Secret.Service.OpenSession", 0,
		"plain", dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return "", errNoSecret
	}

	item := conn.Object("org.freedesktop.secrets", unlocked[0])
	var secret struct {
		Session     dbus.ObjectPath
		Parameters  []byte
		Value       []byte
		ContentType string
	}
	if err := item.Call("org.freedesktop.Secret.Item.GetSecret", 0, session).Store(&secret); err != nil {
		return "", errNoSecret
	}
	return string(secret.Value), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vault/`
Expected: PASS. (The D-Bus path is not exercised by tests; only the fallback logic is.)

- [ ] **Step 5: Commit**

```bash
git add internal/vault/secretservice.go internal/vault/secretservice_test.go
git commit -m "feat: add secret service key provider with peanuts fallback"
```

---

### Task 10: Sidecar surface writer

**Files:**
- Create: `internal/surface/surface.go`
- Create: `internal/surface/sidecar.go`
- Test: `internal/surface/sidecar_test.go`

The sidecar writes the cleartext cookie set into its own SQLite at `0600`. `Apply` upserts and deletes per the diff.

- [ ] **Step 1: Write the failing test**

`internal/surface/sidecar_test.go`:
```go
package surface

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/solomonneas/agentpantry/internal/cookie"
	_ "modernc.org/sqlite"
)

func countRows(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cookies`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSidecarApplyUpsertThenDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sidecar.db")
	s, err := NewSidecar(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c := cookie.Cookie{Host: "a.com", Name: "x", Path: "/", Value: "1", IsSecure: true}
	if err := s.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, path); n != 1 {
		t.Fatalf("after upsert want 1 row, got %d", n)
	}

	// Re-upsert same key with new value must not duplicate.
	c.Value = "2"
	if err := s.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, path); n != 1 {
		t.Fatalf("after re-upsert want 1 row, got %d", n)
	}

	if err := s.Apply(cookie.Diff{Deletes: []string{cookie.Key(c)}}); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, path); n != 0 {
		t.Fatalf("after delete want 0 rows, got %d", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/surface/`
Expected: FAIL, `undefined: NewSidecar`.

- [ ] **Step 3: Write minimal implementation**

`internal/surface/surface.go`:
```go
package surface

import "github.com/solomonneas/agentpantry/internal/cookie"

// Surface is a sink-side destination for synced cookies.
type Surface interface {
	Apply(d cookie.Diff) error
}
```

`internal/surface/sidecar.go`:
```go
package surface

import (
	"database/sql"
	"os"
	"strings"

	"github.com/solomonneas/agentpantry/internal/cookie"
	_ "modernc.org/sqlite"
)

// Sidecar is a plaintext SQLite surface, written 0600.
type Sidecar struct {
	db *sql.DB
}

func NewSidecar(path string) (*Sidecar, error) {
	// Ensure the file exists with 0600 before the driver opens it.
	f, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cookies(
		host TEXT, name TEXT, path TEXT, value TEXT,
		expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER,
		PRIMARY KEY(host, name, path))`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Sidecar{db: db}, nil
}

func (s *Sidecar) Close() error { return s.db.Close() }

// keyParts splits a cookie.Key() back into host, name, path.
func keyParts(k string) (host, name, path string) {
	p := strings.SplitN(k, "\x00", 3)
	for len(p) < 3 {
		p = append(p, "")
	}
	return p[0], p[1], p[2]
}

func (s *Sidecar) Apply(d cookie.Diff) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, c := range d.Upserts {
		_, err = tx.Exec(`INSERT INTO cookies(host,name,path,value,expires_utc,is_secure,is_httponly,samesite)
			VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(host,name,path) DO UPDATE SET
				value=excluded.value, expires_utc=excluded.expires_utc,
				is_secure=excluded.is_secure, is_httponly=excluded.is_httponly,
				samesite=excluded.samesite`,
			c.Host, c.Name, c.Path, c.Value, c.ExpiresUTC,
			b2i(c.IsSecure), b2i(c.IsHTTPOnly), c.SameSite)
		if err != nil {
			return err
		}
	}
	for _, k := range d.Deletes {
		host, name, path := keyParts(k)
		if _, err = tx.Exec(`DELETE FROM cookies WHERE host=? AND name=? AND path=?`, host, name, path); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/surface/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/surface/surface.go internal/surface/sidecar.go internal/surface/sidecar_test.go
git commit -m "feat: add plaintext sidecar surface"
```

---

### Task 11: Configuration load/save

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

`internal/config/config_test.go`:
```go
package config

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("source")
	in.Peer = "198.51.100.5:8787"
	in.Domains.Allow = []string{"github.com"}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Role != "source" || out.Peer != "198.51.100.5:8787" {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	if len(out.Domains.Allow) != 1 || out.Domains.Allow[0] != "github.com" {
		t.Fatalf("domains lost: %+v", out.Domains)
	}
}

func TestDefaultSinkBindsLoopback(t *testing.T) {
	c := Default("sink")
	if c.Peer != "127.0.0.1:8787" {
		t.Fatalf("sink default must bind loopback, got %q", c.Peer)
	}
	if len(c.Surfaces) != 1 || c.Surfaces[0] != "sidecar" {
		t.Fatalf("default surface must be sidecar, got %v", c.Surfaces)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/`
Expected: FAIL, `undefined: Default`.

- [ ] **Step 3: Write minimal implementation**

`internal/config/config.go`:
```go
package config

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/solomonneas/agentpantry/internal/policy"
)

// BrowserRef names a browser profile and its cookie store path.
type BrowserRef struct {
	Kind       string `toml:"kind"` // "chromium"
	Profile    string `toml:"profile"`
	CookiePath string `toml:"cookie_path"`
}

// Config is the on-disk configuration for either role.
type Config struct {
	Role     string        `toml:"role"` // "source" | "sink"
	Peer     string        `toml:"peer"` // dial target (source) or bind addr (sink)
	KeyPath  string        `toml:"key_path"`
	Surfaces []string      `toml:"surfaces"`
	Browsers []BrowserRef  `toml:"browsers"`
	Domains  policy.Domain `toml:"domains"`
}

// Dir returns the config directory, honoring XDG_CONFIG_HOME.
func Dir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "agentpantry")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "agentpantry")
}

// Default returns a config with safe defaults for the given role.
func Default(role string) Config {
	c := Config{
		Role:     role,
		KeyPath:  filepath.Join(Dir(), "psk.key"),
		Surfaces: []string{"sidecar"},
		Domains:  policy.Domain{},
	}
	if role == "sink" {
		c.Peer = "127.0.0.1:8787"
	} else {
		c.Peer = "127.0.0.1:8787"
	}
	return c
}

func Load(path string) (Config, error) {
	var c Config
	_, err := toml.DecodeFile(path, &c)
	return c, err
}

func Save(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(c)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add toml configuration with role defaults"
```

---

### Task 12: PSK keyfile generate/load

**Files:**
- Create: `internal/keyfile/keyfile.go`
- Test: `internal/keyfile/keyfile_test.go`

- [ ] **Step 1: Write the failing test**

`internal/keyfile/keyfile_test.go`:
```go
package keyfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateThenLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	if err := Generate(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file must be 0600, got %v", info.Mode().Perm())
	}
	key, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key must be 32 bytes, got %d", len(key))
	}
}

func TestLoadRejectsWrongLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	os.WriteFile(path, []byte("short"), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("must reject non-32-byte key")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keyfile/`
Expected: FAIL, `undefined: Generate`.

- [ ] **Step 3: Write minimal implementation**

`internal/keyfile/keyfile.go`:
```go
package keyfile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const keyLen = 32

// Generate writes a new random 32-byte key as hex to path with 0600.
func Generate(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600)
}

// Load reads and decodes the hex key, validating its length.
func Load(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("key not valid hex: %w", err)
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("key must be %d bytes, got %d", keyLen, len(key))
	}
	return key, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keyfile/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/keyfile/keyfile.go internal/keyfile/keyfile_test.go
git commit -m "feat: add psk keyfile generate and load"
```

---

### Task 13: Source SyncOnce (vault to wire)

**Files:**
- Create: `internal/source/source.go`
- Test: `internal/source/source_test.go`

`SyncOnce` reads all vaults, builds a snapshot, filters by domain policy, diffs against the previous snapshot held by the `Syncer`, seals the diff JSON, and writes one frame. It returns the new snapshot so the caller (or watch loop) carries state forward.

- [ ] **Step 1: Write the failing test**

`internal/source/source_test.go`:
```go
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/policy"
	"github.com/solomonneas/agentpantry/internal/transport"
)

type fakeVault struct{ cs []cookie.Cookie }

func (f fakeVault) Name() string { return "fake" }
func (f fakeVault) ReadCookies(context.Context) ([]cookie.Cookie, error) {
	return f.cs, nil
}

func TestSyncOnceFiltersAndSeals(t *testing.T) {
	vault := fakeVault{cs: []cookie.Cookie{
		{Host: "github.com", Name: "sid", Path: "/", Value: "keep"},
		{Host: "bank.com", Name: "tok", Path: "/", Value: "drop"},
	}}
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer

	syncer := &Syncer{
		Vaults: []interface{ ReadCookies(context.Context) ([]cookie.Cookie, error) }{vault},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
	}

	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Decode the single frame and confirm only github.com survived.
	frame, err := transport.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	opener, _ := transport.NewOpener(make([]byte, 32))
	payload, err := opener.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	var d cookie.Diff
	if err := json.Unmarshal(payload, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Upserts) != 1 || d.Upserts[0].Host != "github.com" {
		t.Fatalf("policy filter failed: %+v", d.Upserts)
	}
}

func TestSyncOnceNoChangeSendsNothing(t *testing.T) {
	vault := fakeVault{cs: []cookie.Cookie{{Host: "github.com", Name: "s", Path: "/", Value: "v"}}}
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	syncer := &Syncer{
		Vaults: []interface{ ReadCookies(context.Context) ([]cookie.Cookie, error) }{vault},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := buf.Len()
	if first == 0 {
		t.Fatal("first sync should send a frame")
	}
	// Second sync with identical state must add nothing.
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != first {
		t.Fatalf("unchanged state must not resend: grew by %d", buf.Len()-first)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/source/`
Expected: FAIL, `undefined: Syncer`.

- [ ] **Step 3: Write minimal implementation**

`internal/source/source.go`:
```go
package source

import (
	"context"
	"encoding/json"
	"io"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/policy"
	"github.com/solomonneas/agentpantry/internal/transport"
)

// cookieReader is the slice of BrowserVault that Syncer needs.
type cookieReader interface {
	ReadCookies(ctx context.Context) ([]cookie.Cookie, error)
}

// Syncer turns successive vault reads into sealed diff frames.
type Syncer struct {
	Vaults []cookieReader
	Policy policy.Domain
	Sealer *transport.Sealer
	Out    io.Writer

	prev cookie.Snapshot
}

// SyncOnce performs a single read-diff-send cycle.
func (s *Syncer) SyncOnce(ctx context.Context) error {
	var all []cookie.Cookie
	for _, v := range s.Vaults {
		cs, err := v.ReadCookies(ctx)
		if err != nil {
			return err
		}
		for _, c := range cs {
			if s.Policy.Permit(c.Host) {
				all = append(all, c)
			}
		}
	}
	cur := cookie.NewSnapshot(all)
	d := cur.DiffFrom(s.prev)
	s.prev = cur
	if d.IsEmpty() {
		return nil
	}
	payload, err := json.Marshal(d)
	if err != nil {
		return err
	}
	frame, err := s.Sealer.Seal(payload)
	if err != nil {
		return err
	}
	return transport.WriteFrame(s.Out, frame)
}
```

Note: the test constructs `Vaults` as `[]interface{ ReadCookies(...) }`; this matches the unexported `cookieReader` shape structurally, so assign through a local conversion in the test. If Go rejects the anonymous-interface assignment, change the test's slice type to `[]source.cookieReader` is not possible (unexported), so instead the test should build `[]cookieReader` indirectly. To keep the test compiling, export the interface as `CookieReader` and use `Vaults []CookieReader`. Apply that rename now: in `source.go` rename `cookieReader` to `CookieReader` (exported) and update the field type; in the test change the slice literal type to `[]source.CookieReader` is unnecessary because the test is in-package (`package source`), so use `[]CookieReader{vault}`.

Concretely, edit the test's two slice literals from
`[]interface{ ReadCookies(context.Context) ([]cookie.Cookie, error) }{vault}`
to
`[]CookieReader{vault}`
and rename the interface in `source.go` to `CookieReader`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/source/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/source/source.go internal/source/source_test.go
git commit -m "feat: add source syncer with policy filter and diff sealing"
```

---

### Task 14: Sink Serve loop (wire to surfaces)

**Files:**
- Create: `internal/sink/sink.go`
- Test: `internal/sink/sink_test.go`

`Serve` reads frames from an `io.Reader`, opens each, unmarshals the diff, and applies it to every configured surface. It returns when the reader hits EOF.

- [ ] **Step 1: Write the failing test**

`internal/sink/sink_test.go`:
```go
package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/transport"
)

type capturingSurface struct{ applied []cookie.Diff }

func (c *capturingSurface) Apply(d cookie.Diff) error {
	c.applied = append(c.applied, d)
	return nil
}

func TestServeAppliesFramesToSurfaces(t *testing.T) {
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key)
	var wire bytes.Buffer

	d := cookie.Diff{Upserts: []cookie.Cookie{{Host: "a.com", Name: "x", Path: "/", Value: "1"}}}
	payload, _ := json.Marshal(d)
	frame, _ := sealer.Seal(payload)
	transport.WriteFrame(&wire, frame)

	opener, _ := transport.NewOpener(key)
	surf := &capturingSurface{}
	srv := &Server{Opener: opener, Surfaces: []Surface{surf}}

	if err := srv.Serve(context.Background(), &wire); err != nil {
		t.Fatal(err)
	}
	if len(surf.applied) != 1 || len(surf.applied[0].Upserts) != 1 {
		t.Fatalf("surface did not receive the diff: %+v", surf.applied)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sink/`
Expected: FAIL, `undefined: Server`.

- [ ] **Step 3: Write minimal implementation**

`internal/sink/sink.go`:
```go
package sink

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/transport"
)

// Surface is the sink-side destination (matches surface.Surface).
type Surface interface {
	Apply(d cookie.Diff) error
}

// Server opens frames from a stream and applies them to surfaces.
type Server struct {
	Opener   *transport.Opener
	Surfaces []Surface
}

// Serve reads frames until EOF, applying each diff to all surfaces.
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
		payload, err := s.Opener.Open(frame)
		if err != nil {
			return err
		}
		var d cookie.Diff
		if err := json.Unmarshal(payload, &d); err != nil {
			return err
		}
		for _, surf := range s.Surfaces {
			if err := surf.Apply(d); err != nil {
				return err
			}
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sink/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sink/sink.go internal/sink/sink_test.go
git commit -m "feat: add sink serve loop applying frames to surfaces"
```

---

### Task 15: Source watch loop (fsnotify + debounce)

**Files:**
- Modify: `internal/source/source.go` (add `Watch`)
- Test: `internal/source/watch_test.go`

`Watch` runs `SyncOnce` once immediately, then again on each debounced filesystem event for the watched paths, until the context is cancelled.

- [ ] **Step 1: Write the failing test**

`internal/source/watch_test.go`:
```go
package source

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/policy"
	"github.com/solomonneas/agentpantry/internal/transport"
)

type countingVault struct {
	mu    sync.Mutex
	calls int
}

func (c *countingVault) ReadCookies(context.Context) ([]cookie.Cookie, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	// Return a changing value so each call produces a frame.
	return []cookie.Cookie{{Host: "github.com", Name: "s", Path: "/", Value: time.Now().String()}}, nil
}

func TestWatchSyncsOnEvent(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "Cookies")
	os.WriteFile(watched, []byte("init"), 0o600)

	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	v := &countingVault{}
	syncer := &Syncer{
		Vaults: []CookieReader{v},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- syncer.Watch(ctx, []string{watched}, 20*time.Millisecond) }()

	time.Sleep(50 * time.Millisecond)       // allow the initial sync
	os.WriteFile(watched, []byte("changed"), 0o600) // trigger an event
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatal(err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.calls < 2 {
		t.Fatalf("expected initial sync plus at least one event-driven sync, got %d", v.calls)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/source/ -run Watch`
Expected: FAIL, `syncer.Watch undefined`.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/source/source.go`:
```go
import (
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch runs an initial sync, then re-syncs on debounced events for paths.
func (s *Syncer) Watch(ctx context.Context, paths []string, debounce time.Duration) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	for _, p := range paths {
		if err := w.Add(p); err != nil {
			return err
		}
	}

	if err := s.SyncOnce(ctx); err != nil {
		return err
	}

	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-w.Events:
			if !ok {
				return nil
			}
			if timer == nil {
				timer = time.NewTimer(debounce)
				timerC = timer.C
			} else {
				timer.Reset(debounce)
			}
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			return err
		case <-timerC:
			if err := s.SyncOnce(ctx); err != nil {
				return err
			}
		}
	}
}
```

Merge the new `import` block into the existing one at the top of `source.go` rather than adding a second `import` statement.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/source/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/source/source.go internal/source/watch_test.go
git commit -m "feat: add debounced fsnotify watch loop to source"
```

---

### Task 16: systemd user unit generation

**Files:**
- Create: `internal/service/systemd.go`
- Test: `internal/service/systemd_test.go`

- [ ] **Step 1: Write the failing test**

`internal/service/systemd_test.go`:
```go
package service

import (
	"strings"
	"testing"
)

func TestSystemdUnitContents(t *testing.T) {
	unit := SystemdUnit("source", "/usr/local/bin/agentpantry", "/home/u/.config/agentpantry/config.toml")
	for _, want := range []string{
		"Description=agentpantry source",
		"ExecStart=/usr/local/bin/agentpantry source --config /home/u/.config/agentpantry/config.toml",
		"Restart=on-failure",
		"WantedBy=default.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q\n---\n%s", want, unit)
		}
	}
}

func TestUnitFileName(t *testing.T) {
	if got := UnitFileName("sink"); got != "agentpantry-sink.service" {
		t.Fatalf("got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/service/`
Expected: FAIL, `undefined: SystemdUnit`.

- [ ] **Step 3: Write minimal implementation**

`internal/service/systemd.go`:
```go
package service

import "fmt"

// UnitFileName returns the systemd user unit file name for a role.
func UnitFileName(role string) string {
	return "agentpantry-" + role + ".service"
}

// SystemdUnit renders a systemd user unit for the given role and paths.
func SystemdUnit(role, binPath, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=agentpantry %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s %s --config %s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, role, binPath, role, configPath)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/service/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/service/systemd.go internal/service/systemd_test.go
git commit -m "feat: generate systemd user unit for source and sink"
```

---

### Task 17: CLI wiring (init, keygen, source, sink, install-service, status)

**Files:**
- Modify: `cmd/agentpantry/main.go`

This task wires the packages into runnable commands. No new unit tests (it is glue exercised by the integration test in Task 18); verify by building and running `--help`-style invocations.

- [ ] **Step 1: Implement the dispatch and commands**

Replace `cmd/agentpantry/main.go` with:
```go
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/solomonneas/agentpantry/internal/config"
	"github.com/solomonneas/agentpantry/internal/keyfile"
	"github.com/solomonneas/agentpantry/internal/policy"
	"github.com/solomonneas/agentpantry/internal/service"
	"github.com/solomonneas/agentpantry/internal/sink"
	"github.com/solomonneas/agentpantry/internal/source"
	"github.com/solomonneas/agentpantry/internal/surface"
	"github.com/solomonneas/agentpantry/internal/transport"
	"github.com/solomonneas/agentpantry/internal/vault"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "keygen":
		err = cmdKeygen(args)
	case "source":
		err = cmdSource(args)
	case "sink":
		err = cmdSink(args)
	case "install-service":
		err = cmdInstallService(args)
	case "status":
		err = cmdStatus(args)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: agentpantry <init|keygen|source|sink|install-service|status> [flags]")
	os.Exit(2)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	role := fs.String("role", "source", "source or sink")
	out := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	fs.Parse(args)
	if *role != "source" && *role != "sink" {
		return fmt.Errorf("role must be source or sink")
	}
	if err := config.Save(*out, config.Default(*role)); err != nil {
		return err
	}
	fmt.Printf("wrote %s config to %s\n", *role, *out)
	return nil
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", filepath.Join(config.Dir(), "psk.key"), "key path")
	fs.Parse(args)
	if err := keyfile.Generate(*out); err != nil {
		return err
	}
	fmt.Printf("wrote 32-byte PSK to %s (copy this file to the peer)\n", *out)
	return nil
}

func loadConfig(args []string) (config.Config, error) {
	fs := flag.NewFlagSet("cfg", flag.ExitOnError)
	path := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	fs.Parse(args)
	return config.Load(*path)
}

func buildVaults(c config.Config) ([]source.CookieReader, []string, error) {
	var vs []source.CookieReader
	var paths []string
	for _, b := range c.Browsers {
		if b.Kind != "chromium" {
			return nil, nil, fmt.Errorf("unsupported browser kind %q (phase 1 supports chromium)", b.Kind)
		}
		vs = append(vs, &vault.LinuxChromium{
			Profile:     b.Profile,
			CookiePath:  b.CookiePath,
			KeyProvider: &vault.SecretServiceKey{Label: "Chrome Safe Storage"},
		})
		paths = append(paths, b.CookiePath)
	}
	return vs, paths, nil
}

func cmdSource(args []string) error {
	c, err := loadConfig(args)
	if err != nil {
		return err
	}
	key, err := keyfile.Load(c.KeyPath)
	if err != nil {
		return err
	}
	sealer, err := transport.NewSealer(key)
	if err != nil {
		return err
	}
	vs, paths, err := buildVaults(c)
	if err != nil {
		return err
	}
	conn, err := net.Dial("tcp", c.Peer)
	if err != nil {
		return fmt.Errorf("dial sink %s: %w", c.Peer, err)
	}
	defer conn.Close()

	syncer := &source.Syncer{
		Vaults: vs,
		Policy: c.Domains,
		Sealer: sealer,
		Out:    conn,
	}
	ctx := signalCtx()
	fmt.Printf("source: watching %d store(s), pushing to %s\n", len(paths), c.Peer)
	return syncer.Watch(ctx, paths, 500*time.Millisecond)
}

func cmdSink(args []string) error {
	c, err := loadConfig(args)
	if err != nil {
		return err
	}
	key, err := keyfile.Load(c.KeyPath)
	if err != nil {
		return err
	}
	opener, err := transport.NewOpener(key)
	if err != nil {
		return err
	}
	sidecarPath := filepath.Join(config.Dir(), "sidecar.db")
	sc, err := surface.NewSidecar(sidecarPath)
	if err != nil {
		return err
	}
	defer sc.Close()

	ln, err := net.Listen("tcp", c.Peer)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("sink: listening on %s, sidecar at %s\n", c.Peer, sidecarPath)

	srv := &sink.Server{Opener: opener, Surfaces: []sink.Surface{sc}}
	ctx := signalCtx()
	for {
		if ctx.Err() != nil {
			return nil
		}
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		// One connection at a time keeps the replay counter monotonic.
		if err := srv.Serve(ctx, conn); err != nil {
			fmt.Fprintln(os.Stderr, "connection ended:", err)
		}
		conn.Close()
	}
}

func cmdInstallService(args []string) error {
	c, err := loadConfig(args)
	if err != nil {
		return err
	}
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(config.Dir(), "config.toml")
	unitDir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		return err
	}
	unitPath := filepath.Join(unitDir, service.UnitFileName(c.Role))
	if err := os.WriteFile(unitPath, []byte(service.SystemdUnit(c.Role, bin, cfgPath)), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\nenable with:\n  systemctl --user daemon-reload\n  systemctl --user enable --now %s\n",
		unitPath, service.UnitFileName(c.Role))
	return nil
}

func cmdStatus(args []string) error {
	c, err := loadConfig(args)
	if err != nil {
		return err
	}
	fmt.Printf("role:     %s\npeer:     %s\nkey:      %s\nsurfaces: %v\nbrowsers: %d\nallow:    %v\ndeny:     %v\n",
		c.Role, c.Peer, c.KeyPath, c.Surfaces, len(c.Browsers), c.Domains.Allow, c.Domains.Deny)
	return nil
}

func signalCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ch; cancel() }()
	return ctx
}

// ensure policy import is used even if config has no domains in some builds.
var _ = policy.Domain{}
```

- [ ] **Step 2: Build**

Run: `go build ./...`
Expected: exit 0.

- [ ] **Step 3: Smoke test init/keygen/status in a temp config dir**

Run:
```bash
export XDG_CONFIG_HOME=$(mktemp -d)
go run ./cmd/agentpantry init --role sink
go run ./cmd/agentpantry keygen
go run ./cmd/agentpantry status
```
Expected: writes config + key, then prints role `sink`, peer `127.0.0.1:8787`, surfaces `[sidecar]`.

- [ ] **Step 4: Vet**

Run: `go vet ./...`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add cmd/agentpantry/main.go
git commit -m "feat: wire cli commands for source, sink, init, keygen, service"
```

---

### Task 18: End-to-end loopback integration test

**Files:**
- Create: `test/integration_test.go`

Drives a real source `Syncer` into an in-process sink `Server` over an `io.Pipe`, with a real `LinuxChromium` vault reading a fake Chrome DB and a real `Sidecar` surface. Confirms an allowed cookie lands in the sidecar and a denied one does not.

- [ ] **Step 1: Write the failing test**

`test/integration_test.go`:
```go
package test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/policy"
	"github.com/solomonneas/agentpantry/internal/sink"
	"github.com/solomonneas/agentpantry/internal/source"
	"github.com/solomonneas/agentpantry/internal/surface"
	"github.com/solomonneas/agentpantry/internal/transport"
	"github.com/solomonneas/agentpantry/internal/vault"
	_ "modernc.org/sqlite"
)

type staticKey struct{ p string }

func (s staticKey) Passphrase() (string, error) { return s.p, nil }

func encryptChromeV11(pass, value string) []byte {
	return vault.EncryptForTest("v11", pass, value)
}

func writeChromeDB(t *testing.T, path, pass string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE cookies(host_key TEXT,name TEXT,value TEXT,encrypted_value BLOB,
		path TEXT,expires_utc INTEGER,is_secure INTEGER,is_httponly INTEGER,samesite INTEGER)`)
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct{ host, val string }{
		{"github.com", "github-session"},
		{"bank.com", "should-not-sync"},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?)`,
			r.host, "sid", "", encryptChromeV11(pass, r.val), "/", int64(0), 1, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEndToEndSourceToSink(t *testing.T) {
	dir := t.TempDir()
	chromePath := filepath.Join(dir, "Cookies")
	writeChromeDB(t, chromePath, "keyring")

	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key)
	opener, _ := transport.NewOpener(key)

	sidecarPath := filepath.Join(dir, "sidecar.db")
	sc, err := surface.NewSidecar(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	pr, pw := newPipe()
	syncer := &source.Syncer{
		Vaults: []source.CookieReader{&vault.LinuxChromium{
			Profile: "test", CookiePath: chromePath, KeyProvider: staticKey{"keyring"},
		}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    pw,
	}
	srv := &sink.Server{Opener: opener, Surfaces: []sink.Surface{sc}}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), pr) }()

	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sink did not finish")
	}

	// Verify sidecar contents.
	db, _ := sql.Open("sqlite", sidecarPath)
	defer db.Close()
	var got string
	err = db.QueryRow(`SELECT value FROM cookies WHERE host=?`, "github.com").Scan(&got)
	if err != nil {
		t.Fatalf("github cookie missing: %v", err)
	}
	if got != "github-session" {
		t.Fatalf("decrypt/transport failed, got %q", got)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM cookies WHERE host=?`, "bank.com").Scan(&n)
	if n != 0 {
		t.Fatalf("denied domain leaked into sidecar")
	}
	_ = cookie.Cookie{} // keep cookie import referenced
}
```

- [ ] **Step 2: Add the test helpers the test depends on**

The test references `vault.EncryptForTest` and a `newPipe` helper. Add both.

Create `internal/vault/testsupport.go` (compiled normally, used by cross-package tests):
```go
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

// EncryptForTest mirrors Chromium's Linux scheme so other packages' tests can
// build fixtures. It is exported only for tests but lives in a normal file to
// keep it importable across packages.
func EncryptForTest(prefix, passphrase, value string) []byte {
	key := pbkdf2.Key([]byte(passphrase), []byte("saltysalt"), 1, 16, sha1.New)
	block, _ := aes.NewCipher(key)
	iv := bytes.Repeat([]byte{' '}, 16)
	pad := 16 - len(value)%16
	padded := append([]byte(value), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append([]byte(prefix), ct...)
}
```

Create `test/pipe.go`:
```go
package test

import "io"

// newPipe returns a synchronous in-memory pipe (reader, writer).
func newPipe() (*io.PipeReader, *io.PipeWriter) {
	return io.Pipe()
}
```

- [ ] **Step 3: Run test to verify it fails, then passes**

Run: `go test ./test/`
Expected first run while helpers/missing pieces are absent: FAIL. After Step 2 files exist and packages compile: PASS.

- [ ] **Step 4: Run the whole suite**

Run: `go test ./...`
Expected: all packages PASS.

- [ ] **Step 5: Commit**

```bash
git add test/integration_test.go test/pipe.go internal/vault/testsupport.go
git commit -m "test: add end-to-end source-to-sink loopback integration test"
```

---

### Task 19: README and quickstart docs

**Files:**
- Create: `README.md`
- Create: `LICENSE` (MIT)

- [ ] **Step 1: Write the README**

`README.md` must cover: what agentpantry is (cross-platform agentcookie reimagining), the source/sink model, the Phase 1 scope (Linux Chromium cookies, sidecar surface, transport-agnostic encrypted push), a quickstart, and a security note that domains are opt-in and the sidecar is plaintext. Use this skeleton and fill each section with real prose (no placeholders):

```markdown
# agentpantry

Keep your agent's machine authenticated. agentpantry mirrors authenticated
browser sessions from your daily-driver (source) to the machine your agent runs
on (sink), encrypted over any reachable network path, so your agent runtime
wakes up logged in.

Cross-platform reimagining of agentcookie. Phase 1 supports Linux Chromium on
both ends.

## How it works

(source watches + decrypts cookies -> domain filter -> AES-256-GCM frames over
TCP/stdio -> sink writes a plaintext sidecar SQLite. Diagram.)

## Quickstart

### On the sink (agent machine)
    agentpantry init --role sink
    agentpantry keygen
    # copy ~/.config/agentpantry/psk.key to the source machine
    # edit config.toml: set peer to the bind address, e.g. 0.0.0.0:8787 over your VPN
    agentpantry sink

### On the source (daily driver)
    agentpantry init --role source
    # copy the psk.key from the sink into ~/.config/agentpantry/psk.key
    # edit config.toml: set peer to the sink address, add a [[browsers]] block and allow domains
    agentpantry source

## Security

- Domains are opt-in. Nothing syncs until you add it to `domains.allow`.
- The sidecar SQLite is plaintext, mode 0600. Treat the sink like a secret store.
- Transport is AES-256-GCM with a shared key; run it over Tailscale, Twingate,
  a LAN you trust, or an SSH tunnel.

## Status

Phase 1 (v0.1). Roadmap: real-Chrome re-encrypt surface, secrets bus, per-CLI
adapters, Firefox, Windows.
```

- [ ] **Step 2: Add an MIT LICENSE**

Create `LICENSE` with the standard MIT text, copyright `2026 Solomon Neas`.

- [ ] **Step 3: Verify build and tests are still green**

Run: `go build ./... && go test ./...`
Expected: exit 0, all PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md LICENSE
git commit -m "docs: add readme and mit license"
```

---

## Self-Review Notes

- **Spec coverage:** §2 topology -> Tasks 13/14/17; §3 vault/Linux Chromium -> Tasks 7/8/9; §4 transport -> Tasks 5/6; §5 sidecar surface -> Task 10 (re-encrypt/secrets/adapters are later phases, correctly excluded); §6 security (domain opt-in, 0600, no value logging) -> Tasks 4/10/12; §7 config -> Task 11; §8 systemd -> Tasks 16/17; §10 testing -> Task 18. Phases 2-5 deliberately out of this plan.
- **Type consistency:** `cookie.Cookie`, `cookie.Diff`, `cookie.Key`, `cookie.NewSnapshot`, `Snapshot.DiffFrom` are used identically across Tasks 2,3,8,10,13,14,18. `source.CookieReader` (exported, per Task 13 note) is used in Tasks 13/14/17/18. `sink.Surface` and `surface.Surface` are intentionally identical interfaces; `surface.Sidecar` satisfies both. `vault.EncryptForTest` (Task 18) and the in-test `encryptChrome` (Task 7) share one algorithm.
- **Decision captured:** the Task 13 test originally used an anonymous interface slice; the plan renames the interface to exported `CookieReader` and updates the test literal to `[]CookieReader{...}` so it compiles. Apply that rename when implementing Task 13.
- **No placeholders:** every code step contains complete code; the README task (19) is the only prose-fill task and its required sections are enumerated.
