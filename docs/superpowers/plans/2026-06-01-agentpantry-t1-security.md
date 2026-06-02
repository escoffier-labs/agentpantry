# agentpantry T1 Implementation Plan (security hardening)

> REQUIRED SUB-SKILL: subagent-driven-development / executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** Per-session salt + HKDF to close the cross-connection replay gap; a secret-name allow/deny policy; govulncheck make target + clean baseline; fuzz targets for the untrusted-input parsers.

**Architecture:** `NewSealer(key,salt)`/`NewOpener(key,salt)` derive a per-session AES key via HKDF-SHA256(psk, salt). A salt frame is exchanged at connection start (sink-issued over TCP, source-issued over `--stdio`). `policy.Names` filters secret names in `source.SyncOnce`. Fuzz targets assert no-panic on arbitrary input.

**Tech Stack:** Go 1.25; adds `golang.org/x/crypto/hkdf` (already depend on x/crypto). Module `github.com/escoffier-labs/agentpantry`. Base branch `t1-security` off master.

Note: this is a cohesive cross-cutting change. Task 1 changes the transport API and MUST update every call site (main.go + all tests) in the same task so `go build ./...` stays green per commit.

---

### Task 1: Per-session salt (HKDF) + handshake + wire all call sites

**Files:** Modify `internal/transport/envelope.go`, `internal/transport/envelope_test.go`; Create `internal/transport/handshake.go`, `internal/transport/handshake_test.go`; Modify `cmd/agentpantry/main.go`; Modify all tests that build a Sealer/Opener (`internal/source/source_test.go`, `internal/source/aftersync_test.go`, `internal/source/watch_test.go` if any, `internal/sink/sink_test.go`, `test/integration_test.go`).

- [ ] **Step 1: Add hkdf dep** — `go get golang.org/x/crypto/hkdf@latest`.

- [ ] **Step 2: Write failing transport tests**

Replace the seam in `internal/transport/envelope_test.go` so all `NewSealer`/`NewOpener` calls pass a salt, and add the replay-fix assertion:
```go
func salt16() []byte {
	s := make([]byte, 16)
	for i := range s {
		s[i] = byte(100 + i)
	}
	return s
}

func TestDifferentSaltFailsToOpen(t *testing.T) {
	s, _ := NewSealer(key32(), salt16())
	frame, _ := s.Seal([]byte("hi"))
	other := salt16()
	other[0] ^= 0xff
	o, _ := NewOpener(key32(), other)
	if _, err := o.Open(frame); err == nil {
		t.Fatal("a frame sealed under one salt must not open under another")
	}
}
```
Update the existing envelope tests (`TestSealOpenRoundTrip`, `TestOpenRejectsReplay`, `TestOpenRejectsWrongKey`) to call `NewSealer(key32(), salt16())` / `NewOpener(key32(), salt16())` (same salt on both ends).

`internal/transport/handshake_test.go`:
```go
package transport

import (
	"bytes"
	"testing"
)

func TestSendRecvSaltRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	sent, err := SendSalt(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != SaltLen {
		t.Fatalf("want %d-byte salt, got %d", SaltLen, len(sent))
	}
	got, err := RecvSalt(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sent, got) {
		t.Fatal("recv salt != sent salt")
	}
}

func TestRecvSaltRejectsWrongLength(t *testing.T) {
	var buf bytes.Buffer
	WriteFrame(&buf, []byte("short"))
	if _, err := RecvSalt(&buf); err == nil {
		t.Fatal("wrong-length salt must be rejected")
	}
}
```

- [ ] **Step 3: Run, verify fail** — `go test ./internal/transport/` (compile failure: NewSealer takes 1 arg / SendSalt undefined).

- [ ] **Step 4: Implement envelope HKDF**

In `internal/transport/envelope.go`, add imports `crypto/sha256`, `io`, `golang.org/x/crypto/hkdf`, and replace `newAEAD` + constructors:
```go
func deriveSessionKey(key, salt []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	r := hkdf.New(sha256.New, key, salt, []byte("agentpantry/v1 session"))
	sk := make([]byte, 32)
	if _, err := io.ReadFull(r, sk); err != nil {
		return nil, err
	}
	return sk, nil
}

func newAEAD(key, salt []byte) (cipher.AEAD, error) {
	sk, err := deriveSessionKey(key, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func NewSealer(key, salt []byte) (*Sealer, error) {
	a, err := newAEAD(key, salt)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: a}, nil
}

func NewOpener(key, salt []byte) (*Opener, error) {
	a, err := newAEAD(key, salt)
	if err != nil {
		return nil, err
	}
	return &Opener{aead: a}, nil
}
```
`Seal`/`Open` bodies are unchanged.

- [ ] **Step 5: Implement handshake primitives**

`internal/transport/handshake.go`:
```go
package transport

import (
	"crypto/rand"
	"fmt"
	"io"
)

// SaltLen is the per-session salt length.
const SaltLen = 16

// SendSalt generates a random session salt and writes it as one frame.
func SendSalt(w io.Writer) ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if err := WriteFrame(w, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// RecvSalt reads one frame and validates it as a session salt.
func RecvSalt(r io.Reader) ([]byte, error) {
	salt, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("invalid session salt length %d", len(salt))
	}
	return salt, nil
}
```

- [ ] **Step 6: Wire the handshake into main.go**

In `cmdSource`, restructure so the salt is exchanged before the Sealer is built. Replace the sealer/out section:
```go
	vs, paths, err := buildVaults(c)
	if err != nil {
		return err
	}
	var secretReaders []source.SecretReader
	if c.SecretsDir != "" {
		secretReaders = append(secretReaders, &secretsrc.DirReader{Dir: c.SecretsDir})
		if _, statErr := os.Stat(c.SecretsDir); statErr == nil {
			paths = append(paths, c.SecretsDir)
		}
	}

	var out io.Writer
	var salt []byte
	if *stdio {
		out = os.Stdout
		salt, err = transport.SendSalt(os.Stdout) // source issues salt over the one-way pipe
		if err != nil {
			return err
		}
	} else {
		conn, derr := net.Dial("tcp", c.Peer)
		if derr != nil {
			return fmt.Errorf("dial sink %s: %w", c.Peer, derr)
		}
		defer conn.Close()
		out = conn
		salt, err = transport.RecvSalt(conn) // sink issues the salt challenge
		if err != nil {
			return fmt.Errorf("handshake: %w", err)
		}
	}
	sealer, err := transport.NewSealer(key, salt)
	if err != nil {
		return err
	}
```
(Remove the earlier `sealer, err := transport.NewSealer(key)` line that ran before dialing.)

In `cmdSink`, the stdio branch and the accept loop each build an Opener; add the salt exchange:
- stdio branch:
```go
	if *stdio {
		salt, herr := transport.RecvSalt(os.Stdin)
		if herr != nil {
			return fmt.Errorf("handshake: %w", herr)
		}
		opener, oerr := transport.NewOpener(key, salt)
		if oerr != nil {
			return oerr
		}
		srv := &sink.Server{Opener: opener, CookieSurfaces: cookieSurfaces, SecretSurfaces: secretSurfaces}
		fmt.Fprintf(os.Stderr, "sink: reading frames from stdin, surfaces %v\n", c.Surfaces)
		go func() { <-ctx.Done(); os.Stdin.Close() }()
		return srv.Serve(ctx, os.Stdin)
	}
```
- accept loop:
```go
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		salt, herr := transport.SendSalt(conn) // issue a fresh per-connection salt
		if herr != nil {
			fmt.Fprintln(os.Stderr, "handshake failed:", herr)
			conn.Close()
			continue
		}
		opener, oerr := transport.NewOpener(key, salt)
		if oerr != nil {
			conn.Close()
			return oerr
		}
		srv := &sink.Server{Opener: opener, CookieSurfaces: cookieSurfaces, SecretSurfaces: secretSurfaces}
		if err := srv.Serve(ctx, conn); err != nil {
			fmt.Fprintln(os.Stderr, "connection ended:", err)
		}
		conn.Close()
```

- [ ] **Step 7: Update all other test call sites**

In `internal/source/source_test.go`, `internal/source/aftersync_test.go`, `internal/sink/sink_test.go`, and `test/integration_test.go`, every `transport.NewSealer(key)` / `transport.NewOpener(key)` (and the `make([]byte,32)` opener in `decodePayload`) becomes the two-arg form with a shared fixed salt. Add a local helper where convenient, e.g. `salt := make([]byte, 16)` and pass it to both the sealer and opener in each test. In `internal/source/source_test.go`'s `decodePayload`, change `transport.NewOpener(make([]byte, 32))` to `transport.NewOpener(make([]byte, 32), make([]byte, 16))` and have the test's sealer use the same `make([]byte,16)` salt. Apply the same to `watch_test.go` if it constructs a Sealer.

- [ ] **Step 8: Build, vet, test**

Run: `go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...`
Expected: all PASS (the different-salt test proves the replay fix).

- [ ] **Step 9: Commit**
```bash
git add internal/transport/ cmd/agentpantry/main.go internal/source/ internal/sink/ test/ go.mod go.sum
git commit -m "feat: derive a per-session transport key from a handshake salt"
```

---

### Task 2: secret-name allow/deny policy

**Files:** Create `internal/policy/names.go`; Modify `internal/config/config.go`, `internal/source/source.go`; Tests `internal/policy/names_test.go`, `internal/config/config_test.go`, `internal/source/*`

- [ ] **Step 1: Failing test** — `internal/policy/names_test.go`:
```go
package policy

import "testing"

func TestNamesPermit(t *testing.T) {
	d := Names{Deny: []string{"bad"}}
	if !d.Permit("anything") {
		t.Fatal("empty allow must permit all")
	}
	if d.Permit("bad") {
		t.Fatal("deny must block")
	}
	a := Names{Allow: []string{"gh_token"}, Deny: []string{"gh_token"}}
	if a.Permit("gh_token") {
		t.Fatal("deny overrides allow")
	}
	w := Names{Allow: []string{"gh_token"}}
	if !w.Permit("gh_token") || w.Permit("other") {
		t.Fatal("non-empty allow is a whitelist")
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/policy/ -run Names`.

- [ ] **Step 3: Implement** — `internal/policy/names.go`:
```go
package policy

// Names is an exact-match allow/deny policy over secret names.
type Names struct {
	Allow []string `toml:"allow"`
	Deny  []string `toml:"deny"`
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// Permit reports whether a secret named name may sync. Deny overrides Allow; an
// empty Allow permits all (the configured secrets_dir is the opt-in).
func (n Names) Permit(name string) bool {
	if contains(n.Deny, name) {
		return false
	}
	if len(n.Allow) == 0 {
		return true
	}
	return contains(n.Allow, name)
}
```

- [ ] **Step 4: config field** — add to `Config` in `internal/config/config.go`:
```go
	SecretNames policy.Names `toml:"secret_names"`
```
Append a round-trip test to `internal/config/config_test.go`:
```go
func TestSecretNamesRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("source")
	in.SecretNames = policy.Names{Allow: []string{"gh_token"}, Deny: []string{"aws"}}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.SecretNames.Allow) != 1 || out.SecretNames.Deny[0] != "aws" {
		t.Fatalf("secret_names lost: %+v", out.SecretNames)
	}
}
```
(`internal/config` already imports `policy`.)

- [ ] **Step 5: Syncer filter** — add `SecretPolicy policy.Names` to `Syncer` in `internal/source/source.go`, and in `SyncOnce`, filter gathered secrets:
```go
		allSecrets = append(allSecrets, ss...)
```
becomes, after the gather loop, a filter pass before `NewSnapshot`:
```go
	if len(allSecrets) > 0 {
		kept := allSecrets[:0]
		for _, s := range allSecrets {
			if s.SecretPermit(sec.Name) // see below
		}
	}
```
Concretely, replace the secret-gather block's snapshot construction with:
```go
		curSecrets := secret.NewSnapshot(filterSecrets(allSecrets, s.SecretPolicy))
```
and add a helper in source.go:
```go
func filterSecrets(in []secret.Secret, p policy.Names) []secret.Secret {
	out := in[:0]
	for _, s := range in {
		if p.Permit(s.Name) {
			out = append(out, s)
		}
	}
	return out
}
```
Add a source test asserting a denied secret name does not appear in the payload (mirror `TestSyncOnceFiltersCookies...`, using `SecretPolicy: policy.Names{Deny: []string{"secret_b"}}` and two secrets).

- [ ] **Step 6: wire main.go** — in `cmdSource`, set `SecretPolicy: c.SecretNames` on the `source.Syncer` literal.

- [ ] **Step 7: Build, test** — `go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...`.

- [ ] **Step 8: Commit**
```bash
git add internal/policy/ internal/config/ internal/source/ cmd/agentpantry/main.go
git commit -m "feat: add secret-name allow/deny policy"
```

---

### Task 3: fuzz targets + govulncheck + docs

**Files:** Create fuzz tests in `internal/wire`, `internal/transport`, `internal/surface`, `internal/vault`, `internal/wincrypto`; refactor `internal/surface/netscape.go`; create `Makefile`; modify `CHANGELOG.md`, `README.md`

- [ ] **Step 1: Refactor the Netscape line parser** — in `internal/surface/netscape.go`, extract the per-line parse from `seed()` into:
```go
func parseNetscapeLine(line string) (netscapeRow, bool) {
	if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
		return netscapeRow{}, false
	}
	parts := strings.Split(line, "\t")
	if len(parts) != 7 {
		return netscapeRow{}, false
	}
	exp, _ := strconv.ParseInt(parts[4], 10, 64)
	return netscapeRow{
		domain: parts[0], includeSub: parts[1] == "TRUE", path: parts[2],
		secure: parts[3] == "TRUE", expiry: exp, name: parts[5], value: parts[6],
	}, true
}
```
and call it from `seed()` (`if r, ok := parseNetscapeLine(strings.TrimRight(sc.Text(), "\r")); ok { n.rows[cookie.Key(cookie.Cookie{Host: r.domain, Name: r.name, Path: r.path})] = r }`).

- [ ] **Step 2: Add fuzz targets**

`internal/wire/fuzz_test.go`:
```go
package wire

import (
	"encoding/json"
	"testing"
)

func FuzzPayloadUnmarshal(f *testing.F) {
	f.Add([]byte(`{"cookies":{"upserts":[]},"secrets":{"upserts":[]}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var p Payload
		_ = json.Unmarshal(b, &p) // must not panic
		_ = p.IsEmpty()
	})
}
```

`internal/transport/fuzz_test.go`:
```go
package transport

import "testing"

func FuzzOpen(f *testing.F) {
	f.Add([]byte("v10short"))
	o, _ := NewOpener(key32(), salt16())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = o.Open(b) // must not panic
	})
}
```

`internal/surface/fuzz_test.go`:
```go
package surface

import "testing"

func FuzzParseNetscapeLine(f *testing.F) {
	f.Add("a.com\tFALSE\t/\tFALSE\t0\tn\tv")
	f.Add("# comment")
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseNetscapeLine(line) // must not panic
	})
}
```

`internal/vault/fuzz_test.go`:
```go
package vault

import "testing"

func FuzzDecryptValue(f *testing.F) {
	f.Add([]byte("v10abcdefghijklmnop"))
	f.Add([]byte("plain"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecryptValue(b, "pass") // must not panic
	})
}
```

`internal/wincrypto/fuzz_test.go`:
```go
package wincrypto

import "testing"

func FuzzDecryptV10GCM(f *testing.F) {
	f.Add([]byte("v10shorttooshort"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecryptV10GCM(b, key32()) // must not panic
	})
}
```

- [ ] **Step 3: Makefile**

`Makefile`:
```makefile
.PHONY: build test vet windows vuln fuzz
build:
	go build ./...
test:
	go test ./...
vet:
	go vet ./...
windows:
	GOOS=windows go build ./...
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
fuzz:
	go test ./... -run '^$$' -fuzz . -fuzztime 20s
```

- [ ] **Step 4: Run the suite, fuzz seed corpus, and govulncheck**

Run: `go build ./... && go vet ./... && go test ./...` (fuzz targets execute their seed corpus here).
Run: `make vuln` and confirm no findings (fix or document any). Record the clean result.

- [ ] **Step 5: Docs** — CHANGELOG `## Unreleased` -> `### Added`: per-session transport salt (note: breaking transport change, both ends must upgrade), secret-name policy, fuzz targets, Makefile/govulncheck. README: a short note that the transport derives a per-session key from a handshake salt; document `[secret_names]` allow/deny. No em dashes, no private IPs/hostnames.

- [ ] **Step 6: Commit**
```bash
git add internal/ Makefile CHANGELOG.md README.md
git commit -m "test: add fuzz targets; chore: add makefile with govulncheck"
```

---

## Self-Review Notes

- **Spec coverage:** replay fix (spec 2) -> Task 1; secret policy (spec 3) -> Task 2; govulncheck (spec 4) -> Task 3; fuzz (spec 5) -> Task 3.
- **Breaking transport change is contained in Task 1**, which updates the API and every caller (main.go + all tests) so the build stays green per commit.
- **Type consistency:** `NewSealer(key,salt)`/`NewOpener(key,salt)` (Task 1) used everywhere; `SendSalt`/`RecvSalt`/`SaltLen` (Task 1); `policy.Names`/`Permit` (Task 2); `parseNetscapeLine` (Task 3) reused by `seed()` and the fuzz target.
- **No placeholders.**
