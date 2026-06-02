# agentpantry Phase 5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Firefox source cookie reader (`internal/ffvault`) that reads plaintext `moz_cookies` into the normalized model, wire `kind = "firefox"` into the CLI, and make doctor's keyring check Chromium-conditional.

**Architecture:** `ffvault.Firefox` implements `source.CookieReader` by copying `cookies.sqlite` to a temp file and querying `moz_cookies`. Firefox expiry (unix seconds) converts to the pinned micros-since-1601 contract via `cookie.ExpiresFromUnix`. No decryption, no keyring. `buildVaults` constructs it for `kind == "firefox"`.

**Tech Stack:** Go 1.25, `modernc.org/sqlite`, existing internal packages. Module `github.com/escoffier-labs/agentpantry`.

Base branch: `phase-5` (create off master).

---

## File Structure

```
internal/ffvault/firefox.go     # Firefox CookieReader
cmd/agentpantry/main.go         # buildVaults: kind == "firefox"
internal/doctor/doctor.go       # keyring check only when a chromium browser is configured
test/integration_test.go        # firefox e2e
README.md / CHANGELOG.md
```

---

### Task 1: Firefox reader

**Files:** Create `internal/ffvault/firefox.go`; Test `internal/ffvault/firefox_test.go`

- [ ] **Step 1: Failing test**

`internal/ffvault/firefox_test.go`:
```go
package ffvault

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	_ "modernc.org/sqlite"
)

func writeFakeFirefoxDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE moz_cookies(
		id INTEGER PRIMARY KEY,
		originAttributes TEXT NOT NULL DEFAULT '',
		name TEXT, value TEXT, host TEXT, path TEXT,
		expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER,
		isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0,
		sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO moz_cookies(name,value,host,path,expiry,isSecure,isHttpOnly,sameSite)
		VALUES(?,?,?,?,?,?,?,?)`, "sid", "ff-token", ".github.com", "/", int64(1637000000), 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFirefoxReadCookies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cookies.sqlite")
	writeFakeFirefoxDB(t, path)

	f := &Firefox{Profile: "test", CookiePath: path}
	cs, err := f.ReadCookies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cs))
	}
	c := cs[0]
	if c.Host != ".github.com" || c.Name != "sid" || c.Value != "ff-token" || c.Path != "/" {
		t.Fatalf("unexpected cookie: %+v", c)
	}
	if c.ExpiresUTC != cookie.ExpiresFromUnix(1637000000) {
		t.Fatalf("expiry not converted to micros-1601: %d", c.ExpiresUTC)
	}
	if !c.IsSecure || !c.IsHTTPOnly || c.SameSite != 1 {
		t.Fatalf("flags/samesite wrong: %+v", c)
	}
}

func TestFirefoxMissingDBErrors(t *testing.T) {
	f := &Firefox{Profile: "p", CookiePath: filepath.Join(t.TempDir(), "nope.sqlite")}
	if _, err := f.ReadCookies(context.Background()); err == nil {
		t.Fatal("missing DB must error")
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/ffvault/`
Expected: FAIL `undefined: Firefox`.

- [ ] **Step 3: Implement**

`internal/ffvault/firefox.go`:
```go
package ffvault

import (
	"context"
	"database/sql"
	"io"
	"os"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	_ "modernc.org/sqlite"
)

// Firefox reads cookies from a Firefox profile's cookies.sqlite (plaintext values).
type Firefox struct {
	Profile    string
	CookiePath string
}

func (f *Firefox) Name() string { return "firefox:" + f.Profile }

func copyToTemp(src string) (string, func(), error) {
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "agentpantry-ff-*.sqlite")
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

func (f *Firefox) ReadCookies(ctx context.Context) ([]cookie.Cookie, error) {
	tmp, cleanup, err := copyToTemp(f.CookiePath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", tmp+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, `SELECT host, name, value, path, expiry,
		isSecure, isHttpOnly, sameSite FROM moz_cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []cookie.Cookie
	for rows.Next() {
		var (
			host, name, value, path    string
			expiry                     int64
			secure, httpOnly, sameSite int
		)
		if err := rows.Scan(&host, &name, &value, &path, &expiry, &secure, &httpOnly, &sameSite); err != nil {
			return nil, err
		}
		out = append(out, cookie.Cookie{
			Host: host, Name: name, Value: value, Path: path,
			ExpiresUTC: cookie.ExpiresFromUnix(expiry),
			IsSecure:   secure != 0, IsHTTPOnly: httpOnly != 0, SameSite: sameSite,
		})
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/ffvault/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/ffvault/
git commit -m "feat: add firefox source cookie reader"
```

---

### Task 2: CLI wiring + doctor keyring conditional

**Files:** Modify `cmd/agentpantry/main.go`, `internal/doctor/doctor.go`; Test `internal/doctor/doctor_test.go`

- [ ] **Step 1: Extend buildVaults for firefox**

In `cmd/agentpantry/main.go`, add the `ffvault` import and replace the `buildVaults` body's loop so non-chromium no longer hard-errors for firefox:
```go
func buildVaults(c config.Config) ([]source.CookieReader, []string, error) {
	var vs []source.CookieReader
	var paths []string
	for _, b := range c.Browsers {
		switch b.Kind {
		case "chromium":
			vs = append(vs, &vault.LinuxChromium{
				Profile:     b.Profile,
				CookiePath:  b.CookiePath,
				KeyProvider: &vault.SecretServiceKey{Label: "Chrome Safe Storage"},
			})
		case "firefox":
			vs = append(vs, &ffvault.Firefox{Profile: b.Profile, CookiePath: b.CookiePath})
		default:
			return nil, nil, fmt.Errorf("unsupported browser kind %q (supported: chromium, firefox)", b.Kind)
		}
		paths = append(paths, b.CookiePath)
	}
	return vs, paths, nil
}
```
Add `"github.com/escoffier-labs/agentpantry/internal/ffvault"` to the import block.

- [ ] **Step 2: Add a doctor test for the keyring conditional**

Append to `internal/doctor/doctor_test.go`:
```go
func TestPureFirefoxSourceHasNoKeyringCheck(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	ff := filepath.Join(dir, "cookies.sqlite")
	os.WriteFile(ff, []byte("x"), 0o600)
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{Kind: "firefox", Profile: "p", CookiePath: ff}},
	}
	if find(Run(c), "keyring").Status != -1 {
		t.Fatal("a pure-firefox source must not emit a keyring check")
	}
}

func TestChromiumSourceStillHasKeyringCheck(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	cp := filepath.Join(dir, "Cookies")
	os.WriteFile(cp, []byte("x"), 0o600)
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{Kind: "chromium", Profile: "p", CookiePath: cp}},
	}
	if find(Run(c), "keyring").Status == -1 {
		t.Fatal("a chromium source must still emit a keyring check")
	}
}
```
(`find` returns `Check{Status: -1}` when absent, per the existing helper.)

- [ ] **Step 3: Run, verify fail**

Run: `go test ./internal/doctor/ -run Firefox`
Expected: FAIL (keyring check is currently unconditional, so the pure-firefox test fails).

- [ ] **Step 4: Make the keyring check conditional**

In `internal/doctor/doctor.go`, in `Run`'s `case "source":`, replace the unconditional
`checks = append(checks, KeyringCheck(&vault.SecretServiceKey{Label: "Chrome Safe Storage"}))`
with a guard:
```go
		hasChromium := false
		for _, b := range c.Browsers {
			if b.Kind == "chromium" {
				hasChromium = true
			}
		}
		if hasChromium {
			checks = append(checks, KeyringCheck(&vault.SecretServiceKey{Label: "Chrome Safe Storage"}))
		}
```

- [ ] **Step 5: Run, verify pass**

Run: `go test ./internal/doctor/ && go build ./... && go vet ./...`
Expected: PASS, build/vet clean.

- [ ] **Step 6: Commit**

```bash
git add cmd/agentpantry/main.go internal/doctor/doctor.go internal/doctor/doctor_test.go
git commit -m "feat: wire firefox browser kind and scope keyring check to chromium"
```

---

### Task 3: integration test + docs

**Files:** Modify `test/integration_test.go`, `README.md`, `CHANGELOG.md`

- [ ] **Step 1: Add a Firefox end-to-end test**

Append to `test/integration_test.go` (add the `ffvault` and `database/sql` imports if missing; `sql` is already imported as `database/sql`):
```go
func TestEndToEndFirefoxToSidecar(t *testing.T) {
	dir := t.TempDir()
	ffPath := filepath.Join(dir, "cookies.sqlite")
	db, err := sql.Open("sqlite", ffPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE moz_cookies(
		id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT '',
		name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER,
		lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER,
		isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0,
		sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO moz_cookies(name,value,host,path,expiry,isSecure,isHttpOnly,sameSite)
		VALUES(?,?,?,?,?,?,?,?)`, "sid", "ff-session", "github.com", "/", int64(1637000000), 1, 1, 1); err != nil {
		t.Fatal(err)
	}
	db.Close()

	sidecarPath := filepath.Join(dir, "sidecar.db")
	sc, err := surface.NewSidecar(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key)
	opener, _ := transport.NewOpener(key)
	pr, pw := newPipe()
	syncer := &source.Syncer{
		Vaults: []source.CookieReader{&ffvault.Firefox{Profile: "p", CookiePath: ffPath}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    pw,
	}
	srv := &sink.Server{Opener: opener, CookieSurfaces: []sink.CookieSurface{sc}}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), pr) }()
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	rdb, _ := sql.Open("sqlite", sidecarPath)
	defer rdb.Close()
	var got string
	if err := rdb.QueryRow(`SELECT value FROM cookies WHERE host=?`, "github.com").Scan(&got); err != nil || got != "ff-session" {
		t.Fatalf("firefox cookie did not sync: %q / %v", got, err)
	}
}
```
Add `"github.com/escoffier-labs/agentpantry/internal/ffvault"` to the test import block.

- [ ] **Step 2: Run, verify pass**

Run: `go test ./test/`
Expected: PASS.

- [ ] **Step 3: Full suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all PASS, vet clean.

- [ ] **Step 4: Docs**

In `README.md`, document Firefox support: add `kind = "firefox"` with a `cookie_path` pointing at the profile's `cookies.sqlite` to the source config docs; note values are plaintext (no keyring needed) and that a pure-Firefox source skips the keyring check. In `CHANGELOG.md` under `## Unreleased` -> `### Added`, add a Firefox-source-reader bullet. No em dashes, no machine hostnames, no private IPs / bare "localhost".

- [ ] **Step 5: Commit**

```bash
git add test/integration_test.go README.md CHANGELOG.md
git commit -m "test: firefox e2e; document firefox source"
```

---

## Self-Review Notes

- **Spec coverage:** reader (spec 2) -> Task 1; config kind (spec 3) -> Task 2 (Kind is a free string, no schema change); CLI wiring (spec 4) -> Task 2; doctor keyring conditional (spec 5) -> Task 2; testing (spec 8) -> all tasks. Firefox sink writer + containers + auto-discovery explicitly out of scope (spec 7).
- **Type consistency:** `ffvault.Firefox` implements `source.CookieReader` (`ReadCookies(ctx) ([]cookie.Cookie, error)`) used in Tasks 2,3. `cookie.ExpiresFromUnix` (Phase 4) reused. `find(...)` returning `Status -1` for absent checks is the existing doctor_test helper. `copyToTemp` is ffvault-local (the vault package has its own; no collision across packages).
- **No config schema change** (kind is already a string field) -> additive, no owner gate.
- **No placeholders:** all code complete; README task enumerates required additions.
