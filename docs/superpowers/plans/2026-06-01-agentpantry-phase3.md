# agentpantry Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the operability core: a persisted last-sync state with a real `status`, a `doctor` command that reports specific setup failures, and a `--stdio` transport mode so the link can ride an SSH channel.

**Architecture:** A new `state` package persists `state.json` (clock-injected for testability). `source.Syncer` gains an `AfterSync` hook the CLI uses to update state, keeping source decoupled from state. A new `doctor` package holds pure check functions plus a bounded network reachability check; the CLI renders them and sets the exit code. `--stdio` reuses the existing `Syncer.Out io.Writer` and `Server.Serve(io.Reader)` seams.

**Tech Stack:** Go 1.25 toolchain, stdlib only for the new code (net, os, encoding/json, time). Module `github.com/escoffier-labs/agentpantry`.

Base branch: `phase-3` (already created off `master`).

---

## File Structure

```
internal/state/state.go        # State, Clock, Load, Save (0600)
internal/source/source.go      # + AfterSync hook field, invoked in SyncOnce
internal/doctor/doctor.go      # Check model, Run(cfg) pure checks, PeerReachable
cmd/agentpantry/main.go        # cmdDoctor, --stdio on source/sink, state write + status read
test/integration_test.go       # + status-state e2e, stdio e2e
README.md / CHANGELOG.md        # docs
```

---

### Task 1: state package

**Files:** Create `internal/state/state.go`; Test `internal/state/state_test.go`

- [ ] **Step 1: Write the failing test**

`internal/state/state_test.go`:
```go
package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

func TestSaveLoadRoundTripAndPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	in := State{LastSyncUnix: 1700000000, LastSentUnix: 1700000000, Cookies: 3, Secrets: 1}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file must be 0600, got %v", info.Mode().Perm())
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
}

func TestLoadMissingIsZeroValue(t *testing.T) {
	out, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing state must not error, got %v", err)
	}
	if out != (State{}) {
		t.Fatalf("missing state must be zero value, got %+v", out)
	}
}

func TestRealClockNonZero(t *testing.T) {
	if (RealClock{}).Now().IsZero() {
		t.Fatal("real clock must return a real time")
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/state/`
Expected: FAIL `undefined: State`.

- [ ] **Step 3: Implement**

`internal/state/state.go`:
```go
package state

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// State records what the source last did, for `status` to report.
type State struct {
	LastSyncUnix int64 `json:"last_sync_unix"` // last successful SyncOnce cycle
	LastSentUnix int64 `json:"last_sent_unix"` // last cycle that sent a frame
	Cookies      int   `json:"cookies"`        // cookie upserts in the last sent frame
	Secrets      int   `json:"secrets"`        // secret upserts in the last sent frame
}

// Clock yields the current time; injected so tests are deterministic.
type Clock interface {
	Now() time.Time
}

// RealClock is the production clock.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

// Load reads state from path. A missing file is the zero value, not an error.
func Load(path string) (State, error) {
	var s State
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	if len(b) == 0 {
		return State{}, nil
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, err
	}
	return s, nil
}

// Save writes state to path as 0600 JSON.
func Save(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/state/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/state/
git commit -m "feat: add persisted last-sync state"
```

---

### Task 2: source AfterSync hook

**Files:** Modify `internal/source/source.go`; Test `internal/source/aftersync_test.go`

- [ ] **Step 1: Write the failing test**

`internal/source/aftersync_test.go`:
```go
package source

import (
	"bytes"
	"context"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/transport"
)

type oneVault struct{ cs []cookie.Cookie }

func (o oneVault) ReadCookies(context.Context) ([]cookie.Cookie, error) { return o.cs, nil }

func TestAfterSyncFiresWithSentAndCounts(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	type call struct {
		sent             bool
		cookies, secrets int
	}
	var calls []call
	syncer := &Syncer{
		Vaults: []CookieReader{oneVault{cs: []cookie.Cookie{
			{Host: "github.com", Name: "a", Path: "/", Value: "1"},
			{Host: "github.com", Name: "b", Path: "/", Value: "2"},
		}}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
		AfterSync: func(sent bool, c, s int) {
			calls = append(calls, call{sent, c, s})
		},
	}
	// First sync: 2 cookie upserts sent.
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Second sync: no change, nothing sent.
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("AfterSync must fire once per SyncOnce, got %d", len(calls))
	}
	if !calls[0].sent || calls[0].cookies != 2 {
		t.Fatalf("first call wrong: %+v", calls[0])
	}
	if calls[1].sent || calls[1].cookies != 0 {
		t.Fatalf("second call must be no-send: %+v", calls[1])
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/source/ -run AfterSync`
Expected: FAIL (`unknown field AfterSync`).

- [ ] **Step 3: Implement**

In `internal/source/source.go`, add the field to `Syncer` (after `Out`):
```go
	Out     io.Writer

	// AfterSync, if set, is called at the end of each successful SyncOnce.
	// sent reports whether a frame was written; cookies/secrets are the upsert
	// counts in that frame (0 when nothing was sent).
	AfterSync func(sent bool, cookies, secrets int)
```

Add a helper method:
```go
func (s *Syncer) afterSync(sent bool, cookies, secrets int) {
	if s.AfterSync != nil {
		s.AfterSync(sent, cookies, secrets)
	}
}
```

Replace the tail of `SyncOnce` (from `p := wire.Payload{...}` onward) with:
```go
	p := wire.Payload{Cookies: cookieDiff, Secrets: secretDiff}
	if p.IsEmpty() {
		s.afterSync(false, 0, 0)
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
	if err := transport.WriteFrame(s.Out, frame); err != nil {
		return err
	}
	s.afterSync(true, len(cookieDiff.Upserts), len(secretDiff.Upserts))
	return nil
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/source/`
Expected: PASS (existing source tests unaffected; their Syncer literals omit AfterSync, which is fine).

- [ ] **Step 5: Commit**

```bash
git add internal/source/source.go internal/source/aftersync_test.go
git commit -m "feat: add aftersync hook to source syncer"
```

---

### Task 3: doctor package (pure checks)

**Files:** Create `internal/doctor/doctor.go`; Test `internal/doctor/doctor_test.go`

- [ ] **Step 1: Write the failing test**

`internal/doctor/doctor_test.go`:
```go
package doctor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/keyfile"
)

func writeKey(t *testing.T, dir string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, "psk.key")
	if err := keyfile.Generate(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
	return p
}

func find(checks []Check, name string) Check {
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	return Check{Name: name, Status: -1}
}

func TestHealthySinkConfigPasses(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"}}
	checks := Run(c)
	for _, ck := range checks {
		if ck.Status == Fail {
			t.Fatalf("healthy config produced a Fail: %+v", ck)
		}
	}
}

func TestBadKeyPermFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o644)
	c := config.Config{Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"}}
	if find(Run(c), "key").Status != Fail {
		t.Fatal("0644 key must Fail")
	}
}

func TestNonLoopbackBindWarns(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{Role: "sink", Peer: "0.0.0.0:8787", KeyPath: key, Surfaces: []string{"sidecar"}}
	if find(Run(c), "bind").Status != Warn {
		t.Fatal("non-loopback bind must Warn")
	}
}

func TestUnknownSurfaceFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"bogus"}}
	if find(Run(c), "surface:bogus").Status != Fail {
		t.Fatal("unknown surface must Fail")
	}
}

func TestSourceMissingCookieStoreFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{Kind: "chromium", Profile: "p", CookiePath: filepath.Join(dir, "nope", "Cookies")}},
	}
	if find(Run(c), "vault:p").Status != Fail {
		t.Fatal("missing cookie store must Fail")
	}
}

func TestHasFailHelper(t *testing.T) {
	if HasFail([]Check{{Status: OK}, {Status: Warn}}) {
		t.Fatal("no Fail present")
	}
	if !HasFail([]Check{{Status: Fail}}) {
		t.Fatal("Fail present")
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/doctor/`
Expected: FAIL `undefined: Run`.

- [ ] **Step 3: Implement**

`internal/doctor/doctor.go`:
```go
package doctor

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/keyfile"
)

// Status is the outcome of a single check.
type Status int

const (
	OK Status = iota
	Warn
	Fail
)

func (s Status) String() string {
	switch s {
	case OK:
		return "OK"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	default:
		return "?"
	}
}

// Check is one diagnostic result. Detail never contains secret/cookie values.
type Check struct {
	Name   string
	Status Status
	Detail string
}

// HasFail reports whether any check failed.
func HasFail(checks []Check) bool {
	for _, c := range checks {
		if c.Status == Fail {
			return true
		}
	}
	return false
}

func isLoopbackBind(peer string) bool {
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return false
	}
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".pantry-doctor-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// Run executes the role-appropriate non-network checks.
func Run(c config.Config) []Check {
	var checks []Check

	// key
	if info, err := os.Stat(c.KeyPath); err != nil {
		checks = append(checks, Check{"key", Fail, fmt.Sprintf("PSK not found at %s", c.KeyPath)})
	} else if info.Mode().Perm()&0o077 != 0 {
		checks = append(checks, Check{"key", Fail, fmt.Sprintf("PSK perms %v are too open, want 0600", info.Mode().Perm())})
	} else if _, err := keyfile.Load(c.KeyPath); err != nil {
		checks = append(checks, Check{"key", Fail, "PSK unreadable or not 32 bytes: " + err.Error()})
	} else {
		checks = append(checks, Check{"key", OK, "0600, 32 bytes"})
	}

	// config
	if c.Role != "source" && c.Role != "sink" {
		checks = append(checks, Check{"config", Fail, fmt.Sprintf("role must be source|sink, got %q", c.Role)})
	} else if _, _, err := net.SplitHostPort(c.Peer); err != nil {
		checks = append(checks, Check{"config", Fail, fmt.Sprintf("peer %q is not host:port", c.Peer)})
	} else {
		checks = append(checks, Check{"config", OK, c.Role + " " + c.Peer})
	}

	switch c.Role {
	case "source":
		for _, b := range c.Browsers {
			name := "vault:" + b.Profile
			if _, err := os.Stat(b.CookiePath); err != nil {
				checks = append(checks, Check{name, Fail, "cookie store unreadable: " + b.CookiePath})
			} else {
				checks = append(checks, Check{name, OK, b.CookiePath})
			}
		}
		if c.SecretsDir != "" {
			if _, err := os.Stat(c.SecretsDir); err != nil {
				checks = append(checks, Check{"secrets_dir", Fail, "missing: " + c.SecretsDir})
			} else {
				checks = append(checks, Check{"secrets_dir", OK, c.SecretsDir})
			}
		}
	case "sink":
		if !isLoopbackBind(c.Peer) {
			checks = append(checks, Check{"bind", Warn, fmt.Sprintf("binding %s exposes the sink beyond loopback", c.Peer)})
		} else {
			checks = append(checks, Check{"bind", OK, "loopback"})
		}
		for _, name := range c.Surfaces {
			switch name {
			case "sidecar":
				checks = append(checks, Check{"surface:sidecar", OK, "plaintext sidecar"})
			case "chrome":
				if len(c.Browsers) == 0 {
					checks = append(checks, Check{"surface:chrome", Fail, "chrome surface needs a [[browsers]] entry"})
				} else if _, err := os.Stat(c.Browsers[0].CookiePath); err != nil {
					checks = append(checks, Check{"surface:chrome", Fail, "target Cookies missing: " + c.Browsers[0].CookiePath})
				} else if singletonLockPresent(c.Browsers[0].CookiePath) {
					checks = append(checks, Check{"surface:chrome", Warn, "a SingletonLock suggests the target browser is running"})
				} else {
					checks = append(checks, Check{"surface:chrome", OK, c.Browsers[0].CookiePath})
				}
			case "secrets":
				if c.SecretsDir == "" {
					checks = append(checks, Check{"surface:secrets", Fail, "secrets surface needs secrets_dir"})
				} else if !writable(filepath.Dir(c.SecretsDir)) {
					checks = append(checks, Check{"surface:secrets", Fail, "secrets_dir parent not writable: " + c.SecretsDir})
				} else {
					checks = append(checks, Check{"surface:secrets", OK, c.SecretsDir})
				}
			default:
				checks = append(checks, Check{"surface:" + name, Fail, "unknown surface"})
			}
		}
	}
	return checks
}

func singletonLockPresent(cookiePath string) bool {
	dir := filepath.Dir(cookiePath)
	for _, p := range []string{filepath.Join(dir, "SingletonLock"), filepath.Join(filepath.Dir(dir), "SingletonLock")} {
		if _, err := os.Lstat(p); err == nil {
			return true
		}
	}
	return false
}

// PeerReachable dials peer with a timeout. role=source only; no data is sent.
func PeerReachable(peer string, timeout time.Duration) Check {
	conn, err := net.DialTimeout("tcp", peer, timeout)
	if err != nil {
		return Check{"peer", Fail, "unreachable: " + err.Error()}
	}
	conn.Close()
	return Check{"peer", OK, "reachable " + peer}
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/doctor/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/doctor/doctor.go internal/doctor/doctor_test.go
git commit -m "feat: add doctor pure checks and peer reachability"
```

---

### Task 4: doctor peer-reachable network test

**Files:** Modify `internal/doctor/doctor_test.go`

- [ ] **Step 1: Add the failing test**

Append to `internal/doctor/doctor_test.go`:
```go
import_block_note: add "net" and "time" to the existing import block of this test file.

func TestPeerReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if PeerReachable(ln.Addr().String(), time.Second).Status != OK {
		t.Fatal("listening peer must be reachable")
	}
}

func TestPeerUnreachable(t *testing.T) {
	// Port 1 on loopback is not listening.
	if PeerReachable("127.0.0.1:1", 500*time.Millisecond).Status != Fail {
		t.Fatal("closed port must be unreachable")
	}
}
```
Add the `net` and `time` imports to the test file's import block (alongside `os`, `path/filepath`, `testing`, and the internal config/keyfile imports). Do not duplicate the `import_block_note` line - it is guidance, not code; delete it.

- [ ] **Step 2: Run, verify pass (the impl already exists from Task 3)**

Run: `go test ./internal/doctor/`
Expected: PASS (PeerReachable was implemented in Task 3; this task adds its tests).

- [ ] **Step 3: Commit**

```bash
git add internal/doctor/doctor_test.go
git commit -m "test: cover doctor peer reachability"
```

---

### Task 5: CLI wiring - doctor, status state, --stdio

**Files:** Modify `cmd/agentpantry/main.go`

- [ ] **Step 1: Add imports and the doctor/state packages**

Add to the import block of `cmd/agentpantry/main.go`:
```go
	"github.com/escoffier-labs/agentpantry/internal/doctor"
	"github.com/escoffier-labs/agentpantry/internal/state"
```

- [ ] **Step 2: Register the doctor command**

In `main()`'s switch, add a case and update `usage()`:
```go
	case "doctor":
		err = cmdDoctor(args)
```
Update the usage string to include `doctor`:
```go
	fmt.Fprintln(os.Stderr, "usage: agentpantry <init|keygen|source|sink|doctor|status|install-service> [flags]")
```

- [ ] **Step 3: Add a statePath helper and wire state into cmdSource**

Add near `loadConfig`:
```go
func statePath() string {
	return filepath.Join(config.Dir(), "state.json")
}
```

In `cmdSource`, add a `-stdio` flag and the state-writing `AfterSync` hook. Replace the current flag-less body's start and the Syncer/transport section. The new `cmdSource`:
```go
func cmdSource(args []string) error {
	fs := flag.NewFlagSet("source", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	stdio := fs.Bool("stdio", false, "stream frames to stdout instead of dialing the peer")
	fs.Parse(args)

	c, err := config.Load(*cfgPath)
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
	var secretReaders []source.SecretReader
	if c.SecretsDir != "" {
		secretReaders = append(secretReaders, &secretsrc.DirReader{Dir: c.SecretsDir})
		if _, statErr := os.Stat(c.SecretsDir); statErr == nil {
			paths = append(paths, c.SecretsDir)
		}
	}

	var out io.Writer
	if *stdio {
		out = os.Stdout
	} else {
		conn, derr := net.Dial("tcp", c.Peer)
		if derr != nil {
			return fmt.Errorf("dial sink %s: %w", c.Peer, derr)
		}
		defer conn.Close()
		out = conn
	}

	clock := state.RealClock{}
	syncer := &source.Syncer{
		Vaults:  vs,
		Secrets: secretReaders,
		Policy:  c.Domains,
		Sealer:  sealer,
		Out:     out,
		AfterSync: func(sent bool, cookies, secrets int) {
			st, _ := state.Load(statePath())
			now := clock.Now().Unix()
			st.LastSyncUnix = now
			if sent {
				st.LastSentUnix = now
				st.Cookies = cookies
				st.Secrets = secrets
			}
			if err := state.Save(statePath(), st); err != nil {
				fmt.Fprintln(os.Stderr, "warning: could not write state:", err)
			}
		},
	}
	ctx := signalCtx()
	if *stdio {
		fmt.Fprintf(os.Stderr, "source: watching %d store(s), streaming frames to stdout\n", len(paths))
	} else {
		fmt.Printf("source: watching %d store(s), pushing to %s\n", len(paths), c.Peer)
	}
	return syncer.Watch(ctx, paths, 500*time.Millisecond)
}
```
Note: this requires `io` in the import block (add it).

- [ ] **Step 4: Add --stdio to cmdSink**

Add a `-stdio` flag to `cmdSink`. After building the surfaces (the `for _, name := range c.Surfaces` block and its `defer` closer), branch before the listener:
```go
	ctx := signalCtx()

	if *stdio {
		opener, oerr := transport.NewOpener(key)
		if oerr != nil {
			return oerr
		}
		srv := &sink.Server{Opener: opener, CookieSurfaces: cookieSurfaces, SecretSurfaces: secretSurfaces}
		fmt.Fprintf(os.Stderr, "sink: reading frames from stdin, surfaces %v\n", c.Surfaces)
		return srv.Serve(ctx, os.Stdin)
	}

	ln, err := net.Listen("tcp", c.Peer)
	...
```
To add the flag, change the top of `cmdSink` from `loadConfig(args)` to its own FlagSet:
```go
func cmdSink(args []string) error {
	fs := flag.NewFlagSet("sink", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	stdio := fs.Bool("stdio", false, "read frames from stdin instead of listening on a port")
	fs.Parse(args)
	c, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	// ... rest unchanged (key load, surface building) ...
```
Keep the rest of `cmdSink` (surface construction, the `defer` closers, and the network accept loop) as-is; only insert the `if *stdio { ... }` branch after `ctx := signalCtx()` and before `net.Listen`.

- [ ] **Step 5: Add cmdDoctor**

```go
func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	timeout := fs.Duration("timeout", 3*time.Second, "peer reachability dial timeout")
	skipNet := fs.Bool("no-net", false, "skip the peer reachability check")
	fs.Parse(args)

	c, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	checks := doctor.Run(c)
	if c.Role == "source" && !*skipNet {
		checks = append(checks, doctor.PeerReachable(c.Peer, *timeout))
	}
	for _, ck := range checks {
		fmt.Printf("[%-4s] %s: %s\n", ck.Status, ck.Name, ck.Detail)
	}
	if doctor.HasFail(checks) {
		return fmt.Errorf("doctor found problems")
	}
	return nil
}
```
(The `[%-4s]` uses `Status.String()`.)

- [ ] **Step 6: Update cmdStatus to report last-sync state**

In `cmdStatus`, after loading config, load state and include it. Add before the `*jsonOut` branch:
```go
	st, _ := state.Load(statePath())
	lastSync := "never"
	if st.LastSyncUnix > 0 {
		lastSync = time.Unix(st.LastSyncUnix, 0).Format(time.RFC3339)
	}
```
In the JSON payload map, add:
```go
		"last_sync":   lastSync,
		"last_cookies": st.Cookies,
		"last_secrets": st.Secrets,
```
In the text output, append a line:
```go
	fmt.Printf("last sync: %s (cookies %d, secrets %d)\n", lastSync, st.Cookies, st.Secrets)
```
(Add `"time"` to imports if not present - it already is.)

- [ ] **Step 7: Build, vet, smoke test**

Run:
```bash
go build ./... && go vet ./...
export XDG_CONFIG_HOME=$(mktemp -d)
go run ./cmd/agentpantry init --role sink
go run ./cmd/agentpantry keygen
go run ./cmd/agentpantry doctor --no-net ; echo "exit=$?"
go run ./cmd/agentpantry status
```
Expected: build/vet clean; `doctor` prints OK lines and exits 0; `status` shows `last sync: never`.

- [ ] **Step 8: Commit**

```bash
git add cmd/agentpantry/main.go
git commit -m "feat: add doctor command, status last-sync, and --stdio mode"
```

---

### Task 6: integration tests + docs

**Files:** Modify `test/integration_test.go`, `README.md`, `CHANGELOG.md`

- [ ] **Step 1: Add stdio + state integration tests**

Append to `test/integration_test.go` (reuse the existing helpers `newPipe`, and the `sink`, `source`, `surface`, `transport`, `cookie`, `policy` imports already present; add `state` import):
```go
func TestStdioPipeEndToEnd(t *testing.T) {
	dir := t.TempDir()
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
		Vaults: []source.CookieReader{fixedCookie{c: cookie.Cookie{Host: "github.com", Name: "sid", Path: "/", Value: "v"}}},
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

	db, _ := sql.Open("sqlite", sidecarPath)
	defer db.Close()
	var got string
	if err := db.QueryRow(`SELECT value FROM cookies WHERE host=?`, "github.com").Scan(&got); err != nil || got != "v" {
		t.Fatalf("stdio pipe did not deliver cookie: %q / %v", got, err)
	}
}

func TestStatePersistsAcrossSyncs(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "state.json")

	st, _ := state.Load(sp)
	if st.LastSyncUnix != 0 {
		t.Fatal("fresh state must be never-synced")
	}

	sealer, _ := transport.NewSealer(make([]byte, 32))
	syncer := &source.Syncer{
		Vaults: []source.CookieReader{fixedCookie{c: cookie.Cookie{Host: "github.com", Name: "s", Path: "/", Value: "1"}}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    discard{},
		AfterSync: func(sent bool, cookies, secrets int) {
			s2, _ := state.Load(sp)
			s2.LastSyncUnix = 1700000000
			if sent {
				s2.LastSentUnix = 1700000000
				s2.Cookies = cookies
			}
			state.Save(sp, s2)
		},
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := state.Load(sp)
	if got.LastSyncUnix == 0 || got.Cookies != 1 {
		t.Fatalf("state not persisted: %+v", got)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
```
Add `"github.com/escoffier-labs/agentpantry/internal/state"` to the import block.

- [ ] **Step 2: Run, verify pass**

Run: `go test ./test/`
Expected: PASS.

- [ ] **Step 3: Full suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all PASS, vet clean.

- [ ] **Step 4: Update docs**

In `README.md`, add a short "Operating" section documenting `pantry doctor` (what it checks, exit codes), the enriched `status` (last sync time + counts), and `--stdio` with the `pantry source --stdio | ssh sink pantry sink --stdio` example (use `sink.example` or `127.0.0.1`, never a private IP or the bare word localhost). In `CHANGELOG.md` under `## Unreleased` -> `### Added`, add bullets for the doctor command, last-sync state in status, and `--stdio` transport.

- [ ] **Step 5: Commit**

```bash
git add test/integration_test.go README.md CHANGELOG.md
git commit -m "test: cover stdio and state e2e; document operability"
```

---

## Self-Review Notes

- **Spec coverage:** state (spec 2) -> Tasks 1,2,5,6; doctor (spec 3) -> Tasks 3,4,5; --stdio (spec 4) -> Task 5; testing (spec 7) -> every task + Task 6. No config schema change (spec 5). Security (spec 6): state 0600 (Task 1), doctor never prints values (Task 3 Detail strings are paths/states only), bind warn (Task 3).
- **Type consistency:** `state.State`/`Load`/`Save`/`Clock`/`RealClock` (Task 1) used in 5,6. `source.Syncer.AfterSync func(bool,int,int)` (Task 2) used in 5,6. `doctor.Check`/`Status`/`OK`/`Warn`/`Fail`/`Run`/`PeerReachable`/`HasFail` (Task 3) used in 4,5. `fixedCookie` reused from the Phase 2 integration test (already defined in test/integration_test.go) - Task 6 does not redefine it.
- **No new wire format or config schema** -> no breaking change, no owner approval gate triggered.
- **Placeholder scan:** Task 4's `import_block_note` is explicitly flagged as guidance to delete, not code. Every other step is complete code. README (Task 6) enumerates required sections.
- **Existing tests:** source's other tests omit `AfterSync` (nil hook, safely skipped); status's existing `--json` path is extended, not replaced.
