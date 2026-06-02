# agentpantry T2 Implementation Plan (robustness)

> REQUIRED SUB-SKILL: subagent-driven-development / executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** Source auto-reconnect with capped backoff; a periodic resync ticker on `Watch`; CDP interval polling. Base branch `t2-robustness` off master.

---

### Task 1: Syncer.Reset + Backoff + Watch resync ticker

**Files:** Modify `internal/source/source.go`, `internal/source/watch_test.go`; Test `internal/source/reset_test.go`, `internal/source/backoff_test.go`

- [ ] **Step 1: Failing tests**

`internal/source/backoff_test.go`:
```go
package source

import (
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	cases := map[int]time.Duration{0: time.Second, 1: 2 * time.Second, 2: 4 * time.Second, 3: 8 * time.Second, 4: 16 * time.Second, 5: 30 * time.Second, 9: 30 * time.Second}
	for attempt, want := range cases {
		if got := Backoff(attempt); got != want {
			t.Errorf("Backoff(%d) = %v, want %v", attempt, got, want)
		}
	}
}
```

`internal/source/reset_test.go`:
```go
package source

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

func TestResetResendsFullState(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	var buf bytes.Buffer
	s := &Syncer{
		Vaults: []CookieReader{oneVault{cs: []cookie.Cookie{{Host: "github.com", Name: "a", Path: "/", Value: "1"}}}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
	}
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := buf.Len()
	// No change -> nothing re-sent.
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != first {
		t.Fatal("unchanged state should not resend")
	}
	// After Reset, the full state is resent.
	s.Reset()
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == first {
		t.Fatal("Reset should force a full resend")
	}
	// Confirm the resent frame carries the cookie.
	transport.ReadFrame(&buf) // skip first frame
	frame, _ := transport.ReadFrame(&buf)
	opener, _ := transport.NewOpener(make([]byte, 32), make([]byte, 16))
	// fresh opener counter starts at 0; the resent frame is counter 2, accepted.
	raw, err := opener.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	var p wire.Payload
	json.Unmarshal(raw, &p)
	if len(p.Cookies.Upserts) != 1 {
		t.Fatalf("resend should include the cookie, got %+v", p.Cookies.Upserts)
	}
}
```
Note: the opener in this test only opens the second-read frame; since a fresh opener's `lastCounter` is 0 and that frame's counter is 2, it is accepted. (The first ReadFrame is discarded without opening.)

`internal/source/watch_test.go`: update the existing `Watch(ctx, []string{watched}, 20*time.Millisecond)` call to pass a resync arg (`0` to keep current behavior), and add a resync-only test:
```go
func TestWatchPeriodicResync(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
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
	// No watched paths: only the resync ticker drives SyncOnce.
	go func() { done <- syncer.Watch(ctx, nil, 10*time.Millisecond, 25*time.Millisecond) }()
	time.Sleep(120 * time.Millisecond)
	cancel()
	<-done
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.calls < 2 {
		t.Fatalf("resync ticker should fire repeatedly, got %d calls", v.calls)
	}
}
```
(`countingVault` already exists in watch_test.go with a `calls` counter and `mu`.)

- [ ] **Step 2: Run, verify fail** — `go test ./internal/source/` (Backoff/Reset undefined; Watch arity).

- [ ] **Step 3: Implement**

Add to `internal/source/source.go`:
```go
// Reset clears the previous snapshots so the next SyncOnce resends full state.
// Used after a (re)connect, since the peer starts a fresh session.
func (s *Syncer) Reset() {
	s.prev = cookie.Snapshot{}
	s.prevSecrets = secret.Snapshot{}
}

// Backoff returns a capped exponential delay for reconnect attempt n (0-based):
// 1s, 2s, 4s, 8s, 16s, then 30s.
func Backoff(attempt int) time.Duration {
	const base = time.Second
	const max = 30 * time.Second
	d := base << attempt
	if attempt >= 5 || d > max || d <= 0 {
		return max
	}
	return d
}
```

Change `Watch` to take a `resync time.Duration` and add a ticker:
```go
func (s *Syncer) Watch(ctx context.Context, paths []string, debounce, resync time.Duration) error {
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

	var resyncC <-chan time.Time
	if resync > 0 {
		tk := time.NewTicker(resync)
		defer tk.Stop()
		resyncC = tk.C
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
		case <-resyncC:
			if err := s.SyncOnce(ctx); err != nil {
				return err
			}
		}
	}
}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/source/`.

- [ ] **Step 5: Commit**
```bash
git add internal/source/
git commit -m "feat: add syncer reset, reconnect backoff, and resync ticker"
```

---

### Task 2: config + cmdSource reconnect loop + cdp polling

**Files:** Modify `internal/config/config.go`, `internal/config/config_test.go`, `cmd/agentpantry/main.go`

- [ ] **Step 1: config field + test** — add to `Config`: `ResyncSeconds int `toml:"resync_seconds"``. Append a round-trip test asserting `ResyncSeconds` persists.

- [ ] **Step 2: Restructure cmdSource** — build the Syncer once (without Sealer/Out), compute the resync interval, then branch:
```go
	resync := time.Duration(c.ResyncSeconds) * time.Second
	hasCDP := false
	for _, b := range c.Browsers {
		if b.Kind == "cdp" {
			hasCDP = true
		}
	}
	if hasCDP && resync == 0 {
		resync = 60 * time.Second
		fmt.Fprintln(os.Stderr, "agentpantry: cdp source detected, defaulting resync to 60s")
	}

	clock := state.RealClock{}
	sp := statePath(*cfgPath)
	syncer := &source.Syncer{
		Vaults:       vs,
		Secrets:      secretReaders,
		Policy:       c.Domains,
		SecretPolicy: c.SecretNames,
		AfterSync: func(sent bool, cookies, secrets int) {
			st, _ := state.Load(sp)
			now := clock.Now().Unix()
			st.LastSyncUnix = now
			if sent {
				st.LastSentUnix = now
				st.Cookies = cookies
				st.Secrets = secrets
			}
			if err := state.Save(sp, st); err != nil {
				fmt.Fprintln(os.Stderr, "warning: could not write state:", err)
			}
		},
	}
	ctx := signalCtx()

	if *stdio {
		salt, serr := transport.SendSalt(os.Stdout)
		if serr != nil {
			return serr
		}
		sealer, serr := transport.NewSealer(key, salt)
		if serr != nil {
			return serr
		}
		syncer.Sealer = sealer
		syncer.Out = os.Stdout
		fmt.Fprintf(os.Stderr, "source: watching %d store(s), streaming frames to stdout\n", len(paths))
		return syncer.Watch(ctx, paths, 500*time.Millisecond, resync)
	}

	// TCP: reconnect with capped backoff.
	fmt.Printf("source: watching %d store(s), pushing to %s\n", len(paths), c.Peer)
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		conn, derr := net.Dial("tcp", c.Peer)
		if derr != nil {
			if !sleepCtx(ctx, source.Backoff(attempt)) {
				return nil
			}
			attempt++
			continue
		}
		conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		salt, herr := transport.RecvSalt(conn)
		if herr != nil {
			conn.Close()
			if !sleepCtx(ctx, source.Backoff(attempt)) {
				return nil
			}
			attempt++
			continue
		}
		conn.SetReadDeadline(time.Time{})
		sealer, serr := transport.NewSealer(key, salt)
		if serr != nil {
			conn.Close()
			return serr
		}
		syncer.Sealer = sealer
		syncer.Out = conn
		syncer.Reset()
		attempt = 0
		werr := syncer.Watch(ctx, paths, 500*time.Millisecond, resync)
		conn.Close()
		if ctx.Err() != nil {
			return nil
		}
		fmt.Fprintln(os.Stderr, "source: connection lost, reconnecting:", werr)
		if !sleepCtx(ctx, source.Backoff(attempt)) {
			return nil
		}
		attempt++
	}
}

// sleepCtx waits d or until ctx is done; returns false if ctx was cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
```
Remove the now-replaced single-dial block, the old `out`/`salt`/`sealer` construction, and the trailing single `Watch` call. Keep `buildVaults`, `secretReaders`, and `paths` setup above this.

- [ ] **Step 3: Build, vet, test, windows** — `go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...`.

- [ ] **Step 4: Live loopback smoke** — in a temp `XDG_CONFIG_HOME`: init a sink (sidecar) + source pointing at a fake chromium cookie DB and `127.0.0.1:<port>`; same PSK; start sink, start source (background), confirm the sidecar gets the cookie; kill the sink; confirm the source logs reconnect attempts; restart the sink; confirm the sidecar is repopulated (full resend after Reset). Record the result. (If a full live harness is impractical, at minimum start source with no sink and confirm it retries with backoff rather than exiting.)

- [ ] **Step 5: Commit**
```bash
git add internal/config/ cmd/agentpantry/main.go
git commit -m "feat: source auto-reconnect with backoff and cdp resync polling"
```

---

### Task 3: docs

**Files:** `CHANGELOG.md`, `README.md`

- [ ] **Step 1: Docs** — CHANGELOG Unreleased/Added: source auto-reconnect with capped backoff; `resync_seconds` periodic resync; cdp sources poll (default 60s). README: document `resync_seconds` and that a TCP source reconnects automatically and resends full state on reconnect; note cdp sources poll. No em dashes/private IPs/hostnames.

- [ ] **Step 2: Final verify** — `go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...`.

- [ ] **Step 3: Commit**
```bash
git add CHANGELOG.md README.md
git commit -m "docs: document reconnect and resync"
```

---

## Self-Review Notes

- **Spec coverage:** reconnect (spec 2) -> Task 2 + Backoff/Reset (Task 1); resync ticker (spec 3) -> Task 1 + wiring Task 2; cdp polling (spec 4) -> Task 2; config (spec 5) -> Task 2.
- **Type consistency:** `Syncer.Reset()`, `Backoff(int) time.Duration`, `Watch(ctx,paths,debounce,resync)` (Task 1) used by main.go (Task 2). `sleepCtx` helper local to main.go. `handshakeTimeout` const already exists in main.go (T1); reused for the source read deadline.
- **Watch arity change** updates its only non-test caller (cmdSource) and the watch_test caller in the same plan.
- **No placeholders.**
