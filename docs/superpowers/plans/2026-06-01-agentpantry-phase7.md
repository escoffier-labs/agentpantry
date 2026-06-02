# agentpantry Phase 7 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or executing-plans. The spike decision (docs/superpowers/specs/2026-06-01-agentpantry-phase7-spike-decision.md) is committed; this plan implements its CHOSEN approach (CDP). Steps use checkbox (`- [ ]`).

**Goal:** Support Chrome v127+ app-bound (`v20`) cookies by exporting them through Chrome's DevTools Protocol (`Network.getAllCookies`), since Chrome decrypts its own cookies over that supported API. Add a `kind = "cdp"` browser reader, plus doctor reachability and docs.

**Architecture:** `internal/cdpvault.CDP` implements `source.CookieReader`: discover a target's WebSocket debugger URL via `GET <base>/json`, open the WebSocket, send `Network.getAllCookies`, map the decrypted cookies into the normalized model. Cross-platform (CDP works everywhere); no build tags. CI-tested against a fake HTTP+WebSocket server (no real Chrome needed).

**Tech Stack:** Go 1.25; adds `github.com/gorilla/websocket`. Module `github.com/escoffier-labs/agentpantry`.

Base branch: `phase-7` (already created; spike doc committed on it).

---

### Task 1: config URL field for CDP

**Files:** Modify `internal/config/config.go`; Test `internal/config/config_test.go`

- [ ] **Step 1: Failing test** — append to `internal/config/config_test.go`:
```go
func TestBrowserURLRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("source")
	in.Browsers = []BrowserRef{{Kind: "cdp", Profile: "chrome", URL: "http://127.0.0.1:9222"}}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Browsers) != 1 || out.Browsers[0].URL != "http://127.0.0.1:9222" {
		t.Fatalf("URL field lost: %+v", out.Browsers)
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/config/ -run BrowserURL` (FAIL: `URL` undefined).

- [ ] **Step 3: Implement** — add `URL` to `BrowserRef` in `internal/config/config.go`:
```go
type BrowserRef struct {
	Kind       string `toml:"kind"`        // "chromium" | "firefox" | "cdp"
	Profile    string `toml:"profile"`
	CookiePath string `toml:"cookie_path"`
	URL        string `toml:"url"`         // cdp: DevTools base URL, e.g. http://127.0.0.1:9222
}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/config/`.

- [ ] **Step 5: Commit**
```bash
git add internal/config/
git commit -m "feat: add url field to browser ref for cdp"
```

---

### Task 2: CDP reader

**Files:** Create `internal/cdpvault/cdp.go`; Test `internal/cdpvault/cdp_test.go`

- [ ] **Step 1: Add the websocket dependency** — `go get github.com/gorilla/websocket@latest`.

- [ ] **Step 2: Failing test** — `internal/cdpvault/cdp_test.go`:
```go
package cdpvault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/gorilla/websocket"
)

func fakeCDPServer(t *testing.T) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		ws := "ws://" + r.Host + "/devtools/page/ABC"
		json.NewEncoder(w).Encode([]map[string]any{
			{"type": "page", "webSocketDebuggerUrl": ws},
		})
	})
	mux.HandleFunc("/devtools/page/ABC", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		var cmd struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if err := c.ReadJSON(&cmd); err != nil {
			return
		}
		resp := map[string]any{
			"id": cmd.ID,
			"result": map[string]any{
				"cookies": []map[string]any{
					{"name": "sid", "value": "v20-session", "domain": ".github.com", "path": "/",
						"expires": 1637000000.0, "secure": true, "httpOnly": true, "sameSite": "Lax"},
					{"name": "s", "value": "sess", "domain": "x.com", "path": "/",
						"expires": -1.0, "secure": false, "httpOnly": false, "sameSite": "None"},
				},
			},
		}
		c.WriteJSON(resp)
	})
	srv = httptest.NewServer(mux)
	return srv
}

func TestCDPReadCookies(t *testing.T) {
	srv := fakeCDPServer(t)
	defer srv.Close()

	c := &CDP{BaseURL: srv.URL}
	cs, err := c.ReadCookies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 {
		t.Fatalf("want 2 cookies, got %d", len(cs))
	}
	var sid cookie.Cookie
	for _, ck := range cs {
		if ck.Name == "sid" {
			sid = ck
		}
	}
	if sid.Host != ".github.com" || sid.Value != "v20-session" || !sid.IsSecure || !sid.IsHTTPOnly || sid.SameSite != 1 {
		t.Fatalf("unexpected sid cookie: %+v", sid)
	}
	if sid.ExpiresUTC != cookie.ExpiresFromUnix(1637000000) {
		t.Fatalf("expiry not converted: %d", sid.ExpiresUTC)
	}
	// session cookie (-1) maps to 0
	for _, ck := range cs {
		if ck.Name == "s" && ck.ExpiresUTC != 0 {
			t.Fatalf("session cookie expiry should be 0, got %d", ck.ExpiresUTC)
		}
	}
}

func TestCDPNoEndpointErrors(t *testing.T) {
	c := &CDP{BaseURL: "http://127.0.0.1:1"}
	if _, err := c.ReadCookies(context.Background()); err == nil {
		t.Fatal("unreachable endpoint must error")
	}
}

func TestCDPRejectsNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := &CDP{BaseURL: srv.URL}
	if _, err := c.ReadCookies(context.Background()); err == nil {
		t.Fatal("non-200 /json must error")
	}
	_ = strings.TrimSpace("")
}
```

- [ ] **Step 3: Run, verify fail** — `go test ./internal/cdpvault/` (FAIL: `undefined: CDP`).

- [ ] **Step 4: Implement** — `internal/cdpvault/cdp.go`:
```go
package cdpvault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/gorilla/websocket"
)

// CDP reads cookies from a running Chromium via the DevTools Protocol. Chrome
// decrypts its own cookies, so this works for app-bound (v20) profiles.
type CDP struct {
	BaseURL string // e.g. http://127.0.0.1:9222
}

func (c *CDP) Name() string { return "cdp:" + c.BaseURL }

type cdpTarget struct {
	Type                 string `json:"type"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

func (c *CDP) wsURL(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/json", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("CDP /json returned %d", resp.StatusCode)
	}
	var targets []cdpTarget
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return "", err
	}
	for _, t := range targets {
		if t.WebSocketDebuggerURL != "" && (t.Type == "page" || t.Type == "") {
			return t.WebSocketDebuggerURL, nil
		}
	}
	for _, t := range targets {
		if t.WebSocketDebuggerURL != "" {
			return t.WebSocketDebuggerURL, nil
		}
	}
	return "", fmt.Errorf("no DevTools target with a websocket URL at %s", c.BaseURL)
}

type cdpCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	Secure   bool    `json:"secure"`
	HTTPOnly bool    `json:"httpOnly"`
	SameSite string  `json:"sameSite"`
}

func sameSiteCode(s string) int {
	switch s {
	case "Strict":
		return 2
	case "Lax":
		return 1
	default:
		return 0
	}
}

func (c *CDP) ReadCookies(ctx context.Context) ([]cookie.Cookie, error) {
	ws, err := c.wsURL(ctx)
	if err != nil {
		return nil, err
	}
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, ws, nil)
	if err != nil {
		return nil, fmt.Errorf("dial devtools websocket: %w", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(map[string]any{"id": 1, "method": "Network.getAllCookies"}); err != nil {
		return nil, err
	}

	for {
		var msg struct {
			ID     int `json:"id"`
			Result struct {
				Cookies []cdpCookie `json:"cookies"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := conn.ReadJSON(&msg); err != nil {
			return nil, err
		}
		if msg.ID != 1 {
			continue // skip CDP events
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("CDP error: %s", msg.Error.Message)
		}
		out := make([]cookie.Cookie, 0, len(msg.Result.Cookies))
		for _, cc := range msg.Result.Cookies {
			var exp int64
			if cc.Expires > 0 {
				exp = cookie.ExpiresFromUnix(int64(cc.Expires))
			}
			out = append(out, cookie.Cookie{
				Host: cc.Domain, Name: cc.Name, Value: cc.Value, Path: cc.Path,
				ExpiresUTC: exp, IsSecure: cc.Secure, IsHTTPOnly: cc.HTTPOnly,
				SameSite: sameSiteCode(cc.SameSite),
			})
		}
		return out, nil
	}
}
```

- [ ] **Step 5: Run, verify pass** — `go test ./internal/cdpvault/`.

- [ ] **Step 6: Commit**
```bash
git add internal/cdpvault/ go.mod go.sum
git commit -m "feat: add cdp cookie reader for app-bound chrome"
```

---

### Task 3: wire kind=cdp + doctor reachability

**Files:** Modify `cmd/agentpantry/main.go`, `internal/doctor/doctor.go`; Test `internal/doctor/doctor_test.go`

- [ ] **Step 1: buildVaults cdp case** — in `cmd/agentpantry/main.go`, add to the `switch b.Kind` in `buildVaults` (add the `cdpvault` import):
```go
		case "cdp":
			vs = append(vs, &cdpvault.CDP{BaseURL: b.URL})
```
(No watched path is added for cdp; document that cdp readers sync at startup and on other browsers' file events.)

- [ ] **Step 2: doctor test** — append to `internal/doctor/doctor_test.go`:
```go
func TestCDPBrowserReachabilityCheck(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	// Unreachable CDP endpoint -> Fail.
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{Kind: "cdp", Profile: "p", URL: "http://127.0.0.1:1"}},
	}
	if find(Run(c), "cdp:p").Status != Fail {
		t.Fatal("unreachable cdp endpoint must Fail")
	}
}
```

- [ ] **Step 3: Run, verify fail** — `go test ./internal/doctor/ -run CDP`.

- [ ] **Step 4: doctor cdp check** — in `internal/doctor/doctor.go`, in the source `for _, b := range c.Browsers` vault loop, special-case cdp (it has no cookie file to stat). Replace the loop body so a `cdp` kind checks URL reachability instead of a file:
```go
		for _, b := range c.Browsers {
			if b.Kind == "cdp" {
				name := "cdp:" + b.Profile
				client := &http.Client{Timeout: 2 * time.Second}
				resp, err := client.Get(b.URL + "/json")
				if err != nil {
					checks = append(checks, Check{name, Fail, "CDP endpoint unreachable: " + b.URL})
				} else {
					resp.Body.Close()
					checks = append(checks, Check{name, OK, b.URL})
				}
				continue
			}
			name := "vault:" + b.Profile
			if _, err := os.Stat(b.CookiePath); err != nil {
				checks = append(checks, Check{name, Fail, "cookie store unreadable: " + b.CookiePath})
			} else {
				checks = append(checks, Check{name, OK, b.CookiePath})
			}
		}
```
Add `"net/http"` to doctor's imports (`time` is already imported). The `hasChromium` computation below it is unaffected (cdp is not chromium, so a cdp-only source still skips the keyring check).

- [ ] **Step 5: Run, verify pass + build/vet** — `go test ./internal/doctor/ ./internal/config/ ./internal/cdpvault/ && go build ./... && go vet ./... && GOOS=windows go build ./...`.

- [ ] **Step 6: Commit**
```bash
git add cmd/agentpantry/main.go internal/doctor/
git commit -m "feat: wire cdp browser kind and doctor reachability"
```

---

### Task 4: integration test + docs

**Files:** Modify `test/integration_test.go`, `README.md`, `CHANGELOG.md`

- [ ] **Step 1: cdp e2e test** — append to `test/integration_test.go` (add the `cdpvault`, `net/http`, `net/http/httptest`, and `github.com/gorilla/websocket` imports; `encoding/json` may be needed):
```go
func TestEndToEndCDPToSidecar(t *testing.T) {
	up := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"type": "page", "webSocketDebuggerUrl": "ws://" + r.Host + "/devtools/page/A"},
		})
	})
	mux.HandleFunc("/devtools/page/A", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		var cmd struct {
			ID int `json:"id"`
		}
		c.ReadJSON(&cmd)
		c.WriteJSON(map[string]any{"id": cmd.ID, "result": map[string]any{"cookies": []map[string]any{
			{"name": "sid", "value": "appbound", "domain": "github.com", "path": "/", "expires": -1.0, "secure": true, "httpOnly": true, "sameSite": "Lax"},
		}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

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
		Vaults: []source.CookieReader{&cdpvault.CDP{BaseURL: srv.URL}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    pw,
	}
	ssrv := &sink.Server{Opener: opener, CookieSurfaces: []sink.CookieSurface{sc}}
	done := make(chan error, 1)
	go func() { done <- ssrv.Serve(context.Background(), pr) }()
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
	if err := db.QueryRow(`SELECT value FROM cookies WHERE host=?`, "github.com").Scan(&got); err != nil || got != "appbound" {
		t.Fatalf("cdp cookie did not sync: %q / %v", got, err)
	}
}
```

- [ ] **Step 2: Run, verify pass** — `go test ./test/`.

- [ ] **Step 3: Full suite + cross-compile** — `go build ./... && go vet ./... && go test ./... && GOOS=windows go build ./...`.

- [ ] **Step 4: Docs** — README: add an "App-bound Chrome (v127+) via CDP" section: run Chrome with `--remote-debugging-port=9222` (bound to loopback, ideally a dedicated automation profile), configure a `kind = "cdp"` browser with `url = "http://127.0.0.1:9222"`; note this is how app-bound `v20` cookies are exported (Chrome decrypts them), that the debugging port is sensitive (loopback only), and that a cdp reader currently syncs at startup (continuous polling is a follow-on). CHANGELOG Unreleased/Added: cdp reader bullet. No em dashes, no machine hostnames, no private LAN IPs (127.0.0.1 is fine).

- [ ] **Step 5: Commit**
```bash
git add test/integration_test.go README.md CHANGELOG.md
git commit -m "test: cdp e2e; document app-bound chrome via cdp"
```

---

## Self-Review Notes

- **Spike alignment:** implements the spike's CHOSEN option (CDP `Network.getAllCookies`); the detection/warning fallback (option 4) is partially realized via the doctor reachability check + README guidance.
- **Type consistency:** `cdpvault.CDP` implements `source.CookieReader`; `cookie.ExpiresFromUnix` (P4) reused; `config.BrowserRef.URL` (Task 1) used by buildVaults (Task 3) and doctor (Task 3). `sameSiteCode` maps CDP strings to the 0/1/2 the model uses.
- **Config change is additive** (new optional `url` field) -> not breaking, no owner gate.
- **Cross-platform:** CDP needs no build tags; `go build`/`GOOS=windows go build` both compile.
- **Known limitation (documented):** a cdp-only source syncs at startup and on other browsers' fsnotify events but does not yet poll on an interval; noted in README as a follow-on.
- **Validation:** after merge, validate on the Windows host by launching real app-bound Chrome with `--remote-debugging-port` and confirming v20 cookies export end-to-end.
