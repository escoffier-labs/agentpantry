# agentpantry Phase 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three config-driven per-CLI adapters as sink surfaces: a Netscape `cookies.txt` cookie surface, a `gh` hosts secret surface, and an OpenClaw `auth-profiles.json` secret surface. Pin the normalized cookie-expiry epoch contract.

**Architecture:** A new optional `[[adapters]]` config block lists adapters. Each adapter is a `CookieSurface` (netscape) or `SecretSurface` (gh, openclaw) in `internal/surface`. Netscape keeps an in-memory row set seeded from its own file (sink-restart safe) and rewrites the whole file per apply. gh and openclaw are merge-only and upsert-only so a transient secret blip never clobbers a working file. A cookie expiry helper pins the model's `ExpiresUTC` to microseconds-since-1601.

**Tech Stack:** Go 1.25 toolchain; adds `gopkg.in/yaml.v3` for the gh adapter; existing modernc.org/sqlite, toml, dbus. Module `github.com/escoffier-labs/agentpantry`.

Base branch: `phase-4` (create off master).

---

## File Structure

```
internal/cookie/expiry.go        # ExpiresUnix / ExpiresFromUnix + epoch contract
internal/surface/netscape.go     # Netscape (CookieSurface)
internal/surface/ghhosts.go      # GHHosts (SecretSurface)
internal/surface/openclawauth.go # OpenClawAuth (SecretSurface)
internal/config/config.go        # + AdapterRef, Config.Adapters
cmd/agentpantry/main.go          # build adapters in cmdSink
internal/doctor/doctor.go        # adapter checks
test/integration_test.go         # adapter e2e
README.md / CHANGELOG.md
```

---

### Task 1: cookie expiry epoch contract

**Files:** Create `internal/cookie/expiry.go`; Test `internal/cookie/expiry_test.go`

- [ ] **Step 1: Failing test**

`internal/cookie/expiry_test.go`:
```go
package cookie

import "testing"

func TestExpiryRoundTrip(t *testing.T) {
	// 2021-11-14T22:13:20Z == unix 1637000000.
	const unix = int64(1637000000)
	micros := ExpiresFromUnix(unix)
	if got := ExpiresUnix(micros); got != unix {
		t.Fatalf("round trip: got %d want %d", got, unix)
	}
}

func TestExpirySessionStaysZero(t *testing.T) {
	if ExpiresUnix(0) != 0 {
		t.Fatal("session expiry (0) must map to unix 0")
	}
	if ExpiresFromUnix(0) != 0 {
		t.Fatal("session expiry (0) must map to micros 0")
	}
}

func TestExpiryKnownEpoch(t *testing.T) {
	// 13_000_000_000_000_000 micros since 1601 == unix 1355000000 (approx 2012-12).
	if got := ExpiresUnix(13000000000000000); got != 13000000000000000/1_000_000-11644473600 {
		t.Fatalf("unexpected conversion: %d", got)
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/cookie/ -run Expiry`
Expected: FAIL `undefined: ExpiresFromUnix`.

- [ ] **Step 3: Implement**

`internal/cookie/expiry.go`:
```go
package cookie

// chromeEpochOffsetSeconds is the gap between 1601-01-01 and 1970-01-01 in seconds.
const chromeEpochOffsetSeconds = 11644473600

// Cookie.ExpiresUTC contract: microseconds since 1601-01-01 UTC (Chromium's
// native value); 0 means a session cookie. The Chromium reader produces this and
// the sidecar/chrome surfaces round-trip it. Other browser readers (Firefox)
// must convert their native expiry into this contract.

// ExpiresUnix converts the normalized expiry to Unix seconds (0 stays session).
func ExpiresUnix(micros1601 int64) int64 {
	if micros1601 <= 0 {
		return 0
	}
	return micros1601/1_000_000 - chromeEpochOffsetSeconds
}

// ExpiresFromUnix converts Unix seconds to the normalized contract (0 stays session).
func ExpiresFromUnix(unix int64) int64 {
	if unix <= 0 {
		return 0
	}
	return (unix + chromeEpochOffsetSeconds) * 1_000_000
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/cookie/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cookie/expiry.go internal/cookie/expiry_test.go
git commit -m "feat: pin cookie expiry epoch contract with unix converters"
```

---

### Task 2: Netscape cookies.txt adapter

**Files:** Create `internal/surface/netscape.go`; Test `internal/surface/netscape_test.go`

- [ ] **Step 1: Failing test**

`internal/surface/netscape_test.go`:
```go
package surface

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
)

func TestNetscapeWriteDeleteAndPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.txt")
	n, err := NewNetscape(path)
	if err != nil {
		t.Fatal(err)
	}
	c := cookie.Cookie{Host: ".github.com", Name: "sid", Path: "/", Value: "v", IsSecure: true, ExpiresUTC: cookie.ExpiresFromUnix(1637000000)}
	if err := n.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600, got %v", info.Mode().Perm())
	}
	body, _ := os.ReadFile(path)
	line := ""
	for _, l := range strings.Split(string(body), "\n") {
		if strings.Contains(l, "sid") {
			line = l
		}
	}
	cols := strings.Split(line, "\t")
	if len(cols) != 7 {
		t.Fatalf("want 7 tab cols, got %d (%q)", len(cols), line)
	}
	if cols[0] != ".github.com" || cols[1] != "TRUE" || cols[3] != "TRUE" || cols[4] != "1637000000" || cols[5] != "sid" || cols[6] != "v" {
		t.Fatalf("unexpected netscape line: %q", line)
	}

	if err := n.Apply(cookie.Diff{Deletes: []string{cookie.Key(c)}}); err != nil {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(path)
	if strings.Contains(string(body), "sid") {
		t.Fatal("cookie not deleted from file")
	}
}

func TestNetscapeSeedsFromExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.txt")
	// Pre-existing file (simulating a sink that restarted).
	os.WriteFile(path, []byte("# Netscape HTTP Cookie File\nexample.com\tFALSE\t/\tFALSE\t0\told\tval\n"), 0o600)
	n, err := NewNetscape(path)
	if err != nil {
		t.Fatal(err)
	}
	// Apply a new cookie; the seeded one must survive.
	c := cookie.Cookie{Host: "new.com", Name: "n", Path: "/", Value: "1"}
	if err := n.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "old") || !strings.Contains(string(body), "new.com") {
		t.Fatalf("seed lost on restart: %q", body)
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/surface/ -run Netscape`
Expected: FAIL `undefined: NewNetscape`.

- [ ] **Step 3: Implement**

`internal/surface/netscape.go`:
```go
package surface

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
)

type netscapeRow struct {
	domain     string
	includeSub bool
	path       string
	secure     bool
	expiry     int64 // unix seconds, 0=session
	name       string
	value      string
}

// Netscape writes a Netscape-format cookies.txt (curl/wget/yt-dlp).
type Netscape struct {
	path string
	rows map[string]netscapeRow // keyed by cookie.Key
}

func NewNetscape(path string) (*Netscape, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	n := &Netscape{path: path, rows: map[string]netscapeRow{}}
	if err := n.seed(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *Netscape) seed() error {
	f, err := os.Open(n.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 7 {
			continue
		}
		exp, _ := strconv.ParseInt(parts[4], 10, 64)
		r := netscapeRow{
			domain:     parts[0],
			includeSub: parts[1] == "TRUE",
			path:       parts[2],
			secure:     parts[3] == "TRUE",
			expiry:     exp,
			name:       parts[5],
			value:      parts[6],
		}
		n.rows[cookie.Key(cookie.Cookie{Host: r.domain, Name: r.name, Path: r.path})] = r
	}
	return sc.Err()
}

func (n *Netscape) Apply(d cookie.Diff) error {
	for _, c := range d.Upserts {
		n.rows[cookie.Key(c)] = netscapeRow{
			domain:     c.Host,
			includeSub: strings.HasPrefix(c.Host, "."),
			path:       c.Path,
			secure:     c.IsSecure,
			expiry:     cookie.ExpiresUnix(c.ExpiresUTC),
			name:       c.Name,
			value:      c.Value,
		}
	}
	for _, k := range d.Deletes {
		delete(n.rows, k)
	}
	return n.write()
}

func (n *Netscape) write() error {
	keys := make([]string, 0, len(n.rows))
	for k := range n.rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n")
	for _, k := range keys {
		r := n.rows[k]
		b.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			r.domain, boolTF(r.includeSub), r.path, boolTF(r.secure), r.expiry, r.name, r.value))
	}
	return os.WriteFile(n.path, []byte(b.String()), 0o600)
}

func boolTF(b bool) string {
	if b {
		return "TRUE"
	}
	return "FALSE"
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/surface/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/surface/netscape.go internal/surface/netscape_test.go
git commit -m "feat: add netscape cookies.txt adapter"
```

---

### Task 3: gh hosts adapter

**Files:** Create `internal/surface/ghhosts.go`; Test `internal/surface/ghhosts_test.go`

- [ ] **Step 1: Add the yaml dependency**

Run: `go get gopkg.in/yaml.v3@latest`
Expected: go.mod/go.sum updated.

- [ ] **Step 2: Failing test**

`internal/surface/ghhosts_test.go`:
```go
package surface

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func TestGHHostsMergesPreservingOtherHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.yml")
	// Pre-existing file with an unrelated host.
	os.WriteFile(path, []byte("enterprise.example:\n    oauth_token: keep-me\n    user: someone\n"), 0o600)

	g, err := NewGHHosts(path, "gh_token", "github.com", "octocat")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "gh_token", Value: "ghp_new"}}}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600, got %v", info.Mode().Perm())
	}
	body, _ := os.ReadFile(path)
	s := string(body)
	if !strings.Contains(s, "ghp_new") || !strings.Contains(s, "github.com") {
		t.Fatalf("token not written: %q", s)
	}
	if !strings.Contains(s, "keep-me") {
		t.Fatalf("unrelated host clobbered: %q", s)
	}
}

func TestGHHostsUpsertOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.yml")
	g, _ := NewGHHosts(path, "gh_token", "github.com", "")
	// A delete (or unrelated secret) must not write anything.
	if err := g.ApplySecrets(secret.Diff{Deletes: []string{"gh_token"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("delete must not create the hosts file")
	}
}
```

- [ ] **Step 3: Run, verify fail**

Run: `go test ./internal/surface/ -run GHHosts`
Expected: FAIL `undefined: NewGHHosts`.

- [ ] **Step 4: Implement**

`internal/surface/ghhosts.go`:
```go
package surface

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/escoffier-labs/agentpantry/internal/secret"
	"gopkg.in/yaml.v3"
)

// GHHosts writes the GitHub token into gh's hosts.yml, merging with existing hosts.
type GHHosts struct {
	path       string
	secretName string
	host       string
	user       string
}

func NewGHHosts(path, secretName, host, user string) (*GHHosts, error) {
	if secretName == "" {
		return nil, fmt.Errorf("gh adapter requires a secret name")
	}
	if host == "" {
		host = "github.com"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &GHHosts{path: path, secretName: secretName, host: host, user: user}, nil
}

func (g *GHHosts) ApplySecrets(d secret.Diff) error {
	var token string
	found := false
	for _, s := range d.Upserts {
		if s.Name == g.secretName {
			token = s.Value
			found = true
		}
	}
	if !found {
		return nil // upsert-only; ignore deletes and unrelated secrets
	}

	doc := map[string]map[string]any{}
	if b, err := os.ReadFile(g.path); err == nil {
		if e := yaml.Unmarshal(b, &doc); e != nil {
			return fmt.Errorf("parse existing %s: %w", g.path, e)
		}
	}
	if doc == nil {
		doc = map[string]map[string]any{}
	}
	h := doc[g.host]
	if h == nil {
		h = map[string]any{}
	}
	h["oauth_token"] = token
	if g.user != "" {
		h["user"] = g.user
	}
	doc[g.host] = h

	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(g.path, out, 0o600)
}
```

- [ ] **Step 5: Run, verify pass**

Run: `go test ./internal/surface/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/surface/ghhosts.go internal/surface/ghhosts_test.go go.mod go.sum
git commit -m "feat: add gh hosts token adapter"
```

---

### Task 4: OpenClaw auth-profiles adapter

**Files:** Create `internal/surface/openclawauth.go`; Test `internal/surface/openclawauth_test.go`

- [ ] **Step 1: Failing test**

`internal/surface/openclawauth_test.go`:
```go
package surface

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

func TestOpenClawAuthMergesProfileObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-profiles.json")
	// Existing file with another profile that must survive.
	os.WriteFile(path, []byte(`{"profiles":{"openai-codex:default":{"type":"oauth"}}}`), 0o600)

	o, err := NewOpenClawAuth(path, map[string]string{"anthropic_secret": "anthropic:default"})
	if err != nil {
		t.Fatal(err)
	}
	val := `{"type":"oauth","token":"sk-ant-xyz"}`
	if err := o.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "anthropic_secret", Value: val}}}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600, got %v", info.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	var doc struct {
		Profiles map[string]json.RawMessage `json:"profiles"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Profiles["openai-codex:default"]; !ok {
		t.Fatal("existing profile clobbered")
	}
	if _, ok := doc.Profiles["anthropic:default"]; !ok {
		t.Fatal("new profile not written")
	}
}

func TestOpenClawAuthSkipsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-profiles.json")
	o, _ := NewOpenClawAuth(path, map[string]string{"bad": "x:default"})
	if err := o.ApplySecrets(secret.Diff{Upserts: []secret.Secret{{Name: "bad", Value: "not json"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid-JSON secret must not write a file")
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/surface/ -run OpenClawAuth`
Expected: FAIL `undefined: NewOpenClawAuth`.

- [ ] **Step 3: Implement**

`internal/surface/openclawauth.go`:
```go
package surface

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// OpenClawAuth merges provider profiles into an OpenClaw auth-profiles.json.
// The `profiles` field is an OBJECT keyed by "<provider>:default" (NOT an array).
type OpenClawAuth struct {
	path     string
	profiles map[string]string // secretName -> profileKey
}

func NewOpenClawAuth(path string, profiles map[string]string) (*OpenClawAuth, error) {
	if len(profiles) == 0 {
		return nil, fmt.Errorf("openclaw adapter requires a profiles mapping")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &OpenClawAuth{path: path, profiles: profiles}, nil
}

func (o *OpenClawAuth) ApplySecrets(d secret.Diff) error {
	bySecret := map[string]string{}
	for _, s := range d.Upserts {
		bySecret[s.Name] = s.Value
	}

	doc := map[string]json.RawMessage{}
	if b, err := os.ReadFile(o.path); err == nil {
		if e := json.Unmarshal(b, &doc); e != nil {
			return fmt.Errorf("parse existing %s: %w", o.path, e)
		}
	}
	if doc == nil {
		doc = map[string]json.RawMessage{}
	}
	profiles := map[string]json.RawMessage{}
	if raw, ok := doc["profiles"]; ok {
		if e := json.Unmarshal(raw, &profiles); e != nil {
			return fmt.Errorf("parse profiles in %s: %w", o.path, e)
		}
	}

	skipped, changed := 0, false
	for secretName, profileKey := range o.profiles {
		val, ok := bySecret[secretName]
		if !ok {
			continue
		}
		if !json.Valid([]byte(val)) {
			skipped++
			continue
		}
		profiles[profileKey] = json.RawMessage(val)
		changed = true
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "agentpantry: skipped %d openclaw profile secret(s) with invalid JSON\n", skipped)
	}
	if !changed {
		return nil
	}

	pb, err := json.Marshal(profiles)
	if err != nil {
		return err
	}
	doc["profiles"] = pb
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(o.path, out, 0o600)
}
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/surface/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/surface/openclawauth.go internal/surface/openclawauth_test.go
git commit -m "feat: add openclaw auth-profiles adapter"
```

---

### Task 5: config Adapters field

**Files:** Modify `internal/config/config.go`; Test `internal/config/config_test.go`

- [ ] **Step 1: Failing test**

Append to `internal/config/config_test.go`:
```go
func TestAdaptersRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	in := Default("sink")
	in.Adapters = []AdapterRef{
		{Type: "netscape", Path: "/tmp/cookies.txt"},
		{Type: "gh", Path: "/tmp/hosts.yml", Secret: "gh_token", Host: "github.com", User: "octocat"},
		{Type: "openclaw", Path: "/tmp/auth.json", Profiles: map[string]string{"anthropic_secret": "anthropic:default"}},
	}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Adapters) != 3 {
		t.Fatalf("want 3 adapters, got %d", len(out.Adapters))
	}
	if out.Adapters[1].Secret != "gh_token" || out.Adapters[2].Profiles["anthropic_secret"] != "anthropic:default" {
		t.Fatalf("adapter fields lost: %+v", out.Adapters)
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/config/ -run Adapters`
Expected: FAIL `in.Adapters undefined`.

- [ ] **Step 3: Implement**

In `internal/config/config.go`, add the struct and field. After the `BrowserRef` type add:
```go
// AdapterRef declares a per-CLI adapter sink surface.
type AdapterRef struct {
	Type     string            `toml:"type"`     // "netscape" | "gh" | "openclaw"
	Path     string            `toml:"path"`     // target file
	Secret   string            `toml:"secret"`   // gh: secret Name holding the token
	Host     string            `toml:"host"`     // gh: default "github.com"
	User     string            `toml:"user"`     // gh: optional user field
	Profiles map[string]string `toml:"profiles"` // openclaw: secretName -> profileKey
}
```
Add to `Config` (after `SecretsDir`):
```go
	Adapters   []AdapterRef  `toml:"adapters"`
```

- [ ] **Step 4: Run, verify pass**

Run: `go test ./internal/config/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add adapters config block"
```

---

### Task 6: sink wiring + doctor adapter checks

**Files:** Modify `cmd/agentpantry/main.go`, `internal/doctor/doctor.go`; Test `internal/doctor/doctor_test.go`

- [ ] **Step 1: Wire adapters into cmdSink**

In `cmd/agentpantry/main.go`, after the `for _, name := range c.Surfaces { ... }` loop (and before the `defer func(){...closers...}()`), add an adapter-building loop:
```go
	for _, a := range c.Adapters {
		switch a.Type {
		case "netscape":
			ns, err := surface.NewNetscape(a.Path)
			if err != nil {
				return err
			}
			cookieSurfaces = append(cookieSurfaces, ns)
		case "gh":
			gh, err := surface.NewGHHosts(a.Path, a.Secret, a.Host, a.User)
			if err != nil {
				return err
			}
			secretSurfaces = append(secretSurfaces, gh)
		case "openclaw":
			oc, err := surface.NewOpenClawAuth(a.Path, a.Profiles)
			if err != nil {
				return err
			}
			secretSurfaces = append(secretSurfaces, oc)
		default:
			return fmt.Errorf("unknown adapter type %q", a.Type)
		}
	}
```

- [ ] **Step 2: Add a doctor test for adapters**

Append to `internal/doctor/doctor_test.go`:
```go
func TestAdapterUnknownTypeFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"},
		Adapters: []config.AdapterRef{{Type: "bogus", Path: filepath.Join(dir, "x")}},
	}
	if find(Run(c), "adapter:bogus").Status != Fail {
		t.Fatal("unknown adapter type must Fail")
	}
}

func TestAdapterWritableParentOK(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"},
		Adapters: []config.AdapterRef{{Type: "netscape", Path: filepath.Join(dir, "cookies.txt")}},
	}
	if find(Run(c), "adapter:netscape").Status != OK {
		t.Fatal("netscape adapter with writable parent must be OK")
	}
}
```

- [ ] **Step 3: Implement doctor adapter checks**

In `internal/doctor/doctor.go`, inside `Run`'s `case "sink":` block, after the `for _, name := range c.Surfaces { ... }` loop, add:
```go
		for _, a := range c.Adapters {
			name := "adapter:" + a.Type
			switch a.Type {
			case "netscape", "gh", "openclaw":
				if !writableOrCreatable(filepath.Dir(a.Path)) {
					checks = append(checks, Check{name, Fail, "adapter target dir not writable: " + a.Path})
				} else if a.Type == "gh" && a.Secret == "" {
					checks = append(checks, Check{name, Fail, "gh adapter needs a secret name"})
				} else if a.Type == "openclaw" && len(a.Profiles) == 0 {
					checks = append(checks, Check{name, Fail, "openclaw adapter needs a profiles mapping"})
				} else {
					checks = append(checks, Check{name, OK, a.Path})
				}
			default:
				checks = append(checks, Check{name, Fail, "unknown adapter type"})
			}
		}
```

- [ ] **Step 4: Build, vet, test, smoke**

Run:
```bash
go build ./... && go vet ./... && go test ./...
```
Expected: all PASS, vet clean.

- [ ] **Step 5: Commit**

```bash
git add cmd/agentpantry/main.go internal/doctor/doctor.go internal/doctor/doctor_test.go
git commit -m "feat: wire adapters into sink and doctor"
```

---

### Task 7: integration tests + docs

**Files:** Modify `test/integration_test.go`, `README.md`, `CHANGELOG.md`

- [ ] **Step 1: Add adapter e2e tests**

Append to `test/integration_test.go` (imports already include os, filepath, context, testing, and the sink/source/surface/transport/cookie/policy/secret/secretsrc packages; add nothing new):
```go
func TestEndToEndNetscapeAdapter(t *testing.T) {
	dir := t.TempDir()
	nsPath := filepath.Join(dir, "cookies.txt")
	ns, err := surface.NewNetscape(nsPath)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key)
	opener, _ := transport.NewOpener(key)
	pr, pw := newPipe()
	syncer := &source.Syncer{
		Vaults: []source.CookieReader{fixedCookie{c: cookie.Cookie{Host: "github.com", Name: "sid", Path: "/", Value: "tok", IsSecure: true}}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    pw,
	}
	srv := &sink.Server{Opener: opener, CookieSurfaces: []sink.CookieSurface{ns}}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), pr) }()
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(nsPath)
	if !strings.Contains(string(body), "github.com") || !strings.Contains(string(body), "tok") {
		t.Fatalf("netscape adapter did not receive cookie: %q", body)
	}
}

func TestEndToEndGHAdapter(t *testing.T) {
	dir := t.TempDir()
	srcSecrets := filepath.Join(dir, "secrets")
	os.MkdirAll(srcSecrets, 0o700)
	os.WriteFile(filepath.Join(srcSecrets, "gh_token"), []byte("ghp_live"), 0o600)
	hostsPath := filepath.Join(dir, "hosts.yml")
	gh, err := surface.NewGHHosts(hostsPath, "gh_token", "github.com", "octocat")
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key)
	opener, _ := transport.NewOpener(key)
	pr, pw := newPipe()
	syncer := &source.Syncer{
		Secrets: []source.SecretReader{&secretsrc.DirReader{Dir: srcSecrets}},
		Sealer:  sealer,
		Out:     pw,
	}
	srv := &sink.Server{Opener: opener, SecretSurfaces: []sink.SecretSurface{gh}}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), pr) }()
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(hostsPath)
	if !strings.Contains(string(body), "ghp_live") {
		t.Fatalf("gh adapter did not receive token: %q", body)
	}
}
```
Add `"strings"` to the test import block if not already present.

- [ ] **Step 2: Run, verify pass**

Run: `go test ./test/`
Expected: PASS.

- [ ] **Step 3: Full suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all PASS, vet clean.

- [ ] **Step 4: Docs**

In `README.md`, add an "Adapters" section documenting the `[[adapters]]` block, the three types (netscape cookie surface; gh + openclaw secret surfaces, both merge-only and upsert-only), and a config example. Note the OpenClaw `profiles` object-keying gotcha and that the secret value for openclaw must be the profile JSON. In `CHANGELOG.md` under `## Unreleased` -> `### Added`, add bullets for the three adapters and the `[[adapters]]` config block. Use only `127.0.0.1`/`sink.example` and RFC 5737 IPs in examples; no private IPs, no bare "localhost", no machine hostnames.

- [ ] **Step 5: Commit**

```bash
git add test/integration_test.go README.md CHANGELOG.md
git commit -m "test: adapter e2e; document per-cli adapters"
```

---

## Self-Review Notes

- **Spec coverage:** expiry contract (spec 3) -> Task 1; netscape (spec 4) -> Task 2; gh (spec 5) -> Task 3; openclaw (spec 6) -> Task 4; config (spec 2) -> Task 5; sink wiring + doctor (spec 7) -> Task 6; testing (spec 9) -> all + Task 7; security (spec 8): 0600 + merge-preserve + upsert-only covered in Tasks 2-4.
- **Type consistency:** `cookie.ExpiresUnix`/`ExpiresFromUnix` (Task 1) used in 2,7. `surface.Netscape`/`NewNetscape` (Task 2), `surface.GHHosts`/`NewGHHosts` (Task 3), `surface.OpenClawAuth`/`NewOpenClawAuth` (Task 4) all used in 6,7. `config.AdapterRef`/`Config.Adapters` (Task 5) used in 6,7. Netscape satisfies `sink.CookieSurface`; gh/openclaw satisfy `sink.SecretSurface` (their method sets match). `fixedCookie` reused from existing integration test (not redefined). `boolTF` is netscape-local (distinct from sidecar's `b2i`).
- **Config change is additive** (new optional `adapters` field) -> not a breaking schema change, no owner gate.
- **No placeholders:** all code complete; Task 7 README enumerates required sections.
- **Upsert-only adapters (gh, openclaw)** deliberately ignore deletes so a transient secret blip never logs the user out / nukes a gateway profile - asserted in Task 3 `TestGHHostsUpsertOnly`.
