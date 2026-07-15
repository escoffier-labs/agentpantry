package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/surface"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
	"github.com/gorilla/websocket"
)

func writeSidecarCookies(t *testing.T, path string, cookies ...cookie.Cookie) {
	t.Helper()
	sc, err := surface.NewSidecar(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	if err := sc.Apply(cookie.Diff{Upserts: cookies}); err != nil {
		t.Fatal(err)
	}
}

func writeSidecarStorage(t *testing.T, path string, items ...webstorage.Item) {
	t.Helper()
	sc, err := surface.NewSidecar(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	if err := sc.ApplyStorage(webstorage.Diff{Upserts: items}); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreDryRunJSONDoesNotPrintCookieValues(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	writeSidecarCookies(t, sidecarPath,
		cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "secret-example-value"},
		cookie.Cookie{Host: "api.example.com", Name: "sid", Path: "/", Value: "secret-subdomain-value"},
		cookie.Cookie{Host: "example.net", Name: "sid", Path: "/", Value: "secret-net-value"},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	targetPath := filepath.Join(dir, "cookies.txt")
	cmd := exec.CommandContext(ctx, bin, "restore",
		"-sidecar", sidecarPath,
		"--to", "netscape="+targetPath,
		"--domains", "example.com",
		"--dry-run",
		"--json",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restore dry-run failed: %v\n%s", err, out)
	}
	if ctx.Err() != nil {
		t.Fatalf("restore dry-run timed out\n%s", out)
	}
	output := string(out)
	for _, secret := range []string{"secret-example-value", "secret-subdomain-value", "secret-net-value"} {
		if strings.Contains(output, secret) {
			t.Fatalf("dry-run output leaked cookie value %q:\n%s", secret, output)
		}
	}
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("dry-run created target file: %v", err)
	}
	var payload struct {
		Total    int `json:"total"`
		NameHost []struct {
			Name  string `json:"name"`
			Host  string `json:"host"`
			Count int    `json:"count"`
		} `json:"name_hosts"`
		Domains []struct {
			Domain string `json:"domain"`
			Count  int    `json:"count"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("restore dry-run JSON did not parse: %v\n%s", err, out)
	}
	if payload.Total != 2 {
		t.Fatalf("dry-run total = %d, want 2", payload.Total)
	}
	if len(payload.NameHost) != 2 || payload.NameHost[0].Name != "sid" || payload.NameHost[0].Count != 1 {
		t.Fatalf("unexpected name@host summary: %+v", payload.NameHost)
	}
	if len(payload.Domains) != 2 {
		t.Fatalf("unexpected domain summary: %+v", payload.Domains)
	}
}

func TestRestoreFromConfigWritesNetscapeTarget(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	writeSidecarCookies(t, sidecarPath,
		cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "restored-cookie-value", IsSecure: true},
	)
	cfgPath := filepath.Join(dir, "sink.toml")
	writeConfig(t, cfgPath, fmt.Sprintf(`
role = "sink"
peer = "127.0.0.1:1"
key_path = %q
surfaces = ["sidecar"]
sidecar_path = %q
`, filepath.Join(dir, "psk.key"), sidecarPath))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	targetPath := filepath.Join(dir, "cookies.txt")
	cmd := exec.CommandContext(ctx, bin, "restore",
		"-config", cfgPath,
		"--to", "netscape="+targetPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restore failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "restored-cookie-value") {
		t.Fatalf("restore output leaked cookie value:\n%s", out)
	}
	body, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "example.com\tFALSE\t/\tTRUE\t0\tsid\trestored-cookie-value") {
		t.Fatalf("netscape target missing restored cookie:\n%s", body)
	}
}

func TestRestoreToStorageStateWritesPlaywrightFile(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	// Building the sidecar first tightens dir to 0700, satisfying the surface's
	// group/world-writable guard for the subsequent restore.
	writeSidecarCookies(t, sidecarPath,
		cookie.Cookie{Host: "github.com", Name: "user_session", Path: "/", Value: "restored-cookie-value", IsSecure: true, IsHTTPOnly: true, SameSite: 1},
		cookie.Cookie{Host: "api.example.com", Name: "sid", Path: "/", Value: "off-domain-value"},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	targetPath := filepath.Join(dir, "state.json")
	cmd := exec.CommandContext(ctx, bin, "restore",
		"-sidecar", sidecarPath,
		"--to", "storagestate="+targetPath,
		"--domains", "github.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restore failed: %v\n%s", err, out)
	}
	for _, secret := range []string{"restored-cookie-value", "off-domain-value"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("restore output leaked cookie value %q:\n%s", secret, out)
		}
	}

	body, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cookies []struct {
			Name     string  `json:"name"`
			Value    string  `json:"value"`
			Domain   string  `json:"domain"`
			Path     string  `json:"path"`
			Expires  float64 `json:"expires"`
			HTTPOnly bool    `json:"httpOnly"`
			Secure   bool    `json:"secure"`
			SameSite string  `json:"sameSite"`
		} `json:"cookies"`
		Origins []any `json:"origins"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("storagestate target is not valid JSON: %v\n%s", err, body)
	}
	if doc.Origins == nil {
		t.Fatalf("origins must be an empty array, not null:\n%s", body)
	}
	// The -domains github.com narrowing must drop the off-domain cookie.
	if len(doc.Cookies) != 1 {
		t.Fatalf("cookies = %d, want 1 (domain-narrowed):\n%s", len(doc.Cookies), body)
	}
	c := doc.Cookies[0]
	if c.Name != "user_session" || c.Value != "restored-cookie-value" || c.Domain != "github.com" {
		t.Fatalf("unexpected cookie: %+v", c)
	}
	if !c.Secure || !c.HTTPOnly || c.SameSite != "Lax" || c.Expires != -1 {
		t.Fatalf("cookie attributes not carried through: %+v", c)
	}

	if runtime.GOOS != "windows" { // Go synthesizes 0666 on Windows; ACLs govern there
		info, err := os.Stat(targetPath)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("storagestate file mode = %o, want 600", perm)
		}
	}
}

func TestRestoreToStorageStateMaterializesLocalStorage(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	writeSidecarCookies(t, sidecarPath,
		cookie.Cookie{Host: "github.com", Name: "sid", Path: "/", Value: "cookie-secret", IsSecure: true, SameSite: 1},
	)
	writeSidecarStorage(t, sidecarPath,
		webstorage.Item{Origin: "https://github.com", Key: "tok", Value: "ls-secret"},
		webstorage.Item{Origin: "https://evil.com", Key: "x", Value: "off-domain-ls"},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	targetPath := filepath.Join(dir, "state.json")
	cmd := exec.CommandContext(ctx, bin, "restore",
		"-sidecar", sidecarPath,
		"--to", "storagestate="+targetPath,
		"--domains", "github.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restore failed: %v\n%s", err, out)
	}
	for _, secret := range []string{"cookie-secret", "ls-secret", "off-domain-ls"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("restore output leaked value %q:\n%s", secret, out)
		}
	}

	body, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cookies []map[string]any `json:"cookies"`
		Origins []struct {
			Origin       string `json:"origin"`
			LocalStorage []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"localStorage"`
		} `json:"origins"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("storagestate not valid JSON: %v\n%s", err, body)
	}
	// The off-domain origin must be narrowed out; only github.com survives.
	if len(doc.Origins) != 1 || doc.Origins[0].Origin != "https://github.com" {
		t.Fatalf("origins = %+v, want only https://github.com", doc.Origins)
	}
	ls := doc.Origins[0].LocalStorage
	if len(ls) != 1 || ls[0].Name != "tok" || ls[0].Value != "ls-secret" {
		t.Fatalf("localStorage = %+v, want tok=ls-secret", ls)
	}
	if len(doc.Cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(doc.Cookies))
	}
}

func TestRestoreFromConfigDoesNotWidenDomainDeny(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	writeSidecarCookies(t, sidecarPath,
		cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "allowed-value"},
		cookie.Cookie{Host: "api.example.com", Name: "sid", Path: "/", Value: "denied-value"},
	)
	cfgPath := filepath.Join(dir, "sink.toml")
	writeConfig(t, cfgPath, fmt.Sprintf(`
role = "sink"
peer = "127.0.0.1:1"
key_path = %q
surfaces = ["sidecar"]
sidecar_path = %q

[domains]
deny = ["api.example.com"]
`, filepath.Join(dir, "psk.key"), sidecarPath))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "restore",
		"-config", cfgPath,
		"--to", "netscape="+filepath.Join(dir, "cookies.txt"),
		"--domains", "example.com",
		"--dry-run",
		"--json",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restore dry-run failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "denied-value") {
		t.Fatalf("restore output leaked denied cookie value:\n%s", out)
	}
	var payload struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("restore dry-run JSON did not parse: %v\n%s", err, out)
	}
	if payload.Total != 1 {
		t.Fatalf("dry-run total = %d, want 1 after config deny", payload.Total)
	}
}

type fakeRestoreCDP struct {
	server       *httptest.Server
	mu           sync.Mutex
	stored       []map[string]any
	dropReadName string
}

func newFakeRestoreCDP(t *testing.T) *fakeRestoreCDP {
	t.Helper()
	f := &fakeRestoreCDP{}
	up := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		ws := "ws://" + r.Host + "/devtools/page/RESTORE"
		json.NewEncoder(w).Encode([]map[string]any{
			{"type": "page", "webSocketDebuggerUrl": ws},
		})
	})
	mux.HandleFunc("/devtools/page/RESTORE", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		var cmd struct {
			ID     int            `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := c.ReadJSON(&cmd); err != nil {
			return
		}
		switch cmd.Method {
		case "Storage.setCookies":
			rawCookies, _ := cmd.Params["cookies"].([]any)
			stored := make([]map[string]any, 0, len(rawCookies))
			for _, raw := range rawCookies {
				row, _ := raw.(map[string]any)
				stored = append(stored, row)
			}
			f.mu.Lock()
			f.stored = stored
			f.mu.Unlock()
			c.WriteJSON(map[string]any{"id": cmd.ID, "result": map[string]any{}})
		case "Storage.getCookies":
			f.mu.Lock()
			stored := append([]map[string]any(nil), f.stored...)
			dropReadName := f.dropReadName
			f.mu.Unlock()
			if dropReadName != "" {
				filtered := stored[:0]
				for _, row := range stored {
					if row["name"] != dropReadName {
						filtered = append(filtered, row)
					}
				}
				stored = filtered
			}
			c.WriteJSON(map[string]any{"id": cmd.ID, "result": map[string]any{"cookies": stored}})
		default:
			c.WriteJSON(map[string]any{"id": cmd.ID, "error": map[string]any{"message": "unexpected method " + cmd.Method}})
		}
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func TestRestoreToCDPVerifyReportsCountsAndNoValues(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	writeSidecarCookies(t, sidecarPath,
		cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "secret-cdp-value", IsSecure: true, SameSite: 1, ExpiresUTC: cookie.ExpiresFromUnix(1893456000)},
		cookie.Cookie{Host: "example.com", Name: "old", Path: "/", Value: "expired-cdp-value", IsSecure: true, SameSite: 1, ExpiresUTC: cookie.ExpiresFromUnix(946684800)},
		cookie.Cookie{Host: "api.example.com", Name: "prefs", Path: "/", Value: "secret-api-value", IsSecure: true, SameSite: 2},
	)
	cdp := newFakeRestoreCDP(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "restore",
		"-sidecar", sidecarPath,
		"--to", "cdp="+cdp.server.URL,
		"--verify",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restore to CDP failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, secret := range []string{"secret-cdp-value", "expired-cdp-value", "secret-api-value"} {
		if strings.Contains(output, secret) {
			t.Fatalf("restore CDP output leaked cookie value %q:\n%s", secret, output)
		}
	}
	for _, want := range []string{
		"restored 2 cookie(s)",
		"skipped expired: 1",
		"verify:",
		"example.com expected 1 present 1 names sid",
		"api.example.com expected 1 present 1 names prefs",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("restore CDP output missing %q:\n%s", want, output)
		}
	}
}

func TestRestoreToCDPVerifyFailsWhenExpectedCookieMissing(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	writeSidecarCookies(t, sidecarPath,
		cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "secret-cdp-value", IsSecure: true, SameSite: 1},
	)
	cdp := newFakeRestoreCDP(t)
	cdp.mu.Lock()
	cdp.dropReadName = "sid"
	cdp.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "restore",
		"-sidecar", sidecarPath,
		"--to", "cdp="+cdp.server.URL,
		"--verify",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("restore to CDP verify succeeded despite missing cookie\n%s", out)
	}
	output := string(out)
	if !strings.Contains(output, "example.com expected 1 present 0 names sid") ||
		!strings.Contains(output, "error: CDP verify failed: 1 expected cookie(s) absent") {
		t.Fatalf("missing verify failure details:\n%s", output)
	}
	if strings.Contains(output, "secret-cdp-value") {
		t.Fatalf("restore CDP verify failure leaked cookie value:\n%s", output)
	}
}

func TestRestoreChromiumDryRunListsTargetWithoutValues(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	writeSidecarCookies(t, sidecarPath,
		cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "chromium-secret-value", IsSecure: true},
	)
	profileDir := filepath.Join(dir, "Default")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// --dry-run resolves and summarizes the chromium target without opening the
	// OS keyring or writing the profile, so it is safe to exercise in CI.
	cmd := exec.CommandContext(ctx, bin, "restore",
		"-sidecar", sidecarPath,
		"--to", "chromium="+profileDir,
		"--dry-run",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("chromium dry-run failed: %v\n%s", err, out)
	}
	output := string(out)
	if strings.Contains(output, "chromium-secret-value") {
		t.Fatalf("dry-run leaked a cookie value:\n%s", output)
	}
	if !strings.Contains(output, "chromium="+profileDir) {
		t.Fatalf("dry-run did not name the chromium target:\n%s", output)
	}
	if !strings.Contains(output, "sid@example.com") {
		t.Fatalf("dry-run did not list the cookie by name@host:\n%s", output)
	}
	// Dry-run must not create the Cookies store.
	if _, err := os.Stat(filepath.Join(profileDir, "Cookies")); !os.IsNotExist(err) {
		t.Fatalf("dry-run wrote the chromium Cookies store: %v", err)
	}
}

func TestRestoreDesktopAppCodexDryRunFailsClosedWithoutWriting(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	writeSidecarCookies(t, sidecarPath,
		cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "desktop-secret-value"},
		cookie.Cookie{Host: "api.example.com", Name: "auth", Path: "/", Value: "desktop-api-secret-value"},
	)
	profileRoot := filepath.Join(dir, "desktop-profile")
	if err := os.Mkdir(profileRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "restore",
		"-sidecar", sidecarPath,
		"--to", "desktop-app=codex",
		"--dry-run",
	)
	cmd.Env = append(os.Environ(),
		"HOME="+profileRoot,
		"XDG_CONFIG_HOME="+profileRoot,
		"APPDATA="+profileRoot,
		"LOCALAPPDATA="+profileRoot,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Codex desktop-app dry-run failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, secret := range []string{"desktop-secret-value", "desktop-api-secret-value"} {
		if strings.Contains(output, secret) {
			t.Fatalf("dry-run output leaked cookie value %q:\n%s", secret, output)
		}
	}
	for _, want := range []string{
		"restore target: desktop-app=codex",
		"cookies: 2",
		"process state: unknown",
		"injection method: unavailable",
		"write result: desktop-app=codex restore blocked: no supported Codex session injection or read-back bridge; no files written",
		"example.com",
		"api.example.com",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("Codex desktop-app dry-run output missing %q:\n%s", want, output)
		}
	}
	entries, err := os.ReadDir(profileRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Codex desktop-app dry-run wrote under the profile root: %v", entries)
	}
}

func TestRestoreDesktopAppClaudeApplyAndVerifyFailClosedWithoutWriting(t *testing.T) {
	bin := agentpantryCLI(t)
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	writeSidecarCookies(t, sidecarPath,
		cookie.Cookie{Host: "claude.ai", Name: "sessionKey", Path: "/", Value: "claude-secret-value"},
	)

	for _, tc := range []struct {
		name    string
		extra   []string
		wantErr string
	}{
		{
			name:    "apply",
			wantErr: "Stop Claude completely, remove --verify if present, then rerun with --dry-run to inspect the offline profile",
		},
		{
			name:    "verify",
			extra:   []string{"--verify"},
			wantErr: "desktop-app=claude restore blocked: no supported Claude session injection or read-back bridge; no files written",
		},
		{
			name:    "verify_and_dry_run",
			extra:   []string{"--verify", "--dry-run"},
			wantErr: "desktop-app=claude restore blocked: no supported Claude session injection or read-back bridge; no files written",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profileRoot := filepath.Join(dir, tc.name+"-profile")
			if err := os.Mkdir(profileRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			args := []string{"restore", "-sidecar", sidecarPath, "--to", "desktop-app=claude"}
			args = append(args, tc.extra...)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Env = append(os.Environ(),
				"HOME="+profileRoot,
				"XDG_CONFIG_HOME="+profileRoot,
				"APPDATA="+profileRoot,
				"LOCALAPPDATA="+profileRoot,
			)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("Claude desktop-app %s unexpectedly succeeded:\n%s", tc.name, out)
			}
			output := string(out)
			if !strings.Contains(output, tc.wantErr) {
				t.Fatalf("Claude desktop-app %s output missing %q:\n%s", tc.name, tc.wantErr, output)
			}
			if !strings.Contains(output, "remove --verify if present, then rerun with --dry-run") {
				t.Fatalf("Claude desktop-app %s output lacks executable dry-run guidance:\n%s", tc.name, output)
			}
			if strings.Contains(output, "claude-secret-value") {
				t.Fatalf("Claude desktop-app %s leaked a cookie value:\n%s", tc.name, output)
			}
			entries, err := os.ReadDir(profileRoot)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("Claude desktop-app %s wrote under the profile root: %v", tc.name, entries)
			}
		})
	}
}
