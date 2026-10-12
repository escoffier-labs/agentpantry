package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/keepass"
	"github.com/escoffier-labs/agentpantry/internal/policy"
)

const (
	planCookieMarker = "plan-cookie-value-marker"
	planSecretMarker = "plan-secret-value-marker"
)

type planFileMeta struct {
	size  int64
	mode  fs.FileMode
	mtime time.Time
}

// snapshotTree records every path under root with its size, mode, and mtime
// so a test can prove a plan created, removed, or modified nothing.
func snapshotTree(t *testing.T, root string) map[string]planFileMeta {
	t.Helper()
	out := map[string]planFileMeta{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		e := planFileMeta{size: info.Size(), mode: info.Mode(), mtime: info.ModTime()}
		// NTFS bumps a directory's last-write time lazily after a child is
		// written, so on Windows a directory is compared by its entry set
		// (created or removed paths) rather than its mtime.
		if info.IsDir() && runtime.GOOS == "windows" {
			e.mtime = time.Time{}
		}
		out[path] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertTreeUnchanged(t *testing.T, before, after map[string]planFileMeta) {
	t.Helper()
	for path, meta := range after {
		prev, ok := before[path]
		if !ok {
			t.Errorf("plan created %s", path)
			continue
		}
		if prev != meta {
			t.Errorf("plan modified %s: before %+v after %+v", path, prev, meta)
		}
	}
	for path := range before {
		if _, ok := after[path]; !ok {
			t.Errorf("plan removed %s", path)
		}
	}
}

// planFixture writes a synthetic source setup: a 0600 key, a fake Firefox
// cookie store whose bytes carry a marker value, and a secrets_dir holding a
// marker secret. Nothing here is a real profile.
func planFixture(t *testing.T) (string, config.Config) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "psk.key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("42", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	cookiePath := filepath.Join(dir, "cookies.sqlite")
	if err := os.WriteFile(cookiePath, []byte("sid="+planCookieMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	secretsDir := filepath.Join(dir, "source-secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretsDir, "api_token"), []byte(planSecretMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{
		Role:           "source",
		Peer:           "127.0.0.1:8787",
		KeyPath:        keyPath,
		SecretsDir:     secretsDir,
		WarnExpiryDays: 7,
		Browsers: []config.BrowserRef{
			{Kind: "firefox", Profile: "research", CookiePath: cookiePath},
		},
		Domains:     policy.Domain{Allow: []string{"example.com"}, Deny: []string{"bank.example.com"}},
		SecretNames: policy.Names{Deny: []string{"drop_token"}},
		Receipts:    config.Receipts{Enabled: true},
	}
	return dir, c
}

func renderPlan(t *testing.T, p sourcePlan, jsonOut bool) string {
	t.Helper()
	var buf bytes.Buffer
	if err := printSourcePlan(&buf, p, jsonOut); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestSourcePlanReadyDisclosesWithoutReadingValues(t *testing.T) {
	dir, c := planFixture(t)
	cfgPath := filepath.Join(dir, "source.toml")
	before := snapshotTree(t, dir)

	p := buildSourcePlan(cfgPath, c, false, false, nil)

	if p.Status.ConfigReadiness != planReady {
		t.Fatalf("want ready, got %s: %v", p.Status.ConfigReadiness, p.Problems)
	}
	if p.Status.CaptureCoverage != planNotMeasured || p.Status.WebsiteAuthentication != planNotVerified {
		t.Fatalf("coverage and authentication must stay unmeasured: %+v", p.Status)
	}
	if !p.DryRun || p.Role != "source" || p.Mode != planModeWatch {
		t.Fatalf("unexpected header: %+v", p)
	}
	if p.Route.Kind != planRouteTCP || p.Route.Peer != "127.0.0.1:8787" {
		t.Fatalf("want tcp route to the peer, got %+v", p.Route)
	}
	if !p.Key.Present || p.Key.Path != c.KeyPath {
		t.Fatalf("key metadata wrong: %+v", p.Key)
	}
	if len(p.Browsers) != 1 {
		t.Fatalf("want 1 browser, got %d", len(p.Browsers))
	}
	b := p.Browsers[0]
	if b.Kind != "firefox" || b.Profile != "research" || b.StoreCheck != planStorePresent || b.AccountIdentity != planAccountIdentity {
		t.Fatalf("browser row wrong: %+v", b)
	}
	if got := p.DomainPolicy; len(got.Allow) != 1 || got.Allow[0] != "example.com" || len(got.Deny) != 1 || !strings.Contains(got.Rule, "deny wins") {
		t.Fatalf("domain policy wrong: %+v", got)
	}
	if got := p.SecretPolicy; len(got.Deny) != 1 || got.Deny[0] != "drop_token" || !strings.Contains(got.Rule, "deny wins") {
		t.Fatalf("secret policy wrong: %+v", got)
	}
	if sd := p.SecretSources.SecretsDir; !sd.Enabled || !sd.Present || sd.Path != c.SecretsDir {
		t.Fatalf("secrets_dir wrong: %+v", sd)
	}
	if p.SecretSources.Keepass.Enabled {
		t.Fatal("keepass must be reported disabled when keepass_path is unset")
	}
	writes := map[string]string{}
	for _, w := range p.LocalWrites {
		writes[w.Purpose] = w.Path
	}
	if writes["state"] != filepath.Join(dir, "state.json") || writes["receipts"] != filepath.Join(dir, "receipts.jsonl") {
		t.Fatalf("local writes wrong: %+v", p.LocalWrites)
	}

	for _, jsonOut := range []bool{false, true} {
		out := renderPlan(t, p, jsonOut)
		for _, marker := range []string{planCookieMarker, planSecretMarker, strings.Repeat("42", 32)} {
			if strings.Contains(out, marker) {
				t.Fatalf("plan output (json=%t) leaked a value %q:\n%s", jsonOut, marker, out)
			}
		}
	}
	text := renderPlan(t, p, false)
	for _, want := range []string{"config_readiness: ready", "capture_coverage: not_measured", "website_authentication: not_verified", "account identity: unknown"} {
		if !strings.Contains(text, want) {
			t.Fatalf("text plan missing %q:\n%s", want, text)
		}
	}

	assertTreeUnchanged(t, before, snapshotTree(t, dir))
}

func TestSourcePlanMissingKeyStaysMissing(t *testing.T) {
	dir, c := planFixture(t)
	c.KeyPath = filepath.Join(dir, "absent", "psk.key")
	before := snapshotTree(t, dir)

	var buf bytes.Buffer
	err := runSourcePlan(&buf, filepath.Join(dir, "source.toml"), c, false, false, true, nil)
	if err == nil {
		t.Fatal("a missing key must fail the plan")
	}
	var p sourcePlan
	if jerr := json.Unmarshal(buf.Bytes(), &p); jerr != nil {
		t.Fatalf("plan must still print as JSON: %v\n%s", jerr, buf.String())
	}
	if p.Status.ConfigReadiness != planNotReady || p.Key.Present {
		t.Fatalf("want not_ready with key absent, got %+v / %+v", p.Status, p.Key)
	}
	if !strings.Contains(strings.Join(p.Problems, "\n"), "key file not found") {
		t.Fatalf("problems must name the key: %v", p.Problems)
	}
	if _, statErr := os.Stat(c.KeyPath); !os.IsNotExist(statErr) {
		t.Fatalf("plan must not create the key: %v", statErr)
	}
	assertTreeUnchanged(t, before, snapshotTree(t, dir))
}

func TestSourcePlanKeyPermsTooOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("keyfile.Load does not check POSIX modes on Windows")
	}
	_, c := planFixture(t)
	if err := os.Chmod(c.KeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	p := buildSourcePlan("source.toml", c, false, false, nil)
	if p.Status.ConfigReadiness != planNotReady || !strings.Contains(strings.Join(p.Problems, "\n"), "too open") {
		t.Fatalf("want a perms problem, got %v", p.Problems)
	}
}

// TestSourcePlanFlagsWhatSourceRejects keeps the plan's browser checks in step
// with the startup checks the real source applies.
func TestSourcePlanFlagsWhatSourceRejects(t *testing.T) {
	cases := []struct {
		name        string
		browser     config.BrowserRef
		buildVaults bool // buildVaults itself rejects this browser
		want        string
	}{
		{"unsupported kind", config.BrowserRef{Kind: "safari", Profile: "p"}, true, "unsupported browser kind"},
		{"remote cdp", config.BrowserRef{Kind: "cdp", Profile: "p", URL: "http://203.0.113.5:9222"}, true, "loopback"},
		{"localstorage on a file store", config.BrowserRef{Kind: "firefox", Profile: "p", CookiePath: "x", CaptureLocalStorage: true}, false, "capture_localstorage"},
		{"missing cookie store", config.BrowserRef{Kind: "chromium", Profile: "p", CookiePath: filepath.Join(t.TempDir(), "Cookies")}, false, "not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, c := planFixture(t)
			c.Browsers = []config.BrowserRef{tc.browser}
			if tc.buildVaults {
				if _, _, err := buildVaults(c); err == nil {
					t.Fatal("buildVaults accepted a browser the plan must flag")
				}
			}
			p := buildSourcePlan("source.toml", c, false, false, nil)
			if p.Status.ConfigReadiness != planNotReady {
				t.Fatalf("want not_ready, got %s", p.Status.ConfigReadiness)
			}
			if !strings.Contains(strings.Join(p.Problems, "\n"), tc.want) {
				t.Fatalf("problems %v do not mention %q", p.Problems, tc.want)
			}
		})
	}
}

func TestSourcePlanRoutes(t *testing.T) {
	_, c := planFixture(t)

	p := buildSourcePlan("source.toml", c, true, true, nil)
	if p.Route.Kind != planRouteStdio || p.Mode != planModeOnce {
		t.Fatalf("want stdio once, got %+v mode %s", p.Route, p.Mode)
	}

	peerless := c
	peerless.Peer = config.PeerNone
	p = buildSourcePlan("source.toml", peerless, false, false, nil)
	if p.Route.Kind != planRoutePeerless {
		t.Fatalf("want peerless route, got %+v", p.Route)
	}
	if p.Status.ConfigReadiness != planReady {
		t.Fatalf("peerless must be reported, not rejected: %v", p.Problems)
	}

	badPeer := c
	badPeer.Peer = "not-a-hostport"
	p = buildSourcePlan("source.toml", badPeer, false, false, nil)
	if p.Status.ConfigReadiness != planNotReady {
		t.Fatal("an unparseable TCP peer must fail the plan")
	}
	// The same peer is not used in stdio mode, so it is not a problem there.
	p = buildSourcePlan("source.toml", badPeer, true, false, nil)
	if p.Status.ConfigReadiness != planReady {
		t.Fatalf("stdio mode does not dial the peer: %v", p.Problems)
	}

	wrongRole := c
	wrongRole.Role = "sink"
	if p := buildSourcePlan("source.toml", wrongRole, false, false, nil); p.Status.ConfigReadiness != planNotReady {
		t.Fatal("a sink config must fail the source plan")
	}
}

func TestSourcePlanCDPResyncAndLocalStorage(t *testing.T) {
	_, c := planFixture(t)
	c.Browsers = []config.BrowserRef{{Kind: "cdp", Profile: "app", URL: "http://127.0.0.1:9222", CaptureLocalStorage: true}}

	p := buildSourcePlan("source.toml", c, false, false, nil)
	if p.Status.ConfigReadiness != planReady {
		t.Fatalf("want ready, got %v", p.Problems)
	}
	if p.ResyncSeconds != int(defaultCDPResync.Seconds()) {
		t.Fatalf("watch mode cdp should default resync, got %d", p.ResyncSeconds)
	}
	b := p.Browsers[0]
	if b.StoreCheck != planStoreNotChecked || !b.CaptureLocalStorage || !strings.Contains(b.Mechanism, "localStorage") {
		t.Fatalf("cdp row wrong: %+v", b)
	}
	if p := buildSourcePlan("source.toml", c, false, true, nil); p.ResyncSeconds != 0 {
		t.Fatalf("once mode keeps resync off, got %d", p.ResyncSeconds)
	}
}

func TestSourcePlanKeepassPresenceOnly(t *testing.T) {
	dir, c := planFixture(t)
	vault := filepath.Join(dir, "vault.kdbx")
	if err := os.WriteFile(vault, []byte(planSecretMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	c.KeepassPath = vault
	c.KeepassKeyfile = filepath.Join(dir, "missing.key")

	p := buildSourcePlan("source.toml", c, false, false, nil)
	kp := p.SecretSources.Keepass
	if !kp.Enabled || !kp.Present || kp.Tag != "agentpantry" || kp.Keyfile.Present {
		t.Fatalf("keepass row wrong: %+v", kp)
	}
	if p.Status.ConfigReadiness != planNotReady {
		t.Fatal("a missing keepass_keyfile must fail the plan")
	}
	if out := renderPlan(t, p, true); strings.Contains(out, planSecretMarker) {
		t.Fatalf("plan leaked vault bytes:\n%s", out)
	}
}

// TestSourcePlanKeepassCredentialFiles keeps the plan's KeePass checks in step
// with what keepass.Reader rejects before it decodes the vault: an unset
// keyfile, a credential path that is not a regular file, an open mode, or an
// empty file. Each not_ready case is also confirmed against the real reader.
func TestSourcePlanKeepassCredentialFiles(t *testing.T) {
	cases := []struct {
		name      string
		posixOnly bool // keepass does not check POSIX modes on Windows
		setup     func(t *testing.T, dir string, c *config.Config)
		want      string // "" means the plan must be ready
	}{
		{"keyfile and pass file 0600", false, func(t *testing.T, dir string, c *config.Config) {}, ""},
		{"keyfile unset", false, func(t *testing.T, dir string, c *config.Config) {
			c.KeepassKeyfile = ""
		}, "keepass_keyfile is required"},
		{"keyfile 0644", true, func(t *testing.T, dir string, c *config.Config) {
			chmodPlanFile(t, c.KeepassKeyfile, 0o644)
		}, "keepass_keyfile perms 0644 are too open"},
		{"pass file 0640", true, func(t *testing.T, dir string, c *config.Config) {
			chmodPlanFile(t, c.KeepassPassFile, 0o640)
		}, "keepass_pass_file perms 0640 are too open"},
		{"keyfile is a directory", false, func(t *testing.T, dir string, c *config.Config) {
			c.KeepassKeyfile = filepath.Join(dir, "keydir")
			if err := os.Mkdir(c.KeepassKeyfile, 0o700); err != nil {
				t.Fatal(err)
			}
		}, "is not a regular file"},
		{"keyfile empty", false, func(t *testing.T, dir string, c *config.Config) {
			if err := os.WriteFile(c.KeepassKeyfile, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.posixOnly && runtime.GOOS == "windows" {
				t.Skip("keepass credential files are not mode-checked on Windows")
			}
			dir, c := planFixture(t)
			c.KeepassPath = filepath.Join(dir, "vault.kdbx")
			c.KeepassKeyfile = filepath.Join(dir, "vault.key")
			c.KeepassPassFile = filepath.Join(dir, "vault.pass")
			for _, f := range []string{c.KeepassPath, c.KeepassKeyfile, c.KeepassPassFile} {
				if err := os.WriteFile(f, []byte(planSecretMarker), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			tc.setup(t, dir, &c)

			p := buildSourcePlan("source.toml", c, false, false, nil)
			problems := strings.Join(p.Problems, "\n")
			if tc.want == "" {
				if p.Status.ConfigReadiness != planReady {
					t.Fatalf("want ready, got %v", p.Problems)
				}
				kp := p.SecretSources.Keepass
				if !kp.Keyfile.Present || kp.Keyfile.Mode != "0600" || !kp.PassFile.Present || kp.PassFile.Mode != "0600" {
					t.Fatalf("credential file rows wrong: %+v", kp)
				}
			} else {
				if p.Status.ConfigReadiness != planNotReady || !strings.Contains(problems, tc.want) {
					t.Fatalf("want not_ready mentioning %q, got %v", tc.want, p.Problems)
				}
				// The fixture vault is not a real kdbx, so the reader must
				// reject the credentials before it reaches the decoder.
				r := &keepass.Reader{Path: c.KeepassPath, Keyfile: c.KeepassKeyfile, PassFile: c.KeepassPassFile, Tag: c.KeepassTagOrDefault()}
				if _, err := r.ReadSecrets(context.Background()); err == nil || strings.Contains(err.Error(), "decode failed") {
					t.Fatalf("keepass.Reader must reject this config before decoding, got %v", err)
				}
			}
			if out := renderPlan(t, p, true); strings.Contains(out, planSecretMarker) {
				t.Fatalf("plan leaked credential bytes:\n%s", out)
			}
		})
	}
}

func chmodPlanFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePlanJSONSchema(t *testing.T) {
	_, c := planFixture(t)
	c.Domains = policy.Domain{}
	c.SecretNames = policy.Names{}
	var payload map[string]any
	if err := json.Unmarshal([]byte(renderPlan(t, buildSourcePlan("source.toml", c, false, false, nil), true)), &payload); err != nil {
		t.Fatal(err)
	}
	keys := func(m map[string]any) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	wantTop := []string{"browsers", "config", "domain_policy", "dry_run", "key", "local_writes", "mode", "notes", "problems", "resync_seconds", "role", "route", "secret_name_policy", "secret_sources", "status"}
	if got := keys(payload); strings.Join(got, ",") != strings.Join(wantTop, ",") {
		t.Fatalf("top-level keys = %v, want %v", got, wantTop)
	}
	status := payload["status"].(map[string]any)
	if got := keys(status); strings.Join(got, ",") != "capture_coverage,config_readiness,website_authentication" {
		t.Fatalf("status keys = %v", got)
	}
	browser := payload["browsers"].([]any)[0].(map[string]any)
	if got := keys(browser); strings.Join(got, ",") != "account_identity,capture_localstorage,kind,mechanism,profile,store,store_check" {
		t.Fatalf("browser keys = %v", got)
	}
	// Empty lists encode as [] so a wrapper never has to special-case null.
	for _, section := range []string{"domain_policy", "secret_name_policy"} {
		pol := payload[section].(map[string]any)
		for _, k := range []string{"allow", "deny"} {
			if _, ok := pol[k].([]any); !ok {
				t.Fatalf("%s.%s must be a JSON array, got %#v", section, k, pol[k])
			}
		}
	}
	if _, ok := payload["problems"].([]any); !ok {
		t.Fatalf("problems must be a JSON array, got %#v", payload["problems"])
	}
}
