package test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cdpvault"
	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/ffvault"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secretsrc"
	"github.com/escoffier-labs/agentpantry/internal/sink"
	"github.com/escoffier-labs/agentpantry/internal/source"
	"github.com/escoffier-labs/agentpantry/internal/state"
	"github.com/escoffier-labs/agentpantry/internal/surface"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/vault"
	"github.com/gorilla/websocket"
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
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	opener, _ := transport.NewOpener(key, make([]byte, 16))

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
	srv := &sink.Server{Opener: opener, CookieSurfaces: []sink.CookieSurface{sc}}

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
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	opener, _ := transport.NewOpener(key, make([]byte, 16))
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
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	opener, _ := transport.NewOpener(key, make([]byte, 16))

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

func TestStdioPipeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	sidecarPath := filepath.Join(dir, "sidecar.db")
	sc, err := surface.NewSidecar(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	opener, _ := transport.NewOpener(key, make([]byte, 16))

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

	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
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

func TestEndToEndNetscapeAdapter(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	nsPath := filepath.Join(dir, "cookies.txt")
	ns, err := surface.NewNetscape(nsPath)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	opener, _ := transport.NewOpener(key, make([]byte, 16))
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
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	srcSecrets := filepath.Join(dir, "secrets")
	os.MkdirAll(srcSecrets, 0o700)
	os.WriteFile(filepath.Join(srcSecrets, "gh_token"), []byte("ghp_live"), 0o600)
	hostsPath := filepath.Join(dir, "hosts.yml")
	gh, err := surface.NewGHHosts(hostsPath, "gh_token", "github.com", "octocat")
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	opener, _ := transport.NewOpener(key, make([]byte, 16))
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

func TestEndToEndHermesAdapter(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	srcSecrets := filepath.Join(dir, "source-secrets")
	os.MkdirAll(srcSecrets, 0o700)
	os.WriteFile(filepath.Join(srcSecrets, "api_token"), []byte("secret-live"), 0o600)
	hermes, err := surface.NewHermesBundle(filepath.Join(dir, ".hermes", "agentpantry"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	opener, _ := transport.NewOpener(key, make([]byte, 16))
	pr, pw := newPipe()
	syncer := &source.Syncer{
		Vaults:  []source.CookieReader{fixedCookie{c: cookie.Cookie{Host: "github.com", Name: "sid", Path: "/", Value: "cookie-live", IsSecure: true}}},
		Secrets: []source.SecretReader{&secretsrc.DirReader{Dir: srcSecrets}},
		Policy:  policy.Domain{Allow: []string{"github.com"}},
		Sealer:  sealer,
		Out:     pw,
	}
	srv := &sink.Server{
		Opener:         opener,
		CookieSurfaces: []sink.CookieSurface{hermes},
		SecretSurfaces: []sink.SecretSurface{hermes},
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), pr) }()
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cookies, _ := os.ReadFile(filepath.Join(dir, ".hermes", "agentpantry", "cookies.txt"))
	if !strings.Contains(string(cookies), "cookie-live") {
		t.Fatalf("hermes adapter did not receive cookie: %q", cookies)
	}
	secretValue, _ := os.ReadFile(filepath.Join(dir, ".hermes", "agentpantry", "secrets", "api_token"))
	if string(secretValue) != "secret-live" {
		t.Fatalf("hermes adapter did not receive secret: %q", secretValue)
	}
	manifest, _ := os.ReadFile(filepath.Join(dir, ".hermes", "agentpantry", "agentpantry.json"))
	if !strings.Contains(string(manifest), "agentpantry.hermes-bundle.v1") {
		t.Fatalf("hermes manifest missing schema: %q", manifest)
	}
}

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
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	opener, _ := transport.NewOpener(key, make([]byte, 16))
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
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	opener, _ := transport.NewOpener(key, make([]byte, 16))
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

func TestEndToEndOldKeyGraceWindow(t *testing.T) {
	dir := t.TempDir()
	chromePath := filepath.Join(dir, "Cookies")
	writeChromeDB(t, chromePath, "keyring")

	newKey := make([]byte, 32)
	newKey[0] = 1
	oldKey := make([]byte, 32)
	oldKey[0] = 2
	salt := make([]byte, 16)

	// Source still seals under the pre-rotation key; the sink holds both.
	sealer, _ := transport.NewSealer(oldKey, salt)
	opener, err := transport.NewFallbackOpener(newKey, oldKey, salt)
	if err != nil {
		t.Fatal(err)
	}
	fallbacks := 0
	opener.OnFallback = func() { fallbacks++ }

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
	srv := &sink.Server{Opener: opener, CookieSurfaces: []sink.CookieSurface{sc}}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), pr) }()

	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("old-key session must apply during the grace window: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sink did not finish")
	}
	if fallbacks != 1 {
		t.Fatalf("OnFallback must fire once for an old-key session, fired %d times", fallbacks)
	}

	// A new-key session against the same construction applies cleanly with no
	// fallback.
	sealer2, _ := transport.NewSealer(newKey, salt)
	opener2, _ := transport.NewFallbackOpener(newKey, oldKey, salt)
	fallbacks2 := 0
	opener2.OnFallback = func() { fallbacks2++ }
	pr2, pw2 := newPipe()
	syncer2 := &source.Syncer{
		Vaults: []source.CookieReader{&vault.LinuxChromium{
			Profile: "test", CookiePath: chromePath, KeyProvider: staticKey{"keyring"},
		}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer2,
		Out:    pw2,
	}
	srv2 := &sink.Server{Opener: opener2, CookieSurfaces: []sink.CookieSurface{sc}}
	done2 := make(chan error, 1)
	go func() { done2 <- srv2.Serve(context.Background(), pr2) }()
	if err := syncer2.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	pw2.Close()
	select {
	case err := <-done2:
		if err != nil {
			t.Fatalf("new-key session must apply: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sink did not finish")
	}
	if fallbacks2 != 0 {
		t.Fatalf("new-key session must not fire OnFallback, fired %d times", fallbacks2)
	}
}
