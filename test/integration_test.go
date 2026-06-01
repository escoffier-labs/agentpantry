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
