package vault

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

type staticKey struct{ pass string }

func (s staticKey) Passphrase() (string, error) { return s.pass, nil }

// writeFakeChromeDB creates a minimal Chromium cookies DB with one encrypted row.
func writeFakeChromeDB(t *testing.T, dir, pass string) string {
	t.Helper()
	path := filepath.Join(dir, "Cookies")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE cookies(
		host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB,
		path TEXT, expires_utc INTEGER, is_secure INTEGER,
		is_httponly INTEGER, samesite INTEGER)`)
	if err != nil {
		t.Fatal(err)
	}
	enc := encryptChrome("v11", pass, "tok-abc")
	_, err = db.Exec(`INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?)`,
		"example.com", "sid", "", enc, "/", int64(0), 1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLinuxChromiumReadCookies(t *testing.T) {
	dir := t.TempDir()
	writeFakeChromeDB(t, dir, "keyring-pass")

	v := &LinuxChromium{
		Profile:     "test",
		CookiePath:  filepath.Join(dir, "Cookies"),
		KeyProvider: staticKey{"keyring-pass"},
	}
	cs, err := v.ReadCookies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cs))
	}
	got := cs[0]
	if got.Host != "example.com" || got.Name != "sid" || got.Value != "tok-abc" {
		t.Fatalf("unexpected cookie: %+v", got)
	}
	if !got.IsSecure || !got.IsHTTPOnly {
		t.Fatalf("flags not parsed: %+v", got)
	}
}
