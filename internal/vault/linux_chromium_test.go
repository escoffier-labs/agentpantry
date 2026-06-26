package vault

import (
	"bytes"
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

// writeFakeChromeDBWithBadRow creates a cookies DB with one good v11 row and
// one row whose encrypted_value is corrupt (v11 prefix + 16 bytes of 0xFF),
// which cannot be decrypted with the given passphrase.
func writeFakeChromeDBWithBadRow(t *testing.T, dir, pass string) string {
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
	good := encryptChrome("v11", pass, "tok-abc")
	if _, err := db.Exec(`INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?)`,
		"example.com", "sid", "", good, "/", int64(0), 1, 1, 0); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte("v11"), bytes.Repeat([]byte{0xFF}, 16)...)
	if _, err := db.Exec(`INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?)`,
		"bad.example.com", "broken", "", bad, "/", int64(0), 1, 1, 0); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLinuxChromiumReadCookiesSkipsUndecryptableRow(t *testing.T) {
	dir := t.TempDir()
	writeFakeChromeDBWithBadRow(t, dir, "keyring-pass")

	v := &LinuxChromium{
		Profile:     "test",
		CookiePath:  filepath.Join(dir, "Cookies"),
		KeyProvider: staticKey{"keyring-pass"},
	}
	cs, err := v.ReadCookies(context.Background())
	if err != nil {
		t.Fatalf("undecryptable row should be skipped, not error: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("want 1 good cookie, got %d", len(cs))
	}
	got := cs[0]
	if got.Host != "example.com" || got.Name != "sid" || got.Value != "tok-abc" {
		t.Fatalf("unexpected cookie: %+v", got)
	}
}

// TestLinuxChromiumExcludesGarbageDecryptedRow guards the portal-key regression:
// a row that decrypts without error but yields non-printable bytes (a mismatched
// offline key) must be excluded, not passed downstream as a real cookie value.
func TestLinuxChromiumExcludesGarbageDecryptedRow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE cookies(
		host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB,
		path TEXT, expires_utc INTEGER, is_secure INTEGER,
		is_httponly INTEGER, samesite INTEGER)`); err != nil {
		t.Fatal(err)
	}
	good := encryptChrome("v11", "keyring-pass", "tok-abc")
	if _, err := db.Exec(`INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?)`,
		"example.com", "sid", "", good, "/", int64(0), 1, 1, 0); err != nil {
		t.Fatal(err)
	}
	// Decrypts cleanly under the same passphrase but to mostly non-printable
	// bytes, mimicking a value recovered with a key that did not actually match.
	// A real mismatched-key decrypt yields predominantly garbage, not a clean
	// string with a short garbage prefix.
	garbage := string([]byte{
		0xEF, 0xBF, 0xBD, 0xEF, 0xBF, 0xBD, 0x01, 0x07, 0x1b, 0x00,
		0xEF, 0xBF, 0xBD, 0x12, 0x7f, 0x03, 0xEF, 0xBF, 0xBD, 0x04,
	})
	bad := encryptChrome("v11", "keyring-pass", garbage)
	if _, err := db.Exec(`INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?)`,
		"linkedin.com", "li_at", "", bad, "/", int64(0), 1, 1, 0); err != nil {
		t.Fatal(err)
	}
	db.Close()

	v := &LinuxChromium{
		Profile:     "test",
		CookiePath:  path,
		KeyProvider: staticKey{"keyring-pass"},
	}
	cs, err := v.ReadCookies(context.Background())
	if err != nil {
		t.Fatalf("garbage row should be excluded, not error: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("garbage row must be excluded, want 1 cookie, got %d: %+v", len(cs), cs)
	}
	if cs[0].Name != "sid" || cs[0].Value != "tok-abc" {
		t.Fatalf("only the clean cookie should survive, got %+v", cs[0])
	}
}
