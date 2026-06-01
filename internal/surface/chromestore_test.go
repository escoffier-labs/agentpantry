package surface

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/vault"
	_ "modernc.org/sqlite"
)

type fakeKP struct{ p string }

func (k fakeKP) Passphrase() (string, error) { return k.p, nil }

// makeChromeDB creates a modern Chrome-schema cookies table.
func makeChromeDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE cookies(
		creation_utc INTEGER NOT NULL,
		host_key TEXT NOT NULL,
		top_frame_site_key TEXT NOT NULL,
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		encrypted_value BLOB NOT NULL,
		path TEXT NOT NULL,
		expires_utc INTEGER NOT NULL,
		is_secure INTEGER NOT NULL,
		is_httponly INTEGER NOT NULL,
		last_access_utc INTEGER NOT NULL,
		has_expires INTEGER NOT NULL,
		is_persistent INTEGER NOT NULL,
		priority INTEGER NOT NULL,
		samesite INTEGER NOT NULL,
		source_scheme INTEGER NOT NULL,
		source_port INTEGER NOT NULL,
		last_update_utc INTEGER NOT NULL,
		source_type INTEGER NOT NULL DEFAULT 0,
		has_cross_site_ancestor INTEGER NOT NULL DEFAULT 0,
		UNIQUE(host_key, top_frame_site_key, name, path, source_scheme, source_port))`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestChromeStoreWriteThenDecrypt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies")
	makeChromeDB(t, path)

	cs, err := NewChromeStore(path, fakeKP{"sink-keyring"})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	c := cookie.Cookie{Host: "github.com", Name: "sid", Path: "/", Value: "real-session", IsSecure: true, IsHTTPOnly: true, ExpiresUTC: 13300000000000000}
	if err := cs.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}

	// Read encrypted_value back and decrypt with the sink key.
	db, _ := sql.Open("sqlite", path)
	defer db.Close()
	var enc []byte
	var emptyVal string
	err = db.QueryRow(`SELECT value, encrypted_value FROM cookies WHERE host_key=? AND name=? AND path=?`,
		"github.com", "sid", "/").Scan(&emptyVal, &enc)
	if err != nil {
		t.Fatalf("row not written: %v", err)
	}
	if emptyVal != "" {
		t.Fatalf("plaintext value column should be empty, got %q", emptyVal)
	}
	got, err := vault.DecryptValue(enc, "sink-keyring")
	if err != nil || got != "real-session" {
		t.Fatalf("re-encrypt round trip failed: got %q err %v", got, err)
	}

	// Delete removes it.
	if err := cs.Apply(cookie.Diff{Deletes: []string{cookie.Key(c)}}); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM cookies WHERE host_key=?`, "github.com").Scan(&n)
	if n != 0 {
		t.Fatalf("delete failed, %d rows remain", n)
	}
}

func TestChromeStoreMissingDBErrors(t *testing.T) {
	_, err := NewChromeStore(filepath.Join(t.TempDir(), "nope", "Cookies"), fakeKP{"k"})
	if err == nil {
		t.Fatal("missing chrome store must error")
	}
}
