package ffvault

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	_ "modernc.org/sqlite"
)

func writeFakeFirefoxDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE moz_cookies(
		id INTEGER PRIMARY KEY,
		originAttributes TEXT NOT NULL DEFAULT '',
		name TEXT, value TEXT, host TEXT, path TEXT,
		expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER,
		isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0,
		sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO moz_cookies(name,value,host,path,expiry,isSecure,isHttpOnly,sameSite)
		VALUES(?,?,?,?,?,?,?,?)`, "sid", "ff-token", ".github.com", "/", int64(1637000000), 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFirefoxReadCookies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cookies.sqlite")
	writeFakeFirefoxDB(t, path)

	f := &Firefox{Profile: "test", CookiePath: path}
	cs, err := f.ReadCookies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cs))
	}
	c := cs[0]
	if c.Host != ".github.com" || c.Name != "sid" || c.Value != "ff-token" || c.Path != "/" {
		t.Fatalf("unexpected cookie: %+v", c)
	}
	if c.ExpiresUTC != cookie.ExpiresFromUnix(1637000000) {
		t.Fatalf("expiry not converted to micros-1601: %d", c.ExpiresUTC)
	}
	if !c.IsSecure || !c.IsHTTPOnly || c.SameSite != 1 {
		t.Fatalf("flags/samesite wrong: %+v", c)
	}
}

func TestFirefoxMissingDBErrors(t *testing.T) {
	f := &Firefox{Profile: "p", CookiePath: filepath.Join(t.TempDir(), "nope.sqlite")}
	if _, err := f.ReadCookies(context.Background()); err == nil {
		t.Fatal("missing DB must error")
	}
}
