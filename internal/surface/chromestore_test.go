package surface

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/vault"
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

func TestNewChromeStoreEncUsesInjectedEncryptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies")
	makeChromeDB(t, path)

	enc := func(v string) ([]byte, error) { return []byte("ENC:" + v), nil }
	cs, err := NewChromeStoreEnc(path, enc)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	c := cookie.Cookie{Host: "github.com", Name: "sid", Path: "/", Value: "hello"}
	if err := cs.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}
	db, _ := sql.Open("sqlite", path)
	defer db.Close()
	var got []byte
	if err := db.QueryRow(`SELECT encrypted_value FROM cookies WHERE host_key=?`, "github.com").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ENC:hello" {
		t.Fatalf("writer did not use the injected encryptor: %q", got)
	}
}

// chromeEpochFloor is well above any plausible Unix-second timestamp and below
// any real Chromium microsecond-since-1601 value for post-2010 dates.
const chromeEpochFloor int64 = 10_000_000_000_000_000

func assertChromeEpoch(t *testing.T, label string, v int64) {
	t.Helper()
	if v < chromeEpochFloor {
		t.Fatalf("%s=%d looks like Unix seconds, want Chromium epoch micros (>= %d)", label, v, chromeEpochFloor)
	}
	// Sanity: must round-trip near "now" via the shared helper.
	now := cookie.ExpiresFromUnix(time.Now().Unix())
	if v < now-2_000_000_000 || v > now+2_000_000_000 {
		// Allow 2000s of skew for slow tests; still same second-scale epoch family.
		t.Fatalf("%s=%d not near current Chromium epoch %d", label, v, now)
	}
}

func readCookieTimestamps(t *testing.T, dbPath, host, name, path string) (creation, access, update int64) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.QueryRow(
		`SELECT creation_utc, last_access_utc, last_update_utc FROM cookies WHERE host_key=? AND name=? AND path=?`,
		host, name, path,
	).Scan(&creation, &access, &update)
	if err != nil {
		t.Fatalf("read timestamps: %v", err)
	}
	return creation, access, update
}

func listCookieBackups(t *testing.T, cookiePath string) []string {
	t.Helper()
	dir := filepath.Dir(cookiePath)
	base := filepath.Base(cookiePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	prefix := base + ".bak."
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func TestChromeStoreNewCookieTimestampsAreChromeEpoch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies")
	makeChromeDB(t, path)

	cs, err := NewChromeStoreEnc(path, func(v string) ([]byte, error) { return []byte("E:" + v), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	c := cookie.Cookie{Host: "example.com", Name: "new", Path: "/", Value: "v1"}
	if err := cs.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}

	creation, access, update := readCookieTimestamps(t, path, "example.com", "new", "/")
	assertChromeEpoch(t, "creation_utc", creation)
	assertChromeEpoch(t, "last_access_utc", access)
	assertChromeEpoch(t, "last_update_utc", update)
	if creation != access || access != update {
		t.Fatalf("new cookie should stamp creation/access/update equally, got %d %d %d", creation, access, update)
	}
}

func TestChromeStoreReplaceKeepsCreationUpdatesAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies")
	makeChromeDB(t, path)

	// Seed a row with a fixed historical creation_utc so we can prove retention.
	const seededCreation int64 = 13_000_000_000_000_000
	seedDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = seedDB.Exec(`INSERT INTO cookies(
		creation_utc, host_key, top_frame_site_key, name, value, encrypted_value, path,
		expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent,
		priority, samesite, source_scheme, source_port, last_update_utc, source_type, has_cross_site_ancestor
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		seededCreation, "example.com", "", "sid", "", []byte("old"), "/",
		0, 0, 0, int64(0), 0, 0,
		1, 0, 2, -1, int64(0), 0, 0,
	)
	if err != nil {
		seedDB.Close()
		t.Fatal(err)
	}
	seedDB.Close()

	cs, err := NewChromeStoreEnc(path, func(v string) ([]byte, error) { return []byte("E:" + v), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// Sleep so last_access/update cannot equal a zero seed even if clocks skew oddly.
	time.Sleep(10 * time.Millisecond)
	c := cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "replaced"}
	if err := cs.Apply(cookie.Diff{Upserts: []cookie.Cookie{c}}); err != nil {
		t.Fatal(err)
	}

	creation, access, update := readCookieTimestamps(t, path, "example.com", "sid", "/")
	if creation != seededCreation {
		t.Fatalf("replace must keep creation_utc: got %d want %d", creation, seededCreation)
	}
	assertChromeEpoch(t, "last_access_utc", access)
	assertChromeEpoch(t, "last_update_utc", update)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var enc []byte
	if err := db.QueryRow(`SELECT encrypted_value FROM cookies WHERE host_key=? AND name=?`, "example.com", "sid").Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if string(enc) != "E:replaced" {
		t.Fatalf("value not replaced: %q", enc)
	}
}

func TestChromeStoreBackupBeforeWriteHasPreTransactionContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies")
	makeChromeDB(t, path)

	enc := func(v string) ([]byte, error) { return []byte("E:" + v), nil }
	cs, err := NewChromeStoreEnc(path, enc)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	c1 := cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "first"}
	if err := cs.Apply(cookie.Diff{Upserts: []cookie.Cookie{c1}}); err != nil {
		t.Fatal(err)
	}
	beforeSecond := listCookieBackups(t, path)

	c2 := cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "second"}
	if err := cs.Apply(cookie.Diff{Upserts: []cookie.Cookie{c2}}); err != nil {
		t.Fatal(err)
	}
	afterSecond := listCookieBackups(t, path)
	if len(afterSecond) <= len(beforeSecond) {
		t.Fatalf("expected a new backup before the second write, before=%d after=%d", len(beforeSecond), len(afterSecond))
	}

	// Newest backup should hold pre-second-write content (value "first").
	var newest string
	var newestMod time.Time
	for _, b := range afterSecond {
		info, err := os.Stat(b)
		if err != nil {
			t.Fatal(err)
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest = b
			newestMod = info.ModTime()
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(newest)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("backup must be 0600, got %v", info.Mode().Perm())
		}
	}

	bdb, err := sql.Open("sqlite", newest)
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()
	var encVal []byte
	if err := bdb.QueryRow(`SELECT encrypted_value FROM cookies WHERE host_key=? AND name=?`, "example.com", "sid").Scan(&encVal); err != nil {
		t.Fatalf("backup must be readable SQLite with pre-transaction row: %v", err)
	}
	if string(encVal) != "E:first" {
		t.Fatalf("backup should have pre-write value, got %q", encVal)
	}

	// Live DB has the post-write value.
	ldb, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ldb.Close()
	if err := ldb.QueryRow(`SELECT encrypted_value FROM cookies WHERE host_key=? AND name=?`, "example.com", "sid").Scan(&encVal); err != nil {
		t.Fatal(err)
	}
	if string(encVal) != "E:second" {
		t.Fatalf("live store should have new value, got %q", encVal)
	}
}

func TestChromeStoreFailedWriteLeavesUsableBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies")
	makeChromeDB(t, path)

	// Seed a successful cookie so the pre-failure backup has real content.
	ok, err := NewChromeStoreEnc(path, func(v string) ([]byte, error) { return []byte("E:" + v), nil })
	if err != nil {
		t.Fatal(err)
	}
	seed := cookie.Cookie{Host: "example.com", Name: "sid", Path: "/", Value: "keep-me"}
	if err := ok.Apply(cookie.Diff{Upserts: []cookie.Cookie{seed}}); err != nil {
		ok.Close()
		t.Fatal(err)
	}
	ok.Close()

	backupsBefore := listCookieBackups(t, path)

	failing, err := NewChromeStoreEnc(path, func(string) ([]byte, error) {
		return nil, errors.New("encrypt boom")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer failing.Close()

	err = failing.Apply(cookie.Diff{Upserts: []cookie.Cookie{{
		Host: "example.com", Name: "sid", Path: "/", Value: "should-not-land",
	}}})
	if err == nil {
		t.Fatal("expected encrypt failure to abort Apply")
	}

	backupsAfter := listCookieBackups(t, path)
	if len(backupsAfter) <= len(backupsBefore) {
		t.Fatalf("failed write must still create a pre-transaction backup, before=%d after=%d", len(backupsBefore), len(backupsAfter))
	}

	var newest string
	var newestMod time.Time
	for _, b := range backupsAfter {
		info, err := os.Stat(b)
		if err != nil {
			t.Fatal(err)
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest = b
			newestMod = info.ModTime()
		}
	}

	bdb, err := sql.Open("sqlite", newest)
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()
	var enc []byte
	var n int
	if err := bdb.QueryRow(`SELECT COUNT(*) FROM cookies`).Scan(&n); err != nil {
		t.Fatalf("failed-write backup is not usable SQLite: %v", err)
	}
	if n != 1 {
		t.Fatalf("backup should have pre-transaction 1 cookie, got %d", n)
	}
	if err := bdb.QueryRow(`SELECT encrypted_value FROM cookies WHERE name=?`, "sid").Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if string(enc) != "E:keep-me" {
		t.Fatalf("backup should preserve pre-transaction content, got %q", enc)
	}

	// Live DB rolled back / never mutated: still the seed.
	ldb, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ldb.Close()
	if err := ldb.QueryRow(`SELECT encrypted_value FROM cookies WHERE name=?`, "sid").Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if string(enc) != "E:keep-me" {
		t.Fatalf("live DB should keep pre-transaction content after failed write, got %q", enc)
	}
}
