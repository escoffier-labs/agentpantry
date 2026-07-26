package surface

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/dbcopy"
	"github.com/escoffier-labs/agentpantry/internal/privfile"
	"github.com/escoffier-labs/agentpantry/internal/vault"
	_ "modernc.org/sqlite"
)

var chromeWarnOnce sync.Once

// ChromeStore re-encrypts cookies with the sink's keyring key and writes them
// into an existing Chrome-schema Cookies SQLite. Targets a not-running profile.
type ChromeStore struct {
	db      *sql.DB
	path    string
	encrypt func(plaintext string) ([]byte, error)
	cols    map[string]string // present column name -> upper-cased declared type
}

// NewChromeStoreEnc opens an existing Chrome-schema Cookies SQLite and writes
// cookies whose values are encrypted by the supplied encryptor (platform- and
// scheme-specific). Targets a not-running profile.
func NewChromeStoreEnc(cookiePath string, encrypt func(string) ([]byte, error)) (*ChromeStore, error) {
	if _, err := os.Stat(cookiePath); err != nil {
		return nil, fmt.Errorf("chrome cookie store not found at %s: %w", cookiePath, err)
	}
	warnIfChromeRunning(cookiePath)

	db, err := sql.Open("sqlite", cookiePath)
	if err != nil {
		return nil, err
	}
	cols, err := introspectCookieColumns(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if len(cols) == 0 {
		_ = db.Close()
		return nil, fmt.Errorf("no cookies table in %s", cookiePath)
	}
	return &ChromeStore{db: db, path: cookiePath, encrypt: encrypt, cols: cols}, nil
}

// NewChromeStore wires the Linux v11 AES-128-CBC encryptor from a keyring
// passphrase provider.
func NewChromeStore(cookiePath string, kp KeyProvider) (*ChromeStore, error) {
	pass, err := kp.Passphrase()
	if err != nil {
		return nil, err
	}
	return NewChromeStoreEnc(cookiePath, func(v string) ([]byte, error) {
		return vault.EncryptValue(v, pass)
	})
}

func (s *ChromeStore) Close() error { return s.db.Close() }

func introspectCookieColumns(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`PRAGMA table_info(cookies)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]string{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = strings.ToUpper(ctype)
	}
	return cols, rows.Err()
}

func (s *ChromeStore) mappedValues(c cookie.Cookie) (map[string]interface{}, error) {
	enc, err := s.encrypt(c.Value)
	if err != nil {
		return nil, err
	}
	persistent := 0
	if c.ExpiresUTC > 0 {
		persistent = 1
	}
	return map[string]interface{}{
		"host_key":                c.Host,
		"name":                    c.Name,
		"value":                   "",
		"encrypted_value":         enc,
		"path":                    c.Path,
		"expires_utc":             c.ExpiresUTC,
		"is_secure":               b2i(c.IsSecure),
		"is_httponly":             b2i(c.IsHTTPOnly),
		"samesite":                c.SameSite,
		"has_expires":             persistent,
		"is_persistent":           persistent,
		"creation_utc":            int64(0),
		"last_access_utc":         int64(0),
		"last_update_utc":         int64(0),
		"priority":                1,
		"source_scheme":           2,
		"source_port":             -1,
		"top_frame_site_key":      "",
		"source_type":             0,
		"has_cross_site_ancestor": 0,
	}, nil
}

func zeroForType(t string) interface{} {
	switch {
	case strings.Contains(t, "INT"):
		return 0
	case strings.Contains(t, "BLOB"):
		return []byte{}
	default:
		return ""
	}
}

// backupCookiesDB copies path beside itself as path.bak.<UTC timestamp> with
// private mode, using dbcopy for the file copy and privfile for the 0600 write.
// Returns the backup path. The backup captures pre-transaction content so a
// later write failure still leaves a readable SQLite snapshot.
func backupCookiesDB(path string) (string, error) {
	tmp, cleanup, err := dbcopy.ToTemp(path)
	if err != nil {
		return "", fmt.Errorf("backup cookies db: %w", err)
	}
	defer cleanup()

	data, err := os.ReadFile(tmp) // #nosec G304 -- temp path from dbcopy.ToTemp
	if err != nil {
		return "", fmt.Errorf("read cookies backup temp: %w", err)
	}

	now := time.Now().UTC()
	base := fmt.Sprintf("%s.bak.%s", path, now.Format("20060102T150405Z"))
	for i := 0; i < 100; i++ {
		backupPath := base
		if i > 0 {
			backupPath = fmt.Sprintf("%s.%d", base, i)
		}
		if _, err := os.Lstat(backupPath); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return "", err
		}
		if err := privfile.Write(backupPath, data); err != nil {
			return "", fmt.Errorf("write cookies backup: %w", err)
		}
		return backupPath, nil
	}
	return "", fmt.Errorf("could not create unique backup path for %s", path)
}

// stampTimestamps gives new rows real creation/access/update times. Apply's
// conflict update omits creation_utc, so existing rows keep their original
// creation time while access and update advance.
func stampTimestamps(mapped map[string]interface{}) {
	now := cookie.ExpiresFromUnix(time.Now().Unix())
	mapped["creation_utc"] = now
	mapped["last_access_utc"] = now
	mapped["last_update_utc"] = now
}

func (s *ChromeStore) Apply(d cookie.Diff) error {
	if len(d.Upserts) == 0 && len(d.Deletes) == 0 {
		return nil
	}

	// Offline-profile safety (#39 / #26 alignment): snapshot the Cookies DB
	// before any mutation. A failed write must leave this backup intact.
	if _, err := backupCookiesDB(s.path); err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, c := range d.Upserts {
		mapped, err := s.mappedValues(c)
		if err != nil {
			return err
		}
		stampTimestamps(mapped)
		var colNames, placeholders, updates []string
		var args []interface{}
		for col, typ := range s.cols {
			quoted := "\"" + strings.ReplaceAll(col, "\"", "\"\"") + "\""
			colNames = append(colNames, quoted)
			placeholders = append(placeholders, "?")
			if col != "creation_utc" {
				updates = append(updates, quoted+"=excluded."+quoted)
			}
			if v, ok := mapped[col]; ok {
				args = append(args, v)
			} else {
				args = append(args, zeroForType(typ))
			}
		}
		q := fmt.Sprintf("INSERT INTO cookies(%s) VALUES(%s) ON CONFLICT DO UPDATE SET %s", // #nosec G201 -- values are parameterized; identifiers are quoted from SQLite schema introspection.
			strings.Join(colNames, ","), strings.Join(placeholders, ","), strings.Join(updates, ","))
		if _, err := tx.Exec(q, args...); err != nil {
			return err
		}
	}
	for _, k := range d.Deletes {
		host, name, path := keyParts(k)
		if _, err := tx.Exec(`DELETE FROM cookies WHERE host_key=? AND name=? AND path=?`, host, name, path); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// warnIfChromeRunning logs once if a SingletonLock suggests Chrome is live.
func warnIfChromeRunning(cookiePath string) {
	dir := filepath.Dir(cookiePath)
	for _, c := range []string{
		filepath.Join(dir, "SingletonLock"),
		filepath.Join(filepath.Dir(dir), "SingletonLock"),
	} {
		if _, err := os.Lstat(c); err == nil {
			chromeWarnOnce.Do(func() {
				fmt.Fprintln(os.Stderr, "agentpantry: a Chrome SingletonLock is present; the target profile may be running. Writing a live profile is unsupported and Chrome may ignore or overwrite these cookies.")
			})
			return
		}
	}
}
