package surface

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/vault"
	_ "modernc.org/sqlite"
)

var chromeWarnOnce sync.Once

// ChromeStore re-encrypts cookies with the sink's keyring key and writes them
// into an existing Chrome-schema Cookies SQLite. Targets a not-running profile.
type ChromeStore struct {
	db      *sql.DB
	keyPass string
	cols    map[string]string // present column name -> upper-cased declared type
}

func NewChromeStore(cookiePath string, kp KeyProvider) (*ChromeStore, error) {
	if _, err := os.Stat(cookiePath); err != nil {
		return nil, fmt.Errorf("chrome cookie store not found at %s: %w", cookiePath, err)
	}
	warnIfChromeRunning(cookiePath)

	pass, err := kp.Passphrase()
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", cookiePath)
	if err != nil {
		return nil, err
	}
	cols, err := introspectCookieColumns(db)
	if err != nil {
		db.Close()
		return nil, err
	}
	if len(cols) == 0 {
		db.Close()
		return nil, fmt.Errorf("no cookies table in %s", cookiePath)
	}
	return &ChromeStore{db: db, keyPass: pass, cols: cols}, nil
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
	enc, err := vault.EncryptValue(c.Value, s.keyPass)
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

func (s *ChromeStore) Apply(d cookie.Diff) error {
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
		var colNames, placeholders []string
		var args []interface{}
		for col, typ := range s.cols {
			colNames = append(colNames, col)
			placeholders = append(placeholders, "?")
			if v, ok := mapped[col]; ok {
				args = append(args, v)
			} else {
				args = append(args, zeroForType(typ))
			}
		}
		q := fmt.Sprintf("INSERT OR REPLACE INTO cookies(%s) VALUES(%s)",
			strings.Join(colNames, ","), strings.Join(placeholders, ","))
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
