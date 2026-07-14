package surface

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
	_ "modernc.org/sqlite"
)

// Sidecar is a plaintext SQLite surface, written 0600.
type Sidecar struct {
	db *sql.DB
}

func NewSidecar(path string) (*Sidecar, error) {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to open sidecar symlink %s", path)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	// Ensure the file exists with 0600 before the driver opens it.
	f, err := os.OpenFile(path, os.O_CREATE, 0o600) // #nosec G304 -- sidecar path is an application-managed config path.
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cookies(
		host TEXT, name TEXT, path TEXT, value TEXT,
		expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER,
		PRIMARY KEY(host, name, path))`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS localstorage(
		origin TEXT, "key" TEXT, value TEXT,
		PRIMARY KEY(origin, "key"))`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Sidecar{db: db}, nil
}

// OpenSidecarReadOnly opens an existing sidecar store for reading only. Unlike
// NewSidecar it creates nothing - no directory, no file, no schema - and never
// changes permissions, so a read path like inventory cannot mutate an
// operator-supplied file. It refuses symlinks and non-regular files, opens
// SQLite in read-only mode, and requires the cookies table to be present so
// pointing it at an unrelated SQLite file fails cleanly.
func OpenSidecarReadOnly(path string) (*Sidecar, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to open sidecar symlink %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("sidecar path %s is not a regular file", path)
	}
	db, err := sql.Open("sqlite", filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	var name string
	row := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='cookies'`)
	if err := row.Scan(&name); err != nil {
		_ = db.Close()
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s is not a sidecar store (no cookies table)", path)
		}
		return nil, fmt.Errorf("read sidecar %s: %w", path, err)
	}
	return &Sidecar{db: db}, nil
}

func (s *Sidecar) Close() error { return s.db.Close() }

// List returns every cookie stored in the sidecar. It is the read counterpart
// to Apply, used by the inventory command to report on a backup store.
func (s *Sidecar) List() ([]cookie.Cookie, error) {
	rows, err := s.db.Query(`SELECT host, name, path, value, expires_utc,
		is_secure, is_httponly, samesite FROM cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cookie.Cookie
	for rows.Next() {
		var c cookie.Cookie
		var secure, httpOnly int
		if err := rows.Scan(&c.Host, &c.Name, &c.Path, &c.Value, &c.ExpiresUTC,
			&secure, &httpOnly, &c.SameSite); err != nil {
			return nil, err
		}
		c.IsSecure = secure != 0
		c.IsHTTPOnly = httpOnly != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// keyParts splits a cookie.Key() back into host, name, path.
func keyParts(k string) (host, name, path string) {
	p := strings.SplitN(k, "\x00", 3)
	for len(p) < 3 {
		p = append(p, "")
	}
	return p[0], p[1], p[2]
}

func (s *Sidecar) Apply(d cookie.Diff) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, c := range d.Upserts {
		_, err = tx.Exec(`INSERT INTO cookies(host,name,path,value,expires_utc,is_secure,is_httponly,samesite)
			VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(host,name,path) DO UPDATE SET
				value=excluded.value, expires_utc=excluded.expires_utc,
				is_secure=excluded.is_secure, is_httponly=excluded.is_httponly,
				samesite=excluded.samesite`,
			c.Host, c.Name, c.Path, c.Value, c.ExpiresUTC,
			b2i(c.IsSecure), b2i(c.IsHTTPOnly), c.SameSite)
		if err != nil {
			return err
		}
	}
	for _, k := range d.Deletes {
		host, name, path := keyParts(k)
		if _, err = tx.Exec(`DELETE FROM cookies WHERE host=? AND name=? AND path=?`, host, name, path); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// hasTable reports whether a table exists, so read paths tolerate an older
// sidecar that predates the localstorage table.
func (s *Sidecar) hasTable(name string) bool {
	var got string
	err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&got)
	return err == nil
}

// ListStorage returns every localStorage item stored in the sidecar. An older
// sidecar without the table yields an empty list, not an error.
func (s *Sidecar) ListStorage() ([]webstorage.Item, error) {
	if !s.hasTable("localstorage") {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT origin, "key", value FROM localstorage`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webstorage.Item
	for rows.Next() {
		var it webstorage.Item
		if err := rows.Scan(&it.Origin, &it.Key, &it.Value); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ApplyStorage upserts and deletes localStorage items in the same 0600 store as
// cookies, so a captured session's localStorage is persisted for restore.
func (s *Sidecar) ApplyStorage(d webstorage.Diff) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, it := range d.Upserts {
		if _, err = tx.Exec(`INSERT INTO localstorage(origin,"key",value)
			VALUES(?,?,?)
			ON CONFLICT(origin,"key") DO UPDATE SET value=excluded.value`,
			it.Origin, it.Key, it.Value); err != nil {
			return err
		}
	}
	for _, k := range d.Deletes {
		origin, key, ok := strings.Cut(k, "\x00")
		if !ok {
			continue
		}
		if _, err = tx.Exec(`DELETE FROM localstorage WHERE origin=? AND "key"=?`, origin, key); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
