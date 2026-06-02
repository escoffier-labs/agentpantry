package surface

import (
	"database/sql"
	"os"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	_ "modernc.org/sqlite"
)

// Sidecar is a plaintext SQLite surface, written 0600.
type Sidecar struct {
	db *sql.DB
}

func NewSidecar(path string) (*Sidecar, error) {
	// Ensure the file exists with 0600 before the driver opens it.
	f, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
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
		db.Close()
		return nil, err
	}
	return &Sidecar{db: db}, nil
}

func (s *Sidecar) Close() error { return s.db.Close() }

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

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
