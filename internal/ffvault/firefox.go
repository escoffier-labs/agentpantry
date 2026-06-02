package ffvault

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	_ "modernc.org/sqlite"
)

// Firefox reads cookies from a Firefox profile's cookies.sqlite (plaintext values).
type Firefox struct {
	Profile    string
	CookiePath string
}

func (f *Firefox) Name() string { return "firefox:" + f.Profile }

func copyToTemp(src string) (string, func(), error) {
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "agentpantry-ff-*.sqlite")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}

func (f *Firefox) ReadCookies(ctx context.Context) ([]cookie.Cookie, error) {
	tmp, cleanup, err := copyToTemp(f.CookiePath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", filepath.ToSlash(tmp)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// COALESCE so a NULL column (Firefox declares these nullable) yields a zero
	// value instead of failing the scan and aborting the whole read.
	rows, err := db.QueryContext(ctx, `SELECT COALESCE(host,''), COALESCE(name,''),
		COALESCE(value,''), COALESCE(path,''), COALESCE(expiry,0),
		COALESCE(isSecure,0), COALESCE(isHttpOnly,0), COALESCE(sameSite,0) FROM moz_cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []cookie.Cookie
	for rows.Next() {
		var (
			host, name, value, path    string
			expiry                     int64
			secure, httpOnly, sameSite int
		)
		if err := rows.Scan(&host, &name, &value, &path, &expiry, &secure, &httpOnly, &sameSite); err != nil {
			return nil, err
		}
		out = append(out, cookie.Cookie{
			Host: host, Name: name, Value: value, Path: path,
			ExpiresUTC: cookie.ExpiresFromUnix(expiry),
			IsSecure:   secure != 0, IsHTTPOnly: httpOnly != 0, SameSite: sameSite,
		})
	}
	return out, rows.Err()
}
