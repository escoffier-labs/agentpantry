package vault

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/solomonneas/agentpantry/internal/cookie"
	_ "modernc.org/sqlite"
)

// LinuxChromium reads a Chromium-family cookie store on Linux.
type LinuxChromium struct {
	Profile     string
	CookiePath  string
	KeyProvider KeyProvider
}

func (v *LinuxChromium) Name() string { return "chromium:" + v.Profile }

// copyToTemp copies the (possibly locked) cookie DB to a temp file.
func copyToTemp(src string) (string, func(), error) {
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "agentpantry-cookies-*.db")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	cleanup := func() { os.Remove(tmp.Name()) }
	return tmp.Name(), cleanup, nil
}

func (v *LinuxChromium) ReadCookies(ctx context.Context) ([]cookie.Cookie, error) {
	pass, err := v.KeyProvider.Passphrase()
	if err != nil {
		return nil, fmt.Errorf("keyring passphrase: %w", err)
	}
	tmp, cleanup, err := copyToTemp(v.CookiePath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", filepath.ToSlash(tmp)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, `SELECT host_key, name, value, encrypted_value,
		path, expires_utc, is_secure, is_httponly, samesite FROM cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []cookie.Cookie
	for rows.Next() {
		var (
			host, name, plain, path    string
			enc                        []byte
			expires                    int64
			secure, httpOnly, samesite int
		)
		if err := rows.Scan(&host, &name, &plain, &enc, &path, &expires, &secure, &httpOnly, &samesite); err != nil {
			return nil, err
		}
		value := plain
		if len(enc) > 0 {
			value, err = DecryptValue(enc, pass)
			if err != nil {
				return nil, fmt.Errorf("decrypt %s/%s: %w", host, name, err)
			}
		}
		out = append(out, cookie.Cookie{
			Host: host, Name: name, Value: value, Path: path,
			ExpiresUTC: expires, IsSecure: secure != 0,
			IsHTTPOnly: httpOnly != 0, SameSite: samesite,
		})
	}
	return out, rows.Err()
}
