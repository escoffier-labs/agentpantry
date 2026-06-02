//go:build windows

package vault

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/dbcopy"
	"github.com/escoffier-labs/agentpantry/internal/wincrypto"
	_ "modernc.org/sqlite"
)

// WindowsChromium reads a Chromium-family cookie store on Windows (pre-app-bound).
type WindowsChromium struct {
	Profile    string
	CookiePath string
	// LocalStatePath overrides the default discovery (the "Local State" file in
	// the User Data dir above the profile).
	LocalStatePath string
}

func (v *WindowsChromium) Name() string { return "chromium-win:" + v.Profile }

func (v *WindowsChromium) localStatePath() string {
	if v.LocalStatePath != "" {
		return v.LocalStatePath
	}
	// CookiePath is typically <UserData>/<Profile>/Network/Cookies; Local State
	// lives in <UserData>. Walk up to find it.
	dir := filepath.Dir(v.CookiePath)
	for i := 0; i < 3; i++ {
		cand := filepath.Join(dir, "Local State")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	return filepath.Join(filepath.Dir(v.CookiePath), "Local State")
}

func (v *WindowsChromium) key() ([]byte, error) {
	b, err := os.ReadFile(v.localStatePath())
	if err != nil {
		return nil, fmt.Errorf("read Local State: %w", err)
	}
	wrapped, err := wincrypto.ParseLocalStateKey(b)
	if err != nil {
		return nil, err
	}
	return wincrypto.UnwrapDPAPI(wrapped)
}

func (v *WindowsChromium) ReadCookies(ctx context.Context) ([]cookie.Cookie, error) {
	key, err := v.key()
	if err != nil {
		return nil, err
	}
	tmp, cleanup, err := dbcopy.ToTemp(v.CookiePath)
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
	skipped := 0
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
			dv, derr := wincrypto.DecryptV10GCM(enc, key)
			if derr != nil {
				// app-bound (v20) or otherwise undecryptable: skip until phase 7.
				skipped++
				continue
			}
			value = dv
		}
		out = append(out, cookie.Cookie{
			Host: host, Name: name, Value: value, Path: path,
			ExpiresUTC: expires, IsSecure: secure != 0,
			IsHTTPOnly: httpOnly != 0, SameSite: samesite,
		})
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "agentpantry: skipped %d cookie(s) not decryptable as v10 (app-bound v20 needs phase 7)\n", skipped)
	}
	return out, rows.Err()
}
