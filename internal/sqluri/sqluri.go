// Package sqluri builds SQLite URI DSNs for modernc.org/sqlite.
//
// modernc only forwards query parameters such as mode=ro to SQLite when the
// DSN begins with "file:". A plain filesystem path with "?mode=ro" has the
// query stripped before open, so the handle is writable despite the suffix.
package sqluri

import (
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite"
)

// ReadOnlyDSN returns a file: URI DSN that opens path in SQLite read-only mode.
// The path is percent-encoded so spaces, "#", "?", Windows drive letters, and
// UNC hosts survive URI parsing.
//
// Windows drive-relative paths (e.g. C:sidecar.db) are resolved with Windows
// filepath semantics when running on Windows; off Windows they are rejected
// rather than silently reinterpreted as absolute C:/sidecar.db.
func ReadOnlyDSN(path string) (string, error) {
	return readOnlyDSN(path, runtime.GOOS)
}

func readOnlyDSN(path, goos string) (string, error) {
	if goos == "windows" && isWindowsDriveRelative(path) {
		if runtime.GOOS != "windows" {
			return "", fmt.Errorf("windows drive-relative path %q cannot be resolved correctly on %s", path, runtime.GOOS)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("resolve windows drive-relative path %q: %w", path, err)
		}
		path = abs
	}

	u := fileURL(path, goos)
	u.RawQuery = "mode=ro"
	return u.String(), nil
}

// OpenReadOnly opens path with modernc.org/sqlite in URI read-only mode.
func OpenReadOnly(path string) (*sql.DB, error) {
	dsn, err := ReadOnlyDSN(path)
	if err != nil {
		return nil, err
	}
	return sql.Open("sqlite", dsn)
}

// isWindowsDriveRelative reports whether path is a Windows drive-relative form
// such as C:sidecar.db or C: (drive letter + colon, without a directory separator).
func isWindowsDriveRelative(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	c := path[0]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return false
	}
	if len(path) == 2 {
		return true
	}
	return path[2] != '\\' && path[2] != '/'
}

// fileURL converts a filesystem path into a file: URL per SQLite's URI rules:
// https://www.sqlite.org/uri.html
func fileURL(path, goos string) url.URL {
	p := path
	if goos == "windows" {
		p = strings.ReplaceAll(p, `\`, `/`)
	} else {
		p = filepath.ToSlash(p)
	}

	// UNC: \\server\share\file -> file:////server/share/file (empty authority).
	// file://server/... is rejected by modernc as "invalid uri authority".
	if goos == "windows" && strings.HasPrefix(p, "//") {
		return url.URL{Scheme: "file", Path: p}
	}

	// Windows absolute drive path: C:/foo -> file:///C:/foo
	if goos == "windows" && len(p) >= 3 && p[1] == ':' && p[2] == '/' {
		return url.URL{Scheme: "file", Path: "/" + p}
	}

	// Absolute POSIX path: /tmp/foo -> file:///tmp/foo
	if strings.HasPrefix(p, "/") {
		return url.URL{Scheme: "file", Path: p}
	}

	// Relative path: use Opaque so String() yields file:rel/path, not file:///rel/path.
	return url.URL{Scheme: "file", Opaque: escapeOpaquePath(p)}
}

// escapeOpaquePath percent-encodes bytes that would break URI parsing when the
// path is placed in url.URL.Opaque (which is otherwise copied verbatim).
func escapeOpaquePath(p string) string {
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '/' || c == '-' || c == '.' || c == '_' || c == '~' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		default:
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		}
	}
	return b.String()
}
