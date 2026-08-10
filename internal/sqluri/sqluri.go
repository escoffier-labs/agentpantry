// Package sqluri builds SQLite URI DSNs for modernc.org/sqlite.
//
// modernc only forwards query parameters such as mode=ro to SQLite when the
// DSN begins with "file:". A plain filesystem path with "?mode=ro" has the
// query stripped before open, so the handle is writable despite the suffix.
package sqluri

import (
	"database/sql"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite"
)

// ReadOnlyDSN returns a file: URI DSN that opens path in SQLite read-only mode.
// The path is percent-encoded so spaces, "#", "?", Windows drive letters, and
// UNC hosts survive URI parsing.
func ReadOnlyDSN(path string) string {
	return readOnlyDSN(path, runtime.GOOS)
}

func readOnlyDSN(path, goos string) string {
	u := fileURL(path, goos)
	u.RawQuery = "mode=ro"
	return u.String()
}

// OpenReadOnly opens path with modernc.org/sqlite in URI read-only mode.
func OpenReadOnly(path string) (*sql.DB, error) {
	return sql.Open("sqlite", ReadOnlyDSN(path))
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

	// UNC: \\server\share\file -> file://server/share/file
	if goos == "windows" && strings.HasPrefix(p, "//") {
		rest := strings.TrimPrefix(p, "//")
		host, pathPart, ok := strings.Cut(rest, "/")
		if !ok {
			return url.URL{Scheme: "file", Host: rest, Path: "/"}
		}
		return url.URL{Scheme: "file", Host: host, Path: "/" + pathPart}
	}

	// Windows drive letter: C:/foo -> file:///C:/foo
	if goos == "windows" && len(p) >= 2 && p[1] == ':' {
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
