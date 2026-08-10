package sqluri

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestReadOnlyDSNShapes(t *testing.T) {
	tests := []struct {
		name string
		goos string
		path string
		want string
	}{
		{
			name: "posix absolute",
			goos: "linux",
			path: "/tmp/sidecar.db",
			want: "file:///tmp/sidecar.db?mode=ro",
		},
		{
			name: "posix space hash query",
			goos: "linux",
			path: "/tmp/a b#c?d.db",
			want: "file:///tmp/a%20b%23c%3Fd.db?mode=ro",
		},
		{
			name: "posix relative",
			goos: "linux",
			path: "rel/sidecar.db",
			want: "file:rel/sidecar.db?mode=ro",
		},
		{
			name: "windows drive",
			goos: "windows",
			path: `C:\Users\me\sidecar.db`,
			want: "file:///C:/Users/me/sidecar.db?mode=ro",
		},
		{
			name: "windows drive with space",
			goos: "windows",
			path: `C:\Users\me\My Docs\sidecar.db`,
			want: "file:///C:/Users/me/My%20Docs/sidecar.db?mode=ro",
		},
		{
			name: "windows unc",
			goos: "windows",
			path: `\\server\share\sidecar.db`,
			want: "file://server/share/sidecar.db?mode=ro",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readOnlyDSN(tt.path, tt.goos)
			if got != tt.want {
				t.Fatalf("ReadOnlyDSN(%q) on %s = %q, want %q", tt.path, tt.goos, got, tt.want)
			}
		})
	}
}

func TestOpenReadOnlyRejectsWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db with space.sqlite")

	w, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY); INSERT INTO t(id) VALUES(1)`); err != nil {
		t.Fatal(err)
	}
	w.Close()

	db, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`INSERT INTO t(id) VALUES(2)`)
	if err == nil {
		t.Fatal("write succeeded on OpenReadOnly handle")
	}
	if !strings.Contains(err.Error(), "readonly") && !strings.Contains(err.Error(), "(8)") {
		t.Fatalf("want SQLITE_READONLY, got %v", err)
	}

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("count=%d want 1 (unchanged)", n)
	}
}
