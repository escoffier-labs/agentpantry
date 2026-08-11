package sqluri

import (
	"database/sql"
	"path/filepath"
	"runtime"
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
			// Empty authority + UNC path. file://server/... is rejected by modernc
			// as "invalid uri authority".
			want: "file:////server/share/sidecar.db?mode=ro",
		},
		{
			name: "windows unc with space",
			goos: "windows",
			path: `\\server\share\My Docs\sidecar.db`,
			want: "file:////server/share/My%20Docs/sidecar.db?mode=ro",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readOnlyDSN(tt.path, tt.goos)
			if err != nil {
				t.Fatalf("ReadOnlyDSN(%q) on %s: unexpected error: %v", tt.path, tt.goos, err)
			}
			if got != tt.want {
				t.Fatalf("ReadOnlyDSN(%q) on %s = %q, want %q", tt.path, tt.goos, got, tt.want)
			}
		})
	}
}

// TestReadOnlyDSNWindowsUNCModerncParse proves the authority bug against the
// real modernc SQLite URI parser: file://server/... fails with invalid uri
// authority, while the empty-authority form reaches path open (no authority error).
func TestReadOnlyDSNWindowsUNCModerncParse(t *testing.T) {
	const unc = `\\server\share\sidecar.db`
	const buggy = "file://server/share/sidecar.db?mode=ro"

	buggyErr := pingSQLiteDSN(t, buggy)
	if buggyErr == nil || !strings.Contains(buggyErr.Error(), "invalid uri authority") {
		t.Fatalf("buggy UNC DSN %q: want invalid uri authority, got %v", buggy, buggyErr)
	}

	got, err := readOnlyDSN(unc, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "file://server/") || strings.HasPrefix(got, "file://server") {
		t.Fatalf("DSN still uses server authority: %q", got)
	}
	if wantPrefix := "file:////server/share/sidecar.db"; !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("DSN = %q, want prefix %q", got, wantPrefix)
	}

	gotErr := pingSQLiteDSN(t, got)
	if gotErr != nil && strings.Contains(gotErr.Error(), "invalid uri authority") {
		t.Fatalf("corrected UNC DSN %q still fails authority parse: %v", got, gotErr)
	}
}

func TestReadOnlyDSNWindowsDriveRelative(t *testing.T) {
	const driveRel = `C:sidecar.db`

	if runtime.GOOS == "windows" {
		got, err := readOnlyDSN(driveRel, "windows")
		if err != nil {
			t.Fatal(err)
		}
		// Must not silently become root-of-drive C:/sidecar.db.
		if got == "file:///C:/sidecar.db?mode=ro" || got == "file:///C:sidecar.db?mode=ro" {
			t.Fatalf("drive-relative path silently reinterpreted as absolute: %q", got)
		}
		if !strings.HasPrefix(got, "file:///C:/") || !strings.HasSuffix(got, "?mode=ro") {
			t.Fatalf("resolved DSN = %q, want absolute Windows file URI with mode=ro", got)
		}
		return
	}

	_, err := readOnlyDSN(driveRel, "windows")
	if err == nil {
		t.Fatal("expected error for windows drive-relative path when not running on Windows")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "drive-relative") {
		t.Fatalf("error %q should mention drive-relative", err)
	}

	// Absolute drive paths still work off-Windows (pure URI shaping).
	got, err := readOnlyDSN(`C:\Users\me\sidecar.db`, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if got != "file:///C:/Users/me/sidecar.db?mode=ro" {
		t.Fatalf("absolute drive path = %q", got)
	}
}

func pingSQLiteDSN(t *testing.T, dsn string) error {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Ping()
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
