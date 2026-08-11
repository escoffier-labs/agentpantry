package sqluri

import (
	"strings"
	"testing"
)

// FuzzReadOnlyDSN ensures arbitrary paths never panic when turned into a DSN.
func FuzzReadOnlyDSN(f *testing.F) {
	f.Add("/tmp/sidecar.db")
	f.Add("rel/db.sqlite")
	f.Add(`/tmp/a b#c?d.db`)
	f.Add(`C:\Users\me\sidecar.db`)
	f.Add(`\\server\share\sidecar.db`)
	f.Add(`C:sidecar.db`)
	f.Fuzz(func(t *testing.T, path string) {
		_, _ = ReadOnlyDSN(path)
		dsn, err := readOnlyDSN(path, "windows")
		_, _ = readOnlyDSN(path, "linux")
		if err != nil {
			return
		}
		// UNC must keep empty authority; file://host/... is invalid for modernc.
		if strings.HasPrefix(path, `\\`) && strings.HasPrefix(dsn, "file://") && !strings.HasPrefix(dsn, "file:///") {
			t.Fatalf("windows UNC DSN has non-empty authority: path=%q dsn=%q", path, dsn)
		}
	})
}
