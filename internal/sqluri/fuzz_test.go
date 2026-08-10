package sqluri

import "testing"

// FuzzReadOnlyDSN ensures arbitrary paths never panic when turned into a DSN.
func FuzzReadOnlyDSN(f *testing.F) {
	f.Add("/tmp/sidecar.db")
	f.Add("rel/db.sqlite")
	f.Add(`/tmp/a b#c?d.db`)
	f.Add(`C:\Users\me\sidecar.db`)
	f.Add(`\\server\share\sidecar.db`)
	f.Fuzz(func(t *testing.T, path string) {
		_ = ReadOnlyDSN(path)
		_ = readOnlyDSN(path, "windows")
		_ = readOnlyDSN(path, "linux")
	})
}
