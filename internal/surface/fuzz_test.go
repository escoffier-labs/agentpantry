package surface

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
)

func FuzzParseNetscapeLine(f *testing.F) {
	f.Add("a.com\tFALSE\t/\tFALSE\t0\tn\tv")
	f.Add("# comment")
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseNetscapeLine(line) // must not panic
	})
}

// FuzzStorageStateSeed feeds arbitrary bytes to the storageState file parser: a
// malformed or hostile file must be refused or parsed, never panic, and a seeded
// surface must round-trip through Apply/ApplyStorage without crashing.
func FuzzStorageStateSeed(f *testing.F) {
	f.Add([]byte(`{"cookies":[],"origins":[]}`))
	f.Add([]byte(`{"origins":[{"origin":"https://a.com","localStorage":[{"name":"k","value":"v"}]}]}`))
	f.Add([]byte(`{"cookies":[{"name":"n","value":"v","domain":"a.com","path":"/","expires":-1}]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Skip()
		}
		path := filepath.Join(dir, "state.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		ss, err := NewStorageState(path)
		if err != nil {
			return // a foreign/invalid file is refused, not a crash
		}
		_ = ss.Apply(cookie.Diff{})
		_ = ss.ApplyStorage(webstorage.Diff{})
	})
}
