package vault

import "testing"

func FuzzDecryptValue(f *testing.F) {
	f.Add([]byte("v10abcdefghijklmnop"))
	f.Add([]byte("plain"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecryptValue(b, "pass") // must not panic
	})
}
