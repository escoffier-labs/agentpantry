package wincrypto

import "testing"

func FuzzDecryptV10GCM(f *testing.F) {
	f.Add([]byte("v10shorttooshort"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecryptV10GCM(b, key32()) // must not panic
	})
}
