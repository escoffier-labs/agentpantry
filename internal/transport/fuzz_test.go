package transport

import "testing"

func FuzzOpen(f *testing.F) {
	f.Add([]byte("v10short"))
	o, _ := NewOpener(key32(), salt16())
	fo, _ := NewFallbackOpener(key32(), oldKey32(), salt16())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = o.Open(b)  // must not panic
		_, _ = fo.Open(b) // must not panic while probing either key
	})
}
