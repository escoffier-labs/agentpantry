package wire

import (
	"encoding/json"
	"testing"
)

func FuzzPayloadUnmarshal(f *testing.F) {
	f.Add([]byte(`{"cookies":{"upserts":[]},"secrets":{"upserts":[]}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var p Payload
		_ = json.Unmarshal(b, &p) // must not panic
		_ = p.IsEmpty()
	})
}
