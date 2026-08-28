package receipt

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

func FuzzVerify(f *testing.F) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	log := &Log{
		Path:     filepath.Join(f.TempDir(), "seed.jsonl"),
		Key:      key,
		Role:     "sink",
		SourceID: "source",
		SinkID:   "127.0.0.1:1",
	}
	p := wire.Payload{Cookies: cookie.Diff{Upserts: []cookie.Cookie{{Host: "a.com", Name: "n", Path: "/"}}}}
	if err := log.Append(EventApply, p); err != nil {
		f.Fatal(err)
	}
	seed, err := os.ReadFile(log.Path)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte("{}\n"))
	f.Add([]byte("not json\n"))
	f.Add([]byte(`{"v":1,"ts":"t","role":"r","source_id":"s","sink_id":"k","event":"e","payload_hash":"` + hex.EncodeToString(make([]byte, 32)) + `","prev_hash":"` + GenesisPrev + `","sig":"` + hex.EncodeToString(make([]byte, 32)) + `"}` + "\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Skip()
		}
		path := filepath.Join(dir, "receipts.jsonl")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		_, _ = Verify(path, key) // must not panic
		_, _ = ReadAll(path)
	})
}

func FuzzPayloadHash(f *testing.F) {
	f.Add("host", "name", "path", "value", "secret-name", "https://a.com", "k")
	f.Fuzz(func(t *testing.T, host, name, path, value, sname, origin, skey string) {
		p := wire.Payload{
			Cookies: cookie.Diff{Upserts: []cookie.Cookie{{Host: host, Name: name, Path: path, Value: value}}},
			Secrets: secret.Diff{Upserts: []secret.Secret{{Name: sname, Value: value}}},
			Storage: webstorage.Diff{Upserts: []webstorage.Item{{Origin: origin, Key: skey, Value: value}}},
		}
		h, err := PayloadHash(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(h) != hashHexLen {
			t.Fatalf("hash length %d", len(h))
		}
		q := p
		q.Cookies.Upserts[0].Value = value + "x"
		q.Secrets.Upserts[0].Value = value + "y"
		q.Storage.Upserts[0].Value = value + "z"
		h2, err := PayloadHash(q)
		if err != nil {
			t.Fatal(err)
		}
		if h != h2 {
			t.Fatal("payload hash must ignore values")
		}
	})
}
