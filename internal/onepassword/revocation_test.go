package onepassword

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/sink"
	"github.com/escoffier-labs/agentpantry/internal/source"
	"github.com/escoffier-labs/agentpantry/internal/state"
	"github.com/escoffier-labs/agentpantry/internal/surface"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

// This cross-package case uses the actual Reader with the fake op runner, then
// exercises restart revocation through the real encrypted transport and sink.
func TestEmptySelectionThenSourceRemovalRevokesAtSink(t *testing.T) {
	r, f, now := fixture(t)
	f.values["a"] = `{"label":"password","value":"unique-op-fixture-value"}`
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	sd, err := surface.NewSecretDir(filepath.Join(dir, "sink"))
	if err != nil {
		t.Fatal(err)
	}
	s := &source.Syncer{Secrets: []source.SecretReader{r}, StatePath: path}
	cycle := func(s *source.Syncer) wire.Payload {
		t.Helper()
		var handshake, frames bytes.Buffer
		salt, err := transport.SendSalt(&handshake)
		if err != nil {
			t.Fatal(err)
		}
		received, err := transport.RecvSalt(&handshake)
		if err != nil {
			t.Fatal(err)
		}
		key := bytes.Repeat([]byte{24}, 32)
		sealer, err := transport.NewSealer(key, received)
		if err != nil {
			t.Fatal(err)
		}
		opener, err := transport.NewOpener(key, salt)
		if err != nil {
			t.Fatal(err)
		}
		s.Sealer = sealer
		s.Out = &frames
		if err = s.SyncOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		var p wire.Payload
		srv := &sink.Server{Opener: opener, SecretSurfaces: []sink.SecretSurface{sd}, AfterApply: func(payload wire.Payload) { p = payload }}
		if err = srv.Serve(context.Background(), &frames); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cycle(s)
	secretPath := filepath.Join(sd.Dir, "API")
	raw, err := os.ReadFile(secretPath)
	if err != nil || string(raw) != "unique-op-fixture-value" {
		t.Fatal("initial export failed", err)
	}
	f.list = "[]"
	*now = now.Add(301 * time.Second)
	if p := cycle(s); !p.Secrets.IsEmpty() {
		t.Fatal("empty selection emitted deletes")
	}
	if _, err = os.Stat(secretPath); err != nil {
		t.Fatal("empty selection revoked value", err)
	}
	raw, err = os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte("unique-op-fixture-value")) {
		t.Fatal("state contains value bytes", err)
	}
	restarted := &source.Syncer{StatePath: path}
	if p := cycle(restarted); len(p.Secrets.Deletes) != 1 || p.Secrets.Deletes[0] != "API" {
		t.Fatal("restart omitted delete", p.Secrets)
	}
	if _, err = os.Stat(secretPath); !os.IsNotExist(err) {
		t.Fatal("last secret retained after source removal", err)
	}
	st, err := state.Load(path)
	if err != nil || len(st.ExportedSecrets) != 0 {
		t.Fatal("state names not cleared", err)
	}
}
