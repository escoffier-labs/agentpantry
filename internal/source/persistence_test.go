package source

import (
	"bytes"
	"context"
	"errors"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/state"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFailedSendDoesNotCommitExportedNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path, state.State{ExportedSecrets: []string{"OLD"}}); err != nil {
		t.Fatal(err)
	}
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	s := &Syncer{StatePath: path, Secrets: []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "NEW", Value: "never-persist-this-value"}}}}, Sealer: sealer, Out: errWriter{err: errors.New("send failed")}}
	if err := s.SyncOnce(context.Background()); err == nil {
		t.Fatal("send unexpectedly succeeded")
	}
	st, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.ExportedSecrets, []string{"OLD"}) || len(s.prevSecrets.Secrets) != 0 {
		t.Fatal("failed send committed")
	}
}
func TestReconnectReloadsNamesAndResendsCurrentValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	var buf bytes.Buffer
	s := &Syncer{StatePath: path, Secrets: []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "OLD", Value: "value"}}}}, Sealer: sealer, Out: &buf}
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Reset()
	buf.Reset()
	s.Secrets = []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "NEW", Value: ""}}}}
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := decodePayload(t, &buf)
	if len(p.Secrets.Upserts) != 1 || p.Secrets.Upserts[0].Name != "NEW" || !reflect.DeepEqual(p.Secrets.Deletes, []string{"OLD"}) {
		t.Fatal("reconnect baseline lost", p.Secrets)
	}
}
func TestCorruptStateNotRewrittenOnUnavailableRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	bad := []byte(`{"exported_secrets":["OLD"],broken}`)
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	s := &Syncer{StatePath: path, Secrets: []SecretReader{errSecrets{}}}
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, bad) {
		t.Fatal("unavailable read rewrote invalid state")
	}
}

func TestUnreadableStateCannotEmitDeletes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	var buf bytes.Buffer
	s := &Syncer{StatePath: path, Secrets: []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "NEW", Value: "fixture-value"}}}}, Sealer: sealer, Out: &buf}
	stderr := captureStderr(t, func() {
		if err := s.SyncOnce(context.Background()); err == nil {
			t.Fatal("unwritable state path accepted")
		}
	})
	if !strings.Contains(stderr, "could not be loaded; no secret deletion baseline") {
		t.Fatal("no warning")
	}
	p := decodePayload(t, &buf)
	if len(p.Secrets.Deletes) != 0 {
		t.Fatal("unreadable state emitted deletes")
	}
	if len(s.prevSecrets.Secrets) != 0 {
		t.Fatal("failed state write committed snapshot")
	}
}
