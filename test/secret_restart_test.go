package test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/onepassword"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/secretsrc"
	"github.com/escoffier-labs/agentpantry/internal/sink"
	"github.com/escoffier-labs/agentpantry/internal/source"
	"github.com/escoffier-labs/agentpantry/internal/state"
	"github.com/escoffier-labs/agentpantry/internal/surface"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

// scriptedSelection models the already-tested 1Password empty-selection error
// at the SecretReader boundary. No account or subprocess is accessed here.
type scriptedSelection struct {
	ss  []secret.Secret
	err error
}

func (*scriptedSelection) Kind() string                                           { return "onepassword" }
func (r *scriptedSelection) ReadSecrets(context.Context) ([]secret.Secret, error) { return r.ss, r.err }

func restartSource(c config.Config, path string, selection source.SecretReader) *source.Syncer {
	s := &source.Syncer{StatePath: path, SecretPolicy: c.SecretNames}
	if c.SecretsDir != "" {
		s.Secrets = append(s.Secrets, &secretsrc.DirReader{Dir: c.SecretsDir})
	}
	if c.OnePassword != nil {
		s.Secrets = append(s.Secrets, selection)
	}
	return s
}

// deliverSecretCycle uses the production salt handshake, framing, encryption,
// sink server and secret-file surface. Each call has its own random session key.
func deliverSecretCycle(t *testing.T, s *source.Syncer, sd *surface.SecretDir) wire.Payload {
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
	key := bytes.Repeat([]byte{42}, 32)
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
	var payload wire.Payload
	srv := &sink.Server{Opener: opener, SecretSurfaces: []sink.SecretSurface{sd}, AfterApply: func(p wire.Payload) { payload = p }}
	if err = srv.Serve(context.Background(), &frames); err != nil {
		t.Fatal(err)
	}
	return payload
}
func restartFixture(t *testing.T) (string, *surface.SecretDir) {
	t.Helper()
	dir := t.TempDir()
	sd, err := surface.NewSecretDir(filepath.Join(dir, "sink-secrets"))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "state.json"), sd
}
func assertSinkSecret(t *testing.T, sd *surface.SecretDir, name, value string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(sd.Dir, name))
	if err != nil || string(raw) != value {
		t.Fatalf("sink secret mismatch: %v", err)
	}
}
func assertSinkDeleted(t *testing.T, sd *surface.SecretDir, name string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(sd.Dir, name)); !os.IsNotExist(err) {
		t.Fatalf("sink secret not deleted: %v", err)
	}
}
func assertNamesOnly(t *testing.T, path string, names []string, values ...string) {
	t.Helper()
	st, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.ExportedSecrets, names) {
		t.Fatalf("exported names: %v", st.ExportedSecrets)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		if bytes.Contains(raw, []byte(v)) {
			t.Fatal("secret value persisted")
		}
	}
}
func TestRestartRevokesRemovedOnePasswordSource(t *testing.T) {
	path, sd := restartFixture(t)
	selection := &scriptedSelection{ss: []secret.Secret{{Name: "API", Value: "fixture-sensitive-value"}}}
	c := config.Config{OnePassword: &onepassword.Config{Vault: "fixture", Tag: "agentpantry"}}
	s := restartSource(c, path, selection)
	deliverSecretCycle(t, s, sd)
	assertSinkSecret(t, sd, "API", "fixture-sensitive-value")
	selection.ss = nil
	selection.err = errors.New("onepassword: selection came back empty")
	if p := deliverSecretCycle(t, s, sd); !p.Secrets.IsEmpty() {
		t.Fatal("empty-selection error emitted a secret diff")
	}
	assertSinkSecret(t, sd, "API", "fixture-sensitive-value")
	assertNamesOnly(t, path, []string{"API"}, "fixture-sensitive-value")
	c.OnePassword = nil
	s = restartSource(c, path, nil)
	p := deliverSecretCycle(t, s, sd)
	if !reflect.DeepEqual(p.Secrets.Deletes, []string{"API"}) {
		t.Fatal("no explicit removal delete", p.Secrets.Deletes)
	}
	assertSinkDeleted(t, sd, "API")
	assertNamesOnly(t, path, []string{}, "fixture-sensitive-value")
}
func TestRestartRevokesRemovedSecretsDir(t *testing.T) {
	path, sd := restartFixture(t)
	dir := filepath.Join(t.TempDir(), "source-secrets")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "API"), []byte("directory-sensitive-value"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{SecretsDir: dir}
	deliverSecretCycle(t, restartSource(c, path, nil), sd)
	assertSinkSecret(t, sd, "API", "directory-sensitive-value")
	c.SecretsDir = ""
	p := deliverSecretCycle(t, restartSource(c, path, nil), sd)
	if len(p.Secrets.Deletes) != 1 {
		t.Fatal("source removal omitted delete")
	}
	assertSinkDeleted(t, sd, "API")
}
func TestRestartResendsUnchangedSecretsIncludingEmptyValue(t *testing.T) {
	path, sd := restartFixture(t)
	r := &scriptedSelection{ss: []secret.Secret{{Name: "API", Value: "unchanged-sensitive-value"}, {Name: "EMPTY", Value: ""}}}
	c := config.Config{OnePassword: &onepassword.Config{Vault: "fixture"}}
	deliverSecretCycle(t, restartSource(c, path, r), sd)
	p := deliverSecretCycle(t, restartSource(c, path, r), sd)
	if len(p.Secrets.Upserts) != 2 || len(p.Secrets.Deletes) != 0 {
		t.Fatal("restart did not fully resend")
	}
	assertSinkSecret(t, sd, "API", "unchanged-sensitive-value")
	assertSinkSecret(t, sd, "EMPTY", "")
	assertNamesOnly(t, path, []string{"API", "EMPTY"}, "unchanged-sensitive-value")
}
func TestCorruptStateNoDeletesAndRewritten(t *testing.T) {
	path, sd := restartFixture(t)
	r := &scriptedSelection{ss: []secret.Secret{{Name: "API", Value: "corrupt-state-sensitive-value"}}}
	c := config.Config{OnePassword: &onepassword.Config{}}
	deliverSecretCycle(t, restartSource(c, path, r), sd)
	if err := os.WriteFile(path, []byte(`{"exported_secrets":["API"],broken}`), 0600); err != nil {
		t.Fatal(err)
	}
	c.OnePassword = nil
	message := captureRestartWarning(t, func() {
		p := deliverSecretCycle(t, restartSource(c, path, nil), sd)
		if len(p.Secrets.Deletes) != 0 {
			t.Fatal("corrupt baseline emitted deletes")
		}
	})
	if !strings.Contains(message, "could not be loaded; no secret deletion baseline") {
		t.Fatal("missing state warning")
	}
	assertSinkSecret(t, sd, "API", "corrupt-state-sensitive-value")
	assertNamesOnly(t, path, []string{}, "corrupt-state-sensitive-value")
}
func TestRestartUnavailableOrCollisionNeverDeletes(t *testing.T) {
	for _, failure := range []string{"reader", "collision"} {
		t.Run(failure, func(t *testing.T) {
			path, sd := restartFixture(t)
			r := &scriptedSelection{ss: []secret.Secret{{Name: "API", Value: "retained-sensitive-value"}}}
			c := config.Config{OnePassword: &onepassword.Config{}}
			deliverSecretCycle(t, restartSource(c, path, r), sd)
			r.ss = []secret.Secret{{Name: "OTHER", Value: "other"}}
			s := restartSource(c, path, r)
			if failure == "reader" {
				r.err = errors.New("unavailable")
			} else {
				s.Secrets = append(s.Secrets, &scriptedSelection{ss: []secret.Secret{{Name: "OTHER", Value: "collision"}}})
			}
			if p := deliverSecretCycle(t, s, sd); !p.Secrets.IsEmpty() {
				t.Fatal("unavailable path emitted secret diff")
			}
			assertSinkSecret(t, sd, "API", "retained-sensitive-value")
			assertNamesOnly(t, path, []string{"API"}, "retained-sensitive-value")
		})
	}
}
func captureRestartWarning(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	saved := os.Stderr
	os.Stderr = writer
	func() { defer func() { os.Stderr = saved; _ = writer.Close() }(); fn() }()
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
