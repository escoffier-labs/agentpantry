package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/keyfile"
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

func restartSource(t *testing.T, c config.Config, path string, selection source.SecretReader) *source.Syncer {
	if _, err := os.Stat(path + ".toml"); os.IsNotExist(err) {
		if err = os.WriteFile(path+".toml", []byte(`role="source"`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binding, err := state.NewBinding(path+".toml", "fixture", "sink:8787")
	if err != nil {
		t.Fatal(err)
	}
	s := &source.Syncer{StatePath: path, Binding: binding, SecretPolicy: c.SecretNames}
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
	return deliverSecretCycleWithKey(t, s, sd, bytes.Repeat([]byte{42}, 32))
}
func deliverSecretCycleWithKey(t *testing.T, s *source.Syncer, sd *surface.SecretDir, key []byte) wire.Payload {
	t.Helper()
	defer s.Close()
	var handshake, frames bytes.Buffer
	salt, err := transport.SendSalt(&handshake)
	if err != nil {
		t.Fatal(err)
	}
	received, err := transport.RecvSalt(&handshake)
	if err != nil {
		t.Fatal(err)
	}
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
	if sd == nil {
		return wire.Payload{}
	} // Simulate a sink crash after the successful stream write.
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
	s := restartSource(t, c, path, selection)
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
	s = restartSource(t, c, path, nil)
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
	deliverSecretCycle(t, restartSource(t, c, path, nil), sd)
	assertSinkSecret(t, sd, "API", "directory-sensitive-value")
	c.SecretsDir = ""
	p := deliverSecretCycle(t, restartSource(t, c, path, nil), sd)
	if len(p.Secrets.Deletes) != 1 {
		t.Fatal("source removal omitted delete")
	}
	assertSinkDeleted(t, sd, "API")
}
func TestRestartResendsUnchangedSecretsIncludingEmptyValue(t *testing.T) {
	path, sd := restartFixture(t)
	r := &scriptedSelection{ss: []secret.Secret{{Name: "API", Value: "unchanged-sensitive-value"}, {Name: "EMPTY", Value: ""}}}
	c := config.Config{OnePassword: &onepassword.Config{Vault: "fixture"}}
	deliverSecretCycle(t, restartSource(t, c, path, r), sd)
	p := deliverSecretCycle(t, restartSource(t, c, path, r), sd)
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
	deliverSecretCycle(t, restartSource(t, c, path, r), sd)
	if err := os.WriteFile(path, []byte(`{"exported_secrets":["API"],broken}`), 0600); err != nil {
		t.Fatal(err)
	}
	c.OnePassword = nil
	message := captureRestartWarning(t, func() {
		p := deliverSecretCycle(t, restartSource(t, c, path, nil), sd)
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
			deliverSecretCycle(t, restartSource(t, c, path, r), sd)
			r.ss = []secret.Secret{{Name: "OTHER", Value: "other"}}
			s := restartSource(t, c, path, r)
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

func TestConfigsInOneDirectoryNeverDeleteEachOther(t *testing.T) {
	dir := t.TempDir()
	sd, err := surface.NewSecretDir(filepath.Join(dir, "sink"))
	if err != nil {
		t.Fatal(err)
	}
	makeSource := func(configName, name string) *source.Syncer {
		cfg := filepath.Join(dir, configName)
		if err := os.WriteFile(cfg, []byte(`role="source"`), 0600); err != nil {
			t.Fatal(err)
		}
		binding, err := state.NewBinding(cfg, "fixture", "sink:8787")
		if err != nil {
			t.Fatal(err)
		}
		return &source.Syncer{StatePath: binding.ConfigPath + ".state.json", Binding: binding, Secrets: []source.SecretReader{&scriptedSelection{ss: []secret.Secret{{Name: name, Value: "value-for-" + name}}}}}
	}
	a := makeSource("a.toml", "API_A")
	b := makeSource("b.toml", "API_B")
	deliverSecretCycle(t, a, sd)
	if p := deliverSecretCycle(t, b, sd); len(p.Secrets.Deletes) != 0 {
		t.Fatal("b.toml deleted a.toml exports")
	}
	assertSinkSecret(t, sd, "API_A", "value-for-API_A")
	assertSinkSecret(t, sd, "API_B", "value-for-API_B")
	if p := deliverSecretCycle(t, makeSource("a.toml", "API_A"), sd); len(p.Secrets.Deletes) != 0 {
		t.Fatal("a.toml deleted b.toml exports")
	}
	assertNamesOnly(t, a.StatePath, []string{"API_A"}, "value-for-API_A")
	assertNamesOnly(t, b.StatePath, []string{"API_B"}, "value-for-API_B")
}
func TestRestartReplaysDeleteAfterSinkCrash(t *testing.T) {
	path, sd := restartFixture(t)
	r := &scriptedSelection{ss: []secret.Secret{{Name: "API", Value: "crash-fixture-value"}}}
	c := config.Config{OnePassword: &onepassword.Config{}}
	deliverSecretCycle(t, restartSource(t, c, path, r), sd)
	c.OnePassword = nil
	deliverSecretCycle(t, restartSource(t, c, path, nil), nil) // Delete persisted, but never applied at the sink.
	assertSinkSecret(t, sd, "API", "crash-fixture-value")
	p := deliverSecretCycle(t, restartSource(t, c, path, nil), sd)
	if !reflect.DeepEqual(p.Secrets.Deletes, []string{"API"}) {
		t.Fatal("restart failed to replay pending delete")
	}
	assertSinkDeleted(t, sd, "API")
}

func realConfigSource(t *testing.T, path string) *source.Syncer {
	t.Helper()
	binding, err := state.NewBinding(path, "fixture", "sink:8787")
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(binding.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &source.Syncer{Binding: binding, StatePath: binding.ConfigPath + ".state.json"}
	if c.SecretsDir != "" {
		s.Secrets = []source.SecretReader{&secretsrc.DirReader{Dir: c.SecretsDir}}
	}
	return s
}
func writeRealSourceConfig(t *testing.T, cfgDir, name, token string) string {
	t.Helper()
	secrets := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(secrets, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, token), []byte("value-for-"+token), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(cfgDir, name)
	body := fmt.Sprintf(`role = "source"
peer = "sink:8787"
secrets_dir = %q
`, secrets)
	if err := os.WriteFile(cfg, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return cfg
}
func TestSymlinkRetargetNeverDeletesPriorConfig(t *testing.T) {
	dir := t.TempDir()
	sd, err := surface.NewSecretDir(filepath.Join(dir, "sink"))
	if err != nil {
		t.Fatal(err)
	}
	a := writeRealSourceConfig(t, dir, "a.toml", "A_TOKEN")
	b := writeRealSourceConfig(t, dir, "b.toml", "B_TOKEN")
	alias := filepath.Join(dir, "current.toml")
	if err := os.Symlink(a, alias); err != nil {
		t.Fatal(err)
	}
	sourceA := realConfigSource(t, alias)
	deliverSecretCycle(t, sourceA, sd)
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b, alias); err != nil {
		t.Fatal(err)
	}
	sourceB := realConfigSource(t, alias)
	p := deliverSecretCycle(t, sourceB, sd)
	if sourceA.StatePath == sourceB.StatePath || sourceA.Binding.ConfigPath == sourceB.Binding.ConfigPath || len(p.Secrets.Deletes) != 0 {
		t.Fatal("retarget reused A identity or deleted A exports")
	}
	assertSinkSecret(t, sd, "A_TOKEN", "value-for-A_TOKEN")
	assertSinkSecret(t, sd, "B_TOKEN", "value-for-B_TOKEN")
}
func TestConfigRenameOrMoveNeverDeletesPriorExports(t *testing.T) {
	for _, moveDir := range []bool{false, true} {
		t.Run(fmt.Sprint(moveDir), func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "configs")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			sd, err := surface.NewSecretDir(filepath.Join(root, "sink"))
			if err != nil {
				t.Fatal(err)
			}
			a := writeRealSourceConfig(t, dir, "a.toml", "A_TOKEN")
			old := realConfigSource(t, a)
			deliverSecretCycle(t, old, sd)
			next := filepath.Join(dir, "renamed.toml")
			if moveDir {
				newDir := filepath.Join(root, "moved")
				if err := os.Rename(dir, newDir); err != nil {
					t.Fatal(err)
				}
				next = filepath.Join(newDir, "a.toml")
			} else {
				if err := os.Rename(a, next); err != nil {
					t.Fatal(err)
				}
			}
			writeRealSourceConfig(t, filepath.Dir(next), filepath.Base(next), "B_TOKEN")
			fresh := realConfigSource(t, next)
			p := deliverSecretCycle(t, fresh, sd)
			if fresh.Binding.ConfigPath == old.Binding.ConfigPath || len(p.Secrets.Deletes) != 0 {
				t.Fatal("rename/move reused deletion authority")
			}
			assertSinkSecret(t, sd, "A_TOKEN", "value-for-A_TOKEN")
			assertSinkSecret(t, sd, "B_TOKEN", "value-for-B_TOKEN")
		})
	}
}
func TestRotationPreservesPendingRevocations(t *testing.T) {
	for _, pendingTomb := range []bool{false, true} {
		t.Run(fmt.Sprint(pendingTomb), func(t *testing.T) {
			path, sd := restartFixture(t)
			cfg := path + ".toml"
			if err := os.WriteFile(cfg, []byte(`role="source"`), 0600); err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(t.TempDir(), "psk.key")
			if err := keyfile.Generate(keyPath); err != nil {
				t.Fatal(err)
			}
			oldKey, err := keyfile.Load(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := state.NewBinding(cfg, "fixture", "sink:8787")
			if err != nil {
				t.Fatal(err)
			}
			initial := &source.Syncer{StatePath: path, Binding: binding, Secrets: []source.SecretReader{&scriptedSelection{ss: []secret.Secret{{Name: "API", Value: "rotation-fixture-value"}}}}}
			deliverSecretCycleWithKey(t, initial, sd, oldKey)
			if pendingTomb {
				deliverSecretCycleWithKey(t, &source.Syncer{StatePath: path, Binding: binding}, nil, oldKey)
			}
			// Model upgrading existing state from ba925b7 while rotating its key.
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var legacy map[string]any
			if err = json.Unmarshal(raw, &legacy); err != nil {
				t.Fatal(err)
			}
			legacy["binding"].(map[string]any)["key_fingerprint"] = "obsolete-fingerprint"
			raw, err = json.Marshal(legacy)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := keyfile.Rotate(keyPath); err != nil {
				t.Fatal(err)
			}
			newKey, err := keyfile.Load(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(oldKey, newKey) {
				t.Fatal("key did not rotate")
			}
			nextBinding, err := state.NewBinding(cfg, "fixture", "sink:8787")
			if err != nil {
				t.Fatal(err)
			}
			p := deliverSecretCycleWithKey(t, &source.Syncer{StatePath: path, Binding: nextBinding}, sd, newKey)
			if !reflect.DeepEqual(p.Secrets.Deletes, []string{"API"}) {
				t.Fatal("rotation dropped pending revocation")
			}
			assertSinkDeleted(t, sd, "API")
			raw, err = os.ReadFile(path)
			if err != nil || bytes.Contains(raw, []byte("key_fingerprint")) || bytes.Contains(raw, newKey) || bytes.Contains(raw, oldKey) {
				t.Fatal("state retains key-derived material", err)
			}
		})
	}
}
