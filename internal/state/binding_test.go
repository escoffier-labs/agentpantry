package state

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBindingContainsNoKeyDerivedMetadata(t *testing.T) {
	cfg := fixtureConfig(t)
	b, err := NewBinding(cfg, "node", "sink:8787")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 || fields["key_fingerprint"] != nil || !b.Valid() {
		t.Fatal("key-derived metadata in binding")
	}
}
func fixtureConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.toml")
	if err := os.WriteFile(path, []byte(`role="source"`), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func mustStatePath(t *testing.T, path string) string {
	t.Helper()
	out, err := PathForConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestLegacyStateDisplayOnly(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "a.toml")
	for _, name := range []string{"a.toml", "b.toml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`role="source"`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	old := State{LastSyncUnix: 123, ExportedSecrets: []string{"API_A"}, Tombstones: []Tombstone{{Name: "OLD", ExpiresUnix: 999}}}
	if err := Save(filepath.Join(dir, "state.json"), old); err != nil {
		t.Fatal(err)
	}
	display, err := LoadForDisplay(cfg)
	if err != nil || display.LastSyncUnix != 123 || len(display.ExportedSecrets) != 0 || len(display.Tombstones) != 0 || display.Binding != nil {
		t.Fatal("legacy names exposed as baseline", err)
	}
	baseline, err := Load(mustStatePath(t, cfg))
	if err != nil || len(baseline.ExportedSecrets) != 0 {
		t.Fatal("legacy names used for new config", err)
	}
	if mustStatePath(t, cfg) == mustStatePath(t, filepath.Join(dir, "b.toml")) {
		t.Fatal("configs share a state file")
	}
	if err := Save(mustStatePath(t, cfg), State{LastSyncUnix: 456}); err != nil {
		t.Fatal(err)
	}
	display, err = LoadForDisplay(cfg)
	if err != nil || display.LastSyncUnix != 456 {
		t.Fatal("new display path not preferred", err)
	}
}
func TestLockExcludesSecondProcess(t *testing.T) {
	const env = "AGENTPANTRY_TEST_STATE_LOCK"
	if path := os.Getenv(env); path != "" {
		lock, err := Acquire(path)
		if err != nil {
			return
		}
		_ = lock.Close()
		t.Fatal("second process acquired writer lock")
		return
	}
	path := filepath.Join(t.TempDir(), "fixture.toml.state.json")
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	second, err := Acquire(path)
	if err == nil {
		second.Close()
		t.Fatal("second writer accepted")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockExcludesSecondProcess$")
	cmd.Env = append(os.Environ(), env+"="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lock exclusion failed: %v: %s", err, out)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Acquire(path)
	if err != nil {
		t.Fatal("lock not released", err)
	}
	_ = next.Close()
}

func TestBindingAllowsConfiguredEmptyStdioPeer(t *testing.T) {
	binding, err := NewBinding(fixtureConfig(t), "node", "")
	if err != nil || !binding.Valid() || binding.Peer != "" {
		t.Fatal("configured empty stdio peer not preserved", err)
	}
}
