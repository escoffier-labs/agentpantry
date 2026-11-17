package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBindingFingerprintDomainSeparation(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 32)
	b, err := NewBinding("fixture.toml", "node", "sink:8787", key)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(append([]byte("agentpantry/source-state/psk-fingerprint/v1\x00"), key...))
	plain := sha256.Sum256(key)
	if !b.Valid() || b.KeyFingerprint != hex.EncodeToString(expected[:]) || b.KeyFingerprint == hex.EncodeToString(plain[:]) {
		t.Fatal("incorrect fingerprint binding")
	}
	if !filepath.IsAbs(b.ConfigPath) || b.Hostname == "" {
		t.Fatal("missing path or host binding")
	}
}
func TestLegacyStateDisplayOnly(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "a.toml")
	old := State{LastSyncUnix: 123, ExportedSecrets: []string{"API_A"}, Tombstones: []Tombstone{{Name: "OLD", ExpiresUnix: 999}}}
	if err := Save(filepath.Join(dir, "state.json"), old); err != nil {
		t.Fatal(err)
	}
	display, err := LoadForDisplay(cfg)
	if err != nil || display.LastSyncUnix != 123 || len(display.ExportedSecrets) != 0 || len(display.Tombstones) != 0 || display.Binding != nil {
		t.Fatal("legacy names exposed as baseline", err)
	}
	baseline, err := Load(PathForConfig(cfg))
	if err != nil || len(baseline.ExportedSecrets) != 0 {
		t.Fatal("legacy names used for new config", err)
	}
	if PathForConfig(cfg) == PathForConfig(filepath.Join(dir, "b.toml")) {
		t.Fatal("configs share a state file")
	}
	if err := Save(PathForConfig(cfg), State{LastSyncUnix: 456}); err != nil {
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
	binding, err := NewBinding("fixture.toml", "node", "", bytes.Repeat([]byte{42}, 32))
	if err != nil || !binding.Valid() || binding.Peer != "" {
		t.Fatal("configured empty stdio peer not preserved", err)
	}
}
