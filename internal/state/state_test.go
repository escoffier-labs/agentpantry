package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSaveLoadRoundTripAndPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	in := State{ExportedSecrets: []string{}, LastSyncUnix: 1700000000, LastSentUnix: 1700000000, Cookies: 3, Secrets: 1}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("state file must be 0600, got %v", info.Mode().Perm())
		}
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
}

func TestLoadMissingIsZeroValue(t *testing.T) {
	out, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing state must not error, got %v", err)
	}
	if !reflect.DeepEqual(out, State{}) {
		t.Fatalf("missing state must be zero value, got %+v", out)
	}
}

func TestRealClockNonZero(t *testing.T) {
	if (RealClock{}).Now().IsZero() {
		t.Fatal("real clock must return a real time")
	}
}

func TestSaveRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("orig"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := Save(path, State{LastSyncUnix: 1}); err == nil {
		t.Fatal("must refuse to write state through a symlink")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "orig" {
		t.Fatalf("symlink target was overwritten: %q", body)
	}
}

func TestExportedNamesSortedAndValuesAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, State{ExportedSecrets: []string{"Z_TOKEN", "A_TOKEN"}}); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.ExportedSecrets, []string{"A_TOKEN", "Z_TOKEN"}) {
		t.Fatal(got.ExportedSecrets)
	}
}
func TestRejectCorruptState(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", `{"exported_secrets":["API"], broken}`, `{"exported_secrets":[1]}`} {
		got, err := decode([]byte(raw))
		if err == nil || !reflect.DeepEqual(got, State{}) {
			t.Fatalf("corrupt state accepted: %v", err)
		}
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"binding":{"config_path":"/fixture/a.toml","hostname":"fixture","identity":"fixture","peer":"sink:8787","key_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"tombstones":[{"name":"API","expires_unix":1794873600}],"exported_secrets":["CURRENT"]}`))
	f.Add([]byte(`{"exported_secrets":["API"]}`))
	f.Add([]byte(`{"last_sync_unix":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = decode(raw) })
}

func TestStateReadByteCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	base := []byte(`{"exported_secrets":[]}`)
	raw := append(base, bytes.Repeat([]byte{' '}, MaxStateBytes-len(base))...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal("exact byte limit rejected", err)
	}
	raw = append(raw, ' ')
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(path); err == nil || !strings.Contains(err.Error(), "4 MiB") || len(got.ExportedSecrets) != 0 {
		t.Fatal("oversized state accepted", err)
	}
	if _, err := decode(raw); err == nil {
		t.Fatal("decoder bypasses byte cap")
	}
}
func TestTombstoneCapKeepsNewest(t *testing.T) {
	tombs := make([]Tombstone, MaxTombstones+10)
	for i := range tombs {
		tombs[i] = Tombstone{Name: fmt.Sprintf("T_%04d", i), ExpiresUnix: int64(i + 1)}
	}
	capped, dropped := CapTombstones(tombs)
	if dropped != 10 || len(capped) != MaxTombstones || capped[0].Name != "T_0010" || capped[len(capped)-1].Name != "T_1009" {
		t.Fatal("wrong tombstone eviction")
	}
	// A state produced by an older version is also bounded on load.
	raw, err := json.Marshal(State{Tombstones: tombs})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || len(loaded.Tombstones) != MaxTombstones || loaded.Tombstones[0].Name != "T_0010" {
		t.Fatal("load did not cap tombstones", err)
	}
}
