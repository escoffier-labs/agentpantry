package keyfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateThenLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	if err := Generate(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file must be 0600, got %v", info.Mode().Perm())
	}
	key, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key must be 32 bytes, got %d", len(key))
	}
}

func TestGenerateTightensExistingPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Generate(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file must be tightened to 0600, got %v", info.Mode().Perm())
	}
}

func TestLoadRejectsWrongLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	os.WriteFile(path, []byte("short"), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("must reject non-32-byte key")
	}
}

func TestLoadRejectsTooOpenPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows does not expose Unix file mode permissions")
	}
	path := filepath.Join(t.TempDir(), "wide.key")
	if err := os.WriteFile(path, []byte("0000000000000000000000000000000000000000000000000000000000000000"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("must reject group/world-readable key")
	}
}
