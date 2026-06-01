package keyfile

import (
	"os"
	"path/filepath"
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

func TestLoadRejectsWrongLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	os.WriteFile(path, []byte("short"), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("must reject non-32-byte key")
	}
}
