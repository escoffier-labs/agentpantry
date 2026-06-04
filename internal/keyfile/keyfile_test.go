package keyfile

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
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

func TestGenerateWithBackupCopiesExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "psk.key")
	oldKey := hex.EncodeToString([]byte("01234567890123456789012345678901"))
	if err := os.WriteFile(path, []byte(oldKey), 0o600); err != nil {
		t.Fatal(err)
	}
	backupPath, err := GenerateWithBackup(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if backupPath == "" {
		t.Fatal("expected backup path")
	}
	body, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != oldKey {
		t.Fatalf("backup did not preserve previous key: %q", body)
	}
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup file must be 0600, got %v", info.Mode().Perm())
	}
	newBody, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(newBody) == oldKey {
		t.Fatal("key was not rotated")
	}
}

func TestBackupExistingMissingKeyIsNoop(t *testing.T) {
	backupPath, err := backupExisting(filepath.Join(t.TempDir(), "missing.key"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if backupPath != "" {
		t.Fatalf("missing key should not create backup, got %q", backupPath)
	}
}

func TestCreateBackupAvoidsSameSecondCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	now := time.Date(2026, 6, 3, 23, 0, 0, 0, time.UTC)
	first := path + ".bak.20260603T230000Z"
	if err := os.WriteFile(first, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupPath, out, err := createBackup(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if backupPath != first+".1" {
		t.Fatalf("expected numbered backup path, got %q", backupPath)
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
