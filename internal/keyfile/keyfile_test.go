package keyfile

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGenerateThenLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	if err := Generate(path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("key file must be 0600, got %v", info.Mode().Perm())
		}
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
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("key file must be tightened to 0600, got %v", info.Mode().Perm())
		}
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
	if runtime.GOOS != "windows" {
		info, err := os.Stat(backupPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("backup file must be 0600, got %v", info.Mode().Perm())
		}
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

func TestGenerateRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("orig"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "psk.key")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := Generate(path); err == nil {
		t.Fatal("must refuse to write the key through a symlink")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "orig" {
		t.Fatalf("symlink target was overwritten: %q", body)
	}
}

func TestLoadRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.key")
	// 64 valid hex chars, whitespace-padded to 4096 bytes, then trailing junk:
	// a truncating read would silently accept this as a valid key.
	body := strings.Repeat("a1", 32) + strings.Repeat("\n", 4096-64) + "trailing junk"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("must reject an oversized key file instead of silently truncating")
	}
}

func TestRotatePreservesOldKeyAndWritesFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	if err := Generate(path); err != nil {
		t.Fatal(err)
	}
	orig, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	oldPath, err := Rotate(path)
	if err != nil {
		t.Fatal(err)
	}
	if oldPath != OldKeyPath(path) {
		t.Fatalf("rotate must report the old-key path, got %q want %q", oldPath, OldKeyPath(path))
	}
	oldKey, err := Load(oldPath)
	if err != nil {
		t.Fatalf("old key must load: %v", err)
	}
	if hex.EncodeToString(oldKey) != hex.EncodeToString(orig) {
		t.Fatal("old-key file must hold the pre-rotation key")
	}
	newKey, err := Load(path)
	if err != nil {
		t.Fatalf("new key must load: %v", err)
	}
	if hex.EncodeToString(newKey) == hex.EncodeToString(orig) {
		t.Fatal("rotate must write a fresh key")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(oldPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("old-key file must be 0600, got %v", info.Mode().Perm())
		}
	}
}

func TestRotateRefusesWhileRotationInProgress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	if err := Generate(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(path); err == nil {
		t.Fatal("second rotate without finish must fail")
	}
}

func TestRotateRequiresValidCurrentKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	if _, err := Rotate(path); err == nil {
		t.Fatal("rotate without an existing key must fail")
	}
}

func TestFinishRotationRemovesOldKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	if err := Generate(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(path); err != nil {
		t.Fatal(err)
	}
	if err := FinishRotation(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(OldKeyPath(path)); !os.IsNotExist(err) {
		t.Fatal("finish must remove the old-key file")
	}
}

func TestFinishRotationWithoutRotationFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	if err := Generate(path); err != nil {
		t.Fatal(err)
	}
	if err := FinishRotation(path); err == nil {
		t.Fatal("finish without a rotation in progress must fail")
	}
}
