//go:build !windows

package keyfile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestGenerateReplacesExistingFileAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "psk.key")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	st1, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Generate(path); err != nil {
		t.Fatal(err)
	}
	st2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st1.Sys().(*syscall.Stat_t).Ino == st2.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("expected temp-file + rename (no loose-perm window); same inode means in-place truncate")
	}
}

func TestGenerateWithBackupRefusesSymlinkBeforeBackup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("sensitive"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "psk.key")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := GenerateWithBackup(path, true); err == nil {
		t.Fatal("must refuse a symlinked key path")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak.") {
			t.Fatalf("no backup of the symlink target may be created, found %q", e.Name())
		}
	}
}

func TestLoadRejectsNonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo.key")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Load(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("must reject a non-regular key file")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Load hung opening a FIFO instead of rejecting it")
	}
}
