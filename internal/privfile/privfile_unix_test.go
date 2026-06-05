//go:build !windows

package privfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteReplacesViaRenameNotTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := Write(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	st1, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("two")); err != nil {
		t.Fatal(err)
	}
	st2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ino1 := st1.Sys().(*syscall.Stat_t).Ino
	ino2 := st2.Sys().(*syscall.Stat_t).Ino
	if ino1 == ino2 {
		t.Fatal("expected a new inode (temp file + rename); same inode means in-place truncate")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "two" {
		t.Fatalf("got %q want %q", body, "two")
	}
}

func TestWriteReplacesExistingLoosePermsWithoutWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file must be 0600 after replace, got %v", info.Mode().Perm())
	}
}
