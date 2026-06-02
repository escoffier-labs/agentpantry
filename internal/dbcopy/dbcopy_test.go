package dbcopy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestToTempCopiesAnd0600(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := ToTemp(src)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "hello" {
		t.Fatalf("copy mismatch: %q / %v", b, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("temp copy must be 0600, got %v", info.Mode().Perm())
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("cleanup must remove the temp file")
	}
}

func TestToTempMissingSourceErrors(t *testing.T) {
	if _, _, err := ToTemp(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing source must error")
	}
}
