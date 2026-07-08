//go:build !windows

package keepass

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLoadCredFileRejectsOpenPerms(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.key")
	if err := os.WriteFile(p, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredFile(p); err == nil || !strings.Contains(err.Error(), "too open") {
		t.Fatalf("0644 must be rejected, got %v", err)
	}
}

func TestLoadCredFileRejectsFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	if _, err := loadCredFile(p); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("FIFO must be rejected without blocking, got %v", err)
	}
}
