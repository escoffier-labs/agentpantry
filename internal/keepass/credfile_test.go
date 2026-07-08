package keepass

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCredFileReadsBytes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.key")
	if err := os.WriteFile(p, []byte{0x00, 0x01, 0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadCredFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != 0xff {
		t.Fatalf("raw bytes lost: %v", got)
	}
}

func TestLoadCredFileRejectsEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty.key")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredFile(p); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty file must be rejected, got %v", err)
	}
}

func TestLoadCredFileRejectsOversize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.key")
	if err := os.WriteFile(p, make([]byte, maxCredFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredFile(p); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversize file must be rejected, got %v", err)
	}
}

func TestLoadCredFileMissing(t *testing.T) {
	if _, err := loadCredFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing file must error")
	}
}
