package keyfile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const keyLen = 32

// Generate writes a new random 32-byte key as hex to path with 0600.
func Generate(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// Load reads and decodes the hex key, validating its length.
func Load(path string) ([]byte, error) {
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("key perms %v are too open, want 0600", info.Mode().Perm())
		}
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- key path is intentionally operator-selected and permissions were checked above.
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("key not valid hex: %w", err)
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("key must be %d bytes, got %d", keyLen, len(key))
	}
	return key, nil
}
