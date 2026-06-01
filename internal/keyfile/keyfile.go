package keyfile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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
	return os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600)
}

// Load reads and decodes the hex key, validating its length.
func Load(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
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
