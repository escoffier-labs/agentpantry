package keyfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const keyLen = 32

// Generate writes a new random 32-byte key as hex to path with 0600.
func Generate(path string) error {
	_, err := GenerateWithBackup(path, false)
	return err
}

// GenerateWithBackup writes a new random 32-byte key as hex to path with 0600.
// When backup is true and path already exists, it first copies the existing key
// beside the original as path.bak.<UTC timestamp>, also mode 0600.
func GenerateWithBackup(path string, backup bool) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	backupPath := ""
	if backup {
		var err error
		backupPath, err = backupExisting(path, time.Now().UTC())
		if err != nil {
			return "", err
		}
	}
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return "", err
	}
	return backupPath, os.Chmod(path, 0o600)
}

func backupExisting(path string, now time.Time) (string, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("cannot back up key path %s: is a directory", path)
	}
	in, err := os.Open(path) // #nosec G304 -- key path is intentionally operator-selected.
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	backupPath, out, err := createBackup(path, now)
	if err != nil {
		return "", err
	}
	copied := false
	defer func() {
		_ = out.Close()
		if !copied {
			_ = os.Remove(backupPath)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	if err := out.Chmod(0o600); err != nil {
		return "", err
	}
	copied = true
	return backupPath, nil
}

func createBackup(path string, now time.Time) (string, *os.File, error) {
	base := fmt.Sprintf("%s.bak.%s", path, now.Format("20060102T150405Z"))
	for i := 0; i < 100; i++ {
		backupPath := base
		if i > 0 {
			backupPath = fmt.Sprintf("%s.%d", base, i)
		}
		out, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- backup path is derived from the operator-selected key path.
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return backupPath, out, err
	}
	return "", nil, fmt.Errorf("could not create unique backup path for %s", path)
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
