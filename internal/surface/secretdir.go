package surface

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// SecretDir writes secrets as 0600 files under Dir.
type SecretDir struct {
	Dir string
}

func NewSecretDir(dir string) (*SecretDir, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &SecretDir{Dir: dir}, nil
}

// safeName accepts only a single, non-dotdot path element.
func safeName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if filepath.IsAbs(name) {
		return false
	}
	if strings.ContainsRune(name, '/') || strings.ContainsRune(name, os.PathSeparator) {
		return false
	}
	if strings.ContainsRune(name, 0) || strings.ContainsRune(name, '\\') {
		return false
	}
	return name == filepath.Base(name)
}

func (s *SecretDir) ApplySecrets(d secret.Diff) error {
	skipped := 0
	for _, sec := range d.Upserts {
		if !safeName(sec.Name) {
			skipped++
			continue
		}
		if err := os.WriteFile(filepath.Join(s.Dir, sec.Name), []byte(sec.Value), 0o600); err != nil {
			skipped++
			continue
		}
	}
	for _, name := range d.Deletes {
		if !safeName(name) {
			skipped++
			continue
		}
		if err := os.Remove(filepath.Join(s.Dir, name)); err != nil && !os.IsNotExist(err) {
			skipped++
			continue
		}
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "agentpantry: skipped %d secret(s) with unsafe names\n", skipped)
	}
	return nil
}
