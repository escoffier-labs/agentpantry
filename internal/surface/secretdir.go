package surface

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/privfile"
	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// SecretDir writes secrets as 0600 files under Dir.
type SecretDir struct {
	Dir string
}

func NewSecretDir(dir string) (*SecretDir, error) {
	if err := ensurePrivateDir(dir); err != nil {
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
	// Unsafe names and planted symlinks are skipped (one hostile entry must not
	// stall the whole sync), but real I/O failures are reported so the sink
	// never claims success while secrets are stale or missing.
	skipped := 0
	var errs []error
	for _, sec := range d.Upserts {
		if !safeName(sec.Name) {
			skipped++
			continue
		}
		if err := privfile.Write(filepath.Join(s.Dir, sec.Name), []byte(sec.Value)); err != nil {
			if errors.Is(err, privfile.ErrSymlink) {
				skipped++
				continue
			}
			errs = append(errs, err)
		}
	}
	for _, name := range d.Deletes {
		if !safeName(name) {
			skipped++
			continue
		}
		if err := os.Remove(filepath.Join(s.Dir, name)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "agentpantry: skipped %d secret(s) with unsafe names or symlinked targets\n", skipped)
	}
	return errors.Join(errs...)
}
