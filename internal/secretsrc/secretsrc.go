package secretsrc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// DirReader reads each regular file in Dir as one secret (name=file, value=contents).
type DirReader struct {
	Dir string
}

func (r *DirReader) ReadSecrets(ctx context.Context) ([]secret.Secret, error) {
	entries, err := os.ReadDir(r.Dir)
	if err != nil {
		return nil, fmt.Errorf("secrets dir %s: %w", r.Dir, err)
	}
	var out []secret.Secret
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(r.Dir, name)) // #nosec G304 -- name came from ReadDir under the configured directory and symlinks are skipped.
		if err != nil {
			return nil, err
		}
		out = append(out, secret.Secret{Name: name, Value: string(data)})
	}
	return out, nil
}
