package secretsrc

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/solomonneas/agentpantry/internal/secret"
)

// DirReader reads each regular file in Dir as one secret (name=file, value=contents).
type DirReader struct {
	Dir string
}

func (r *DirReader) ReadSecrets(ctx context.Context) ([]secret.Secret, error) {
	entries, err := os.ReadDir(r.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []secret.Secret
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(r.Dir, name))
		if err != nil {
			return nil, err
		}
		out = append(out, secret.Secret{Name: name, Value: string(data)})
	}
	return out, nil
}
