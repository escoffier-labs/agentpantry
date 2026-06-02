package surface

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/escoffier-labs/agentpantry/internal/secret"
	"gopkg.in/yaml.v3"
)

// GHHosts writes the GitHub token into gh's hosts.yml, merging with existing hosts.
type GHHosts struct {
	path       string
	secretName string
	host       string
	user       string
}

func NewGHHosts(path, secretName, host, user string) (*GHHosts, error) {
	if secretName == "" {
		return nil, fmt.Errorf("gh adapter requires a secret name")
	}
	if host == "" {
		host = "github.com"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &GHHosts{path: path, secretName: secretName, host: host, user: user}, nil
}

func (g *GHHosts) ApplySecrets(d secret.Diff) error {
	var token string
	found := false
	for _, s := range d.Upserts {
		if s.Name == g.secretName {
			token = s.Value
			found = true
		}
	}
	if !found {
		return nil // upsert-only; ignore deletes and unrelated secrets
	}

	doc := map[string]map[string]any{}
	if b, err := os.ReadFile(g.path); err == nil {
		if e := yaml.Unmarshal(b, &doc); e != nil {
			return fmt.Errorf("parse existing %s: %w", g.path, e)
		}
	}
	if doc == nil {
		doc = map[string]map[string]any{}
	}
	h := doc[g.host]
	if h == nil {
		h = map[string]any{}
	}
	h["oauth_token"] = token
	if g.user != "" {
		h["user"] = g.user
	}
	doc[g.host] = h

	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(g.path, out, 0o600)
}
