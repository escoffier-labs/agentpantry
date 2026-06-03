package surface

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// HermesBundle writes an Agent Pantry auth bundle under a Hermes-readable root.
// It intentionally owns only its own subtree:
//
//	root/
//	  agentpantry.json
//	  cookies.txt
//	  secrets/<name>
type HermesBundle struct {
	root   string
	cookie *Netscape
	secret *SecretDir
}

type hermesManifest struct {
	Schema     string `json:"schema"`
	Cookies    string `json:"cookies"`
	SecretsDir string `json:"secrets_dir"`
}

func NewHermesBundle(root string) (*HermesBundle, error) {
	if root == "" {
		return nil, fmt.Errorf("hermes adapter requires a path")
	}
	if err := ensurePrivateDir(root); err != nil {
		return nil, err
	}
	secretsDir := filepath.Join(root, "secrets")
	if err := ensurePrivateDir(secretsDir); err != nil {
		return nil, err
	}
	n, err := NewNetscape(filepath.Join(root, "cookies.txt"))
	if err != nil {
		return nil, err
	}
	s, err := NewSecretDir(secretsDir)
	if err != nil {
		return nil, err
	}
	h := &HermesBundle{root: root, cookie: n, secret: s}
	if err := h.writeManifest(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *HermesBundle) Apply(d cookie.Diff) error {
	return h.cookie.Apply(d)
}

func (h *HermesBundle) ApplySecrets(d secret.Diff) error {
	return h.secret.ApplySecrets(d)
}

func (h *HermesBundle) writeManifest() error {
	m := hermesManifest{
		Schema:     "agentpantry.hermes-bundle.v1",
		Cookies:    "cookies.txt",
		SecretsDir: "secrets",
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return writePrivateFile(filepath.Join(h.root, "agentpantry.json"), out)
}
