package config

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/escoffier-labs/agentpantry/internal/policy"
)

// BrowserRef names a browser profile and its cookie store path.
type BrowserRef struct {
	Kind       string `toml:"kind"` // "chromium"
	Profile    string `toml:"profile"`
	CookiePath string `toml:"cookie_path"`
}

// Config is the on-disk configuration for either role.
type Config struct {
	Role       string        `toml:"role"` // "source" | "sink"
	Peer       string        `toml:"peer"` // dial target (source) or bind addr (sink)
	KeyPath    string        `toml:"key_path"`
	Surfaces   []string      `toml:"surfaces"`
	Browsers   []BrowserRef  `toml:"browsers"`
	SecretsDir string        `toml:"secrets_dir"` // source: read from; sink: write to
	Domains    policy.Domain `toml:"domains"`
}

// Dir returns the config directory, honoring XDG_CONFIG_HOME.
func Dir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "agentpantry")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "agentpantry")
}

// Default returns a config with safe defaults for the given role.
func Default(role string) Config {
	c := Config{
		Role:     role,
		KeyPath:  filepath.Join(Dir(), "psk.key"),
		Surfaces: []string{"sidecar"},
		Domains:  policy.Domain{},
	}
	c.Peer = "127.0.0.1:8787"
	return c
}

func Load(path string) (Config, error) {
	var c Config
	_, err := toml.DecodeFile(path, &c)
	return c, err
}

func Save(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(c)
}
