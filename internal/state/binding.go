package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Binding scopes deletion metadata independently of transport key rotation.
// No key-derived material belongs in this identity.
type Binding struct {
	ConfigPath string `json:"config_path"`
	Hostname   string `json:"hostname"`
	Identity   string `json:"identity"`
	Peer       string `json:"peer"`
}

// ResolveConfig follows the complete config path before deriving its identity.
// Resolution failures never fall back to lexical identity.
func ResolveConfig(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return "", err
	}
	return finalConfigPath(filepath.Clean(real))
}
func PathForConfig(path string) (string, error) {
	real, err := ResolveConfig(path)
	if err != nil {
		return "", err
	}
	return real + ".state.json", nil
}

func NewBinding(configPath, identity, peer string) (Binding, error) {
	path, err := ResolveConfig(configPath)
	if err != nil {
		return Binding{}, err
	}
	host, err := os.Hostname()
	if err != nil {
		return Binding{}, err
	}
	binding := Binding{path, host, identity, peer}
	if !binding.Valid() {
		return Binding{}, errors.New("source state binding requires config, host and identity")
	}
	return binding, nil
}
func (b Binding) Valid() bool {
	return filepath.IsAbs(b.ConfigPath) && strings.TrimSpace(b.Hostname) != "" && strings.TrimSpace(b.Identity) != ""
}

// LoadForDisplay reads legacy shared state only for status counters.
func LoadForDisplay(configPath string) (State, error) {
	real, err := ResolveConfig(configPath)
	if err != nil {
		return State{}, err
	}
	path := real + ".state.json"
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return Load(path)
	}
	old, err := Load(filepath.Join(filepath.Dir(real), "state.json"))
	return State{LastSyncUnix: old.LastSyncUnix, LastSentUnix: old.LastSentUnix, Cookies: old.Cookies, Secrets: old.Secrets, Storage: old.Storage}, err
}
