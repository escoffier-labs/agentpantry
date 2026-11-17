package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Binding scopes deletion metadata to one source configuration and destination.
// KeyFingerprint is a domain-separated digest, never the PSK bytes.
type Binding struct {
	ConfigPath     string `json:"config_path"`
	Hostname       string `json:"hostname"`
	Identity       string `json:"identity"`
	Peer           string `json:"peer"`
	KeyFingerprint string `json:"key_fingerprint"`
}

// PathForConfig keeps configs in the same directory on distinct state files.
func PathForConfig(configPath string) string { return filepath.Clean(configPath) + ".state.json" }

// NewBinding binds one config and destination to a host and domain-separated PSK digest.
func NewBinding(configPath, identity, peer string, key []byte) (Binding, error) {
	path, err := filepath.Abs(configPath)
	if err != nil {
		return Binding{}, err
	}
	host, err := os.Hostname()
	if err != nil {
		return Binding{}, err
	}
	if len(key) != 32 {
		return Binding{}, errors.New("source state binding requires a 32-byte PSK")
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("agentpantry/source-state/psk-fingerprint/v1\x00"))
	_, _ = digest.Write(key)
	binding := Binding{path, host, identity, peer, hex.EncodeToString(digest.Sum(nil))}
	if !binding.Valid() {
		return Binding{}, errors.New("source state binding requires config, host, identity and PSK fingerprint")
	}
	return binding, nil
}
func (b Binding) Valid() bool {
	digest, err := hex.DecodeString(b.KeyFingerprint)
	return filepath.IsAbs(b.ConfigPath) && strings.TrimSpace(b.Hostname) != "" && strings.TrimSpace(b.Identity) != "" && err == nil && len(digest) == sha256.Size
}

// LoadForDisplay reads legacy shared state only for status counters. Source
// deletion logic uses Load directly on the config-specific path instead.
func LoadForDisplay(configPath string) (State, error) {
	path := PathForConfig(configPath)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return Load(path)
	}
	old, err := Load(filepath.Join(filepath.Dir(configPath), "state.json"))
	return State{LastSyncUnix: old.LastSyncUnix, LastSentUnix: old.LastSentUnix, Cookies: old.Cookies, Secrets: old.Secrets, Storage: old.Storage}, err
}
