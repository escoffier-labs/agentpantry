package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/privfile"
)

// BrowserRef names a browser profile and its cookie store path.
type BrowserRef struct {
	Kind       string `toml:"kind"` // "chromium" | "firefox" | "cdp"
	Profile    string `toml:"profile"`
	CookiePath string `toml:"cookie_path"`
	URL        string `toml:"url"` // cdp: DevTools base URL, e.g. http://127.0.0.1:9222
}

// AdapterRef declares a per-CLI or per-harness adapter sink surface.
type AdapterRef struct {
	Type     string            `toml:"type"`     // "netscape" | "gh" | "openclaw" | "hermes"
	Path     string            `toml:"path"`     // target file, or hermes bundle directory
	Secret   string            `toml:"secret"`   // gh: secret Name holding the token
	Host     string            `toml:"host"`     // gh: default "github.com"
	User     string            `toml:"user"`     // gh: optional user field
	Profiles map[string]string `toml:"profiles"` // openclaw: secretName -> profileKey
}

// Config is the on-disk configuration for either role.
type Config struct {
	Role           string        `toml:"role"` // "source" | "sink"
	Peer           string        `toml:"peer"` // dial target (source) or bind addr (sink)
	KeyPath        string        `toml:"key_path"`
	Surfaces       []string      `toml:"surfaces"`
	Browsers       []BrowserRef  `toml:"browsers"`
	SecretsDir     string        `toml:"secrets_dir"` // source: read from; sink: write to
	Adapters       []AdapterRef  `toml:"adapters"`
	Domains        policy.Domain `toml:"domains"`
	SecretNames    policy.Names  `toml:"secret_names"`
	ResyncSeconds  int           `toml:"resync_seconds"`   // source: periodic resync (0 = off)
	WarnExpiryDays int           `toml:"warn_expiry_days"` // source: warn on cookies expiring within N days (0 = off)
	SidecarPath    string        `toml:"sidecar_path"`     // sink: override the sidecar.db path (default: config dir)
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
	c, _, err := LoadChecked(path)
	return c, err
}

// LoadChecked parses path and also returns the names of any keys the config
// schema does not recognize, so a misspelled or misplaced key (for example
// secrets_dir landing under [domains]) surfaces instead of being silently
// ignored.
func LoadChecked(path string) (Config, []string, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return c, nil, err
	}
	var unknown []string
	for _, k := range md.Undecoded() {
		unknown = append(unknown, k.String())
	}
	return c, unknown, nil
}

// WriteTemplate writes a commented starter config for role. The uncommented
// values parse back to Default(role); the comments walk a new user through the
// fields the quickstart tells them to fill in.
func WriteTemplate(path, role string) error {
	keyPath := filepath.Join(Dir(), "psk.key")
	var body string
	switch role {
	case "source":
		body = fmt.Sprintf(`# agentpantry source config (runs on your daily driver).
# Edit the values below, then run `+"`agentpantry doctor`"+` to validate.

role = "source"

# Where to send sealed frames: the sink machine's host:port.
peer = "127.0.0.1:8787"

# Pre-shared key. Generate it on the sink with `+"`agentpantry keygen`"+` and
# copy the file here over a secure channel. Both ends need the same 0600 file.
key_path = %q

# Optional: mirror a directory of named secret files (one file = one secret).
#secrets_dir = "/home/you/.config/agentpantry/source-secrets"

# Optional: periodic full re-sync in seconds, in addition to file events.
#resync_seconds = 300

# Optional: warn on stderr when a synced cookie expires within this many days
# (0 = off). The sync is read-only and cannot renew a session; this just makes a
# looming re-auth visible.
#warn_expiry_days = 7

# At least one browser to read cookies from.
# kind: "chromium" (Chrome, Chromium, Brave, Edge), "firefox", or "cdp".
#[[browsers]]
#kind = "chromium"
#profile = "Default"
#cookie_path = "/home/you/.config/chromium/Default/Cookies"

# Domains are opt-in: nothing syncs until it matches an allow entry.
# A deny entry overrides any allow match.
[domains]
allow = []
deny = []

# Optional: restrict which secret names sync (empty allow permits all).
[secret_names]
allow = []
deny = []
`, keyPath)
	case "sink":
		body = fmt.Sprintf(`# agentpantry sink config (runs on the agent machine).
# Edit the values below, then run `+"`agentpantry doctor`"+` to validate.

role = "sink"

# Address to listen on. Keep it loopback or a trusted VPN interface.
peer = "127.0.0.1:8787"

# Pre-shared key. Generate it here with `+"`agentpantry keygen`"+`, then copy
# the file to the source machine over a secure channel.
key_path = %q

# Surfaces this sink writes to: "sidecar" (default), "secrets", "chrome".
surfaces = ["sidecar"]

# Optional: override where the sidecar surface writes its DB. Defaults to
# sidecar.db in the config dir. Set this to give each profile its own store
# without juggling XDG_CONFIG_HOME.
#sidecar_path = "/home/agent/.local/share/agentpantry/sidecar.db"

# Required by the "secrets" surface: where synced secrets are written.
#secrets_dir = "/home/agent/.config/agentpantry/secrets"

# Optional adapters write synced data where existing tools already look.
# See the examples/ directory for netscape, gh, openclaw, and hermes.
#[[adapters]]
#type = "netscape"
#path = "/home/agent/.config/agentpantry/cookies.txt"
`, keyPath)
	default:
		return fmt.Errorf("role must be source or sink")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return privfile.Write(path, []byte(body))
}

func Save(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return err
	}
	return privfile.Write(path, buf.Bytes())
}
