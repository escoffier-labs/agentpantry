package doctor

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/keyfile"
	"github.com/escoffier-labs/agentpantry/internal/vault"
)

// Status is the outcome of a single check.
type Status int

const (
	OK Status = iota
	Warn
	Fail
)

func (s Status) String() string {
	switch s {
	case OK:
		return "OK"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	default:
		return "?"
	}
}

// Check is one diagnostic result. Detail never contains secret/cookie values.
type Check struct {
	Name   string
	Status Status
	Detail string
}

// HasFail reports whether any check failed.
func HasFail(checks []Check) bool {
	for _, c := range checks {
		if c.Status == Fail {
			return true
		}
	}
	return false
}

func isLoopbackBind(peer string) bool {
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return false
	}
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".pantry-doctor-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// writableOrCreatable reports whether dir is writable, or does not yet exist but
// its parent is writable (so it will be created on first run).
func writableOrCreatable(dir string) bool {
	if writable(dir) {
		return true
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return writable(filepath.Dir(dir))
	}
	return false
}

// Run executes the role-appropriate non-network checks.
func Run(c config.Config) []Check {
	var checks []Check

	// key
	if info, err := os.Stat(c.KeyPath); err != nil {
		checks = append(checks, Check{"key", Fail, fmt.Sprintf("PSK not found at %s", c.KeyPath)})
	} else if info.Mode().Perm()&0o077 != 0 {
		checks = append(checks, Check{"key", Fail, fmt.Sprintf("PSK perms %v are too open, want 0600", info.Mode().Perm())})
	} else if _, err := keyfile.Load(c.KeyPath); err != nil {
		checks = append(checks, Check{"key", Fail, "PSK unreadable or not 32 bytes: " + err.Error()})
	} else {
		checks = append(checks, Check{"key", OK, "0600, 32 bytes"})
	}

	// config
	if c.Role != "source" && c.Role != "sink" {
		checks = append(checks, Check{"config", Fail, fmt.Sprintf("role must be source|sink, got %q", c.Role)})
	} else if _, _, err := net.SplitHostPort(c.Peer); err != nil {
		checks = append(checks, Check{"config", Fail, fmt.Sprintf("peer %q is not host:port", c.Peer)})
	} else {
		checks = append(checks, Check{"config", OK, c.Role + " " + c.Peer})
	}

	switch c.Role {
	case "source":
		for _, b := range c.Browsers {
			name := "vault:" + b.Profile
			if _, err := os.Stat(b.CookiePath); err != nil {
				checks = append(checks, Check{name, Fail, "cookie store unreadable: " + b.CookiePath})
			} else {
				checks = append(checks, Check{name, OK, b.CookiePath})
			}
		}
		if c.SecretsDir != "" {
			if _, err := os.Stat(c.SecretsDir); err != nil {
				checks = append(checks, Check{"secrets_dir", Fail, "missing: " + c.SecretsDir})
			} else {
				checks = append(checks, Check{"secrets_dir", OK, c.SecretsDir})
			}
		}
		hasChromium := false
		for _, b := range c.Browsers {
			if b.Kind == "chromium" {
				hasChromium = true
			}
		}
		if hasChromium && keyringRelevant() {
			checks = append(checks, KeyringCheck(&vault.SecretServiceKey{Label: "Chrome Safe Storage"}))
		}
	case "sink":
		if !isLoopbackBind(c.Peer) {
			checks = append(checks, Check{"bind", Warn, fmt.Sprintf("binding %s exposes the sink beyond loopback", c.Peer)})
		} else {
			checks = append(checks, Check{"bind", OK, "loopback"})
		}
		for _, name := range c.Surfaces {
			switch name {
			case "sidecar":
				if !writableOrCreatable(config.Dir()) {
					checks = append(checks, Check{"surface:sidecar", Fail, "sidecar dir not writable: " + config.Dir()})
				} else {
					checks = append(checks, Check{"surface:sidecar", OK, "plaintext sidecar"})
				}
			case "chrome":
				if len(c.Browsers) == 0 {
					checks = append(checks, Check{"surface:chrome", Fail, "chrome surface needs a [[browsers]] entry"})
				} else if _, err := os.Stat(c.Browsers[0].CookiePath); err != nil {
					checks = append(checks, Check{"surface:chrome", Fail, "target Cookies missing: " + c.Browsers[0].CookiePath})
				} else if singletonLockPresent(c.Browsers[0].CookiePath) {
					checks = append(checks, Check{"surface:chrome", Warn, "a SingletonLock suggests the target browser is running"})
				} else {
					checks = append(checks, Check{"surface:chrome", OK, c.Browsers[0].CookiePath})
				}
			case "secrets":
				if c.SecretsDir == "" {
					checks = append(checks, Check{"surface:secrets", Fail, "secrets surface needs secrets_dir"})
				} else if !writable(filepath.Dir(c.SecretsDir)) {
					checks = append(checks, Check{"surface:secrets", Fail, "secrets_dir parent not writable: " + c.SecretsDir})
				} else {
					checks = append(checks, Check{"surface:secrets", OK, c.SecretsDir})
				}
			default:
				checks = append(checks, Check{"surface:" + name, Fail, "unknown surface"})
			}
		}
		for _, a := range c.Adapters {
			name := "adapter:" + a.Type
			switch a.Type {
			case "netscape", "gh", "openclaw":
				if a.Path == "" {
					checks = append(checks, Check{name, Fail, "adapter needs a path"})
				} else if !writableOrCreatable(filepath.Dir(a.Path)) {
					checks = append(checks, Check{name, Fail, "adapter target dir not writable: " + a.Path})
				} else if a.Type == "gh" && a.Secret == "" {
					checks = append(checks, Check{name, Fail, "gh adapter needs a secret name"})
				} else if a.Type == "openclaw" && len(a.Profiles) == 0 {
					checks = append(checks, Check{name, Fail, "openclaw adapter needs a profiles mapping"})
				} else {
					checks = append(checks, Check{name, OK, a.Path})
				}
			default:
				checks = append(checks, Check{name, Fail, "unknown adapter type"})
			}
		}
	}
	return checks
}

func singletonLockPresent(cookiePath string) bool {
	dir := filepath.Dir(cookiePath)
	for _, p := range []string{filepath.Join(dir, "SingletonLock"), filepath.Join(filepath.Dir(dir), "SingletonLock")} {
		if _, err := os.Lstat(p); err == nil {
			return true
		}
	}
	return false
}

// KeyringCheck resolves the browser keyring passphrase and warns on the basic
// fallback. It never includes the passphrase value in the result.
func KeyringCheck(kp vault.KeyProvider) Check {
	pass, err := kp.Passphrase()
	if err != nil {
		return Check{"keyring", Fail, "keyring passphrase error: " + err.Error()}
	}
	if pass == "peanuts" {
		return Check{"keyring", Warn, "keyring fell back to the basic 'peanuts' passphrase (no Secret Service or locked keyring); v11 cookies will not decrypt with a real keyring"}
	}
	return Check{"keyring", OK, "resolved from Secret Service"}
}

// PeerReachable dials peer with a timeout. role=source only; no data is sent.
func PeerReachable(peer string, timeout time.Duration) Check {
	conn, err := net.DialTimeout("tcp", peer, timeout)
	if err != nil {
		return Check{"peer", Fail, "unreachable: " + err.Error()}
	}
	conn.Close()
	return Check{"peer", OK, "reachable " + peer}
}
