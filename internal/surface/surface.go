package surface

import (
	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
)

// CookieSurface is a sink-side destination for synced cookies.
type CookieSurface interface {
	Apply(d cookie.Diff) error
}

// SecretSurface is a sink-side destination for synced secrets.
type SecretSurface interface {
	ApplySecrets(d secret.Diff) error
}

// KeyProvider supplies a keyring passphrase (used by ChromeStore).
type KeyProvider interface {
	Passphrase() (string, error)
}
