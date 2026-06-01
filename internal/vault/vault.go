package vault

import (
	"context"

	"github.com/solomonneas/agentpantry/internal/cookie"
)

// KeyProvider supplies the v11 keyring passphrase for a browser.
type KeyProvider interface {
	Passphrase() (string, error)
}

// BrowserVault reads and decrypts cookies from one browser profile.
type BrowserVault interface {
	Name() string
	ReadCookies(ctx context.Context) ([]cookie.Cookie, error)
}
