package wire

import (
	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/secret"
)

// Payload is the single envelope carried inside each transport frame.
type Payload struct {
	Cookies cookie.Diff `json:"cookies"`
	Secrets secret.Diff `json:"secrets"`
}

// IsEmpty reports whether neither diff carries changes.
func (p Payload) IsEmpty() bool {
	return p.Cookies.IsEmpty() && p.Secrets.IsEmpty()
}
