package wire

import (
	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
)

// Payload is the single envelope carried inside each transport frame.
//
// Storage is additive: a frame from an older source omits the field, and an
// older sink drops it, so both directions default to an empty localStorage diff
// with no version negotiation.
type Payload struct {
	Cookies cookie.Diff     `json:"cookies"`
	Secrets secret.Diff     `json:"secrets"`
	Storage webstorage.Diff `json:"storage"`
}

// IsEmpty reports whether no diff carries changes.
func (p Payload) IsEmpty() bool {
	return p.Cookies.IsEmpty() && p.Secrets.IsEmpty() && p.Storage.IsEmpty()
}
