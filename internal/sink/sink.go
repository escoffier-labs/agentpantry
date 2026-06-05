package sink

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

// CookieSurface is a sink-side destination for synced cookies.
type CookieSurface interface {
	Apply(d cookie.Diff) error
}

// SecretSurface is a sink-side destination for synced secrets.
type SecretSurface interface {
	ApplySecrets(d secret.Diff) error
}

// Server opens frames from a stream and routes payloads to surfaces.
type Server struct {
	Opener         *transport.Opener
	CookieSurfaces []CookieSurface
	SecretSurfaces []SecretSurface

	// AuthTimeout, when > 0 and the stream supports read deadlines, bounds the
	// wait for the first frame that authenticates under the session key. A peer
	// that connects but never proves knowledge of the PSK is dropped instead of
	// holding the connection open forever. Cleared once a frame authenticates:
	// a legitimate source may idle indefinitely between syncs.
	AuthTimeout time.Duration

	// ApplyMu, when set, serializes surface application across concurrently
	// served connections that share the same surfaces.
	ApplyMu *sync.Mutex
}

// readDeadliner is the optional stream capability AuthTimeout needs.
type readDeadliner interface {
	SetReadDeadline(time.Time) error
}

// Serve reads frames until EOF, routing each payload to all surfaces.
func (s *Server) Serve(ctx context.Context, r io.Reader) error {
	dr, canDeadline := r.(readDeadliner)
	if s.AuthTimeout > 0 && canDeadline {
		if err := dr.SetReadDeadline(time.Now().Add(s.AuthTimeout)); err != nil {
			return err
		}
	}
	authed := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		frame, err := transport.ReadFrame(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		raw, err := s.Opener.Open(frame)
		if err != nil {
			return err
		}
		if !authed {
			authed = true
			if s.AuthTimeout > 0 && canDeadline {
				if err := dr.SetReadDeadline(time.Time{}); err != nil {
					return err
				}
			}
		}
		var p wire.Payload
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		if err := s.apply(p); err != nil {
			return err
		}
	}
}

func (s *Server) apply(p wire.Payload) error {
	if s.ApplyMu != nil {
		s.ApplyMu.Lock()
		defer s.ApplyMu.Unlock()
	}
	if !p.Cookies.IsEmpty() {
		for _, cs := range s.CookieSurfaces {
			if err := cs.Apply(p.Cookies); err != nil {
				return err
			}
		}
	}
	if !p.Secrets.IsEmpty() {
		for _, ss := range s.SecretSurfaces {
			if err := ss.ApplySecrets(p.Secrets); err != nil {
				return err
			}
		}
	}
	return nil
}
