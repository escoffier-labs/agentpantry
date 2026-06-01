package sink

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/secret"
	"github.com/solomonneas/agentpantry/internal/transport"
	"github.com/solomonneas/agentpantry/internal/wire"
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
}

// Serve reads frames until EOF, routing each payload to all surfaces.
func (s *Server) Serve(ctx context.Context, r io.Reader) error {
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
		var p wire.Payload
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
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
	}
}
