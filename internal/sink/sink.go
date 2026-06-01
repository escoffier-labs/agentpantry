package sink

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/transport"
)

// Surface is the sink-side destination (matches surface.Surface).
type Surface interface {
	Apply(d cookie.Diff) error
}

// Server opens frames from a stream and applies them to surfaces.
type Server struct {
	Opener   *transport.Opener
	Surfaces []Surface
}

// Serve reads frames until EOF, applying each diff to all surfaces.
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
		payload, err := s.Opener.Open(frame)
		if err != nil {
			return err
		}
		var d cookie.Diff
		if err := json.Unmarshal(payload, &d); err != nil {
			return err
		}
		for _, surf := range s.Surfaces {
			if err := surf.Apply(d); err != nil {
				return err
			}
		}
	}
}
