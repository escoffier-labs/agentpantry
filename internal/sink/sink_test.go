package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/transport"
)

type capturingSurface struct{ applied []cookie.Diff }

func (c *capturingSurface) Apply(d cookie.Diff) error {
	c.applied = append(c.applied, d)
	return nil
}

func TestServeAppliesFramesToSurfaces(t *testing.T) {
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key)
	var wire bytes.Buffer

	d := cookie.Diff{Upserts: []cookie.Cookie{{Host: "a.com", Name: "x", Path: "/", Value: "1"}}}
	payload, _ := json.Marshal(d)
	frame, _ := sealer.Seal(payload)
	transport.WriteFrame(&wire, frame)

	opener, _ := transport.NewOpener(key)
	surf := &capturingSurface{}
	srv := &Server{Opener: opener, Surfaces: []Surface{surf}}

	if err := srv.Serve(context.Background(), &wire); err != nil {
		t.Fatal(err)
	}
	if len(surf.applied) != 1 || len(surf.applied[0].Upserts) != 1 {
		t.Fatalf("surface did not receive the diff: %+v", surf.applied)
	}
}
