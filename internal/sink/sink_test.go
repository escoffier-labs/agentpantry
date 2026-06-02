package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

type capCookie struct{ applied []cookie.Diff }

func (c *capCookie) Apply(d cookie.Diff) error { c.applied = append(c.applied, d); return nil }

type capSecret struct{ applied []secret.Diff }

func (c *capSecret) ApplySecrets(d secret.Diff) error { c.applied = append(c.applied, d); return nil }

func TestServeRoutesPayloadToBothSurfaces(t *testing.T) {
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	var w bytes.Buffer

	p := wire.Payload{
		Cookies: cookie.Diff{Upserts: []cookie.Cookie{{Host: "a.com", Name: "x", Path: "/", Value: "1"}}},
		Secrets: secret.Diff{Upserts: []secret.Secret{{Name: "gh", Value: "tok"}}},
	}
	b, _ := json.Marshal(p)
	frame, _ := sealer.Seal(b)
	transport.WriteFrame(&w, frame)

	opener, _ := transport.NewOpener(key, make([]byte, 16))
	cc := &capCookie{}
	ss := &capSecret{}
	srv := &Server{Opener: opener, CookieSurfaces: []CookieSurface{cc}, SecretSurfaces: []SecretSurface{ss}}

	if err := srv.Serve(context.Background(), &w); err != nil {
		t.Fatal(err)
	}
	if len(cc.applied) != 1 || len(cc.applied[0].Upserts) != 1 {
		t.Fatalf("cookie surface not called: %+v", cc.applied)
	}
	if len(ss.applied) != 1 || len(ss.applied[0].Upserts) != 1 {
		t.Fatalf("secret surface not called: %+v", ss.applied)
	}
}
