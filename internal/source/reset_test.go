package source

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

func TestResetResendsFullState(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	var buf bytes.Buffer
	s := &Syncer{
		Vaults: []CookieReader{oneVault{cs: []cookie.Cookie{{Host: "github.com", Name: "a", Path: "/", Value: "1"}}}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
	}
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := buf.Len()
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != first {
		t.Fatal("unchanged state should not resend")
	}
	s.Reset()
	if err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == first {
		t.Fatal("Reset should force a full resend")
	}
	transport.ReadFrame(&buf) // skip first frame
	frame, _ := transport.ReadFrame(&buf)
	opener, _ := transport.NewOpener(make([]byte, 32), make([]byte, 16))
	raw, err := opener.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	var p wire.Payload
	json.Unmarshal(raw, &p)
	if len(p.Cookies.Upserts) != 1 {
		t.Fatalf("resend should include the cookie, got %+v", p.Cookies.Upserts)
	}
}
