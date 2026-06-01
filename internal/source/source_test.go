package source

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/policy"
	"github.com/solomonneas/agentpantry/internal/transport"
)

type fakeVault struct{ cs []cookie.Cookie }

func (f fakeVault) Name() string { return "fake" }
func (f fakeVault) ReadCookies(context.Context) ([]cookie.Cookie, error) {
	return f.cs, nil
}

func TestSyncOnceFiltersAndSeals(t *testing.T) {
	vault := fakeVault{cs: []cookie.Cookie{
		{Host: "github.com", Name: "sid", Path: "/", Value: "keep"},
		{Host: "bank.com", Name: "tok", Path: "/", Value: "drop"},
	}}
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer

	syncer := &Syncer{
		Vaults: []CookieReader{vault},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
	}

	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Decode the single frame and confirm only github.com survived.
	frame, err := transport.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	opener, _ := transport.NewOpener(make([]byte, 32))
	payload, err := opener.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	var d cookie.Diff
	if err := json.Unmarshal(payload, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Upserts) != 1 || d.Upserts[0].Host != "github.com" {
		t.Fatalf("policy filter failed: %+v", d.Upserts)
	}
}

func TestSyncOnceNoChangeSendsNothing(t *testing.T) {
	vault := fakeVault{cs: []cookie.Cookie{{Host: "github.com", Name: "s", Path: "/", Value: "v"}}}
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	syncer := &Syncer{
		Vaults: []CookieReader{vault},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := buf.Len()
	if first == 0 {
		t.Fatal("first sync should send a frame")
	}
	// Second sync with identical state must add nothing.
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != first {
		t.Fatalf("unchanged state must not resend: grew by %d", buf.Len()-first)
	}
}
