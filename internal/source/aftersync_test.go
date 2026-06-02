package source

import (
	"bytes"
	"context"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/transport"
)

type oneVault struct{ cs []cookie.Cookie }

func (o oneVault) ReadCookies(context.Context) ([]cookie.Cookie, error) { return o.cs, nil }

func TestAfterSyncFiresWithSentAndCounts(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	type call struct {
		sent             bool
		cookies, secrets int
	}
	var calls []call
	syncer := &Syncer{
		Vaults: []CookieReader{oneVault{cs: []cookie.Cookie{
			{Host: "github.com", Name: "a", Path: "/", Value: "1"},
			{Host: "github.com", Name: "b", Path: "/", Value: "2"},
		}}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
		AfterSync: func(sent bool, c, s int) {
			calls = append(calls, call{sent, c, s})
		},
	}
	// First sync: 2 cookie upserts sent.
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Second sync: no change, nothing sent.
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("AfterSync must fire once per SyncOnce, got %d", len(calls))
	}
	if !calls[0].sent || calls[0].cookies != 2 {
		t.Fatalf("first call wrong: %+v", calls[0])
	}
	if calls[1].sent || calls[1].cookies != 0 {
		t.Fatalf("second call must be no-send: %+v", calls[1])
	}
}
