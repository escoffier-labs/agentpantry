package source

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

type oneVault struct{ cs []cookie.Cookie }

func (o oneVault) ReadCookies(context.Context) ([]cookie.Cookie, error) { return o.cs, nil }

func TestAfterSyncFiresWithSentAndCounts(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
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

func TestSyncOnceFiltersSecretsByName(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32), make([]byte, 16))
	var buf bytes.Buffer
	syncer := &Syncer{
		Secrets:      []SecretReader{fixedSecrets{ss: []secret.Secret{{Name: "keep", Value: "1"}, {Name: "drop", Value: "2"}}}},
		SecretPolicy: policy.Names{Deny: []string{"drop"}},
		Sealer:       sealer,
		Out:          &buf,
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	frame, err := transport.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	opener, _ := transport.NewOpener(make([]byte, 32), make([]byte, 16))
	raw, err := opener.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	var p wire.Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Secrets.Upserts) != 1 || p.Secrets.Upserts[0].Name != "keep" {
		t.Fatalf("secret-name policy did not filter: %+v", p.Secrets.Upserts)
	}
}

type fixedSecrets struct{ ss []secret.Secret }

func (f fixedSecrets) ReadSecrets(context.Context) ([]secret.Secret, error) { return f.ss, nil }
