package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/solomonneas/agentpantry/internal/cookie"
	"github.com/solomonneas/agentpantry/internal/policy"
	"github.com/solomonneas/agentpantry/internal/secret"
	"github.com/solomonneas/agentpantry/internal/transport"
	"github.com/solomonneas/agentpantry/internal/wire"
)

type fakeVault struct{ cs []cookie.Cookie }

func (f fakeVault) ReadCookies(context.Context) ([]cookie.Cookie, error) { return f.cs, nil }

type fakeSecrets struct{ ss []secret.Secret }

func (f fakeSecrets) ReadSecrets(context.Context) ([]secret.Secret, error) { return f.ss, nil }

type errSecrets struct{}

func (errSecrets) ReadSecrets(context.Context) ([]secret.Secret, error) {
	return nil, errors.New("secrets dir gone")
}

func decodePayload(t *testing.T, buf *bytes.Buffer) wire.Payload {
	t.Helper()
	frame, err := transport.ReadFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	opener, _ := transport.NewOpener(make([]byte, 32))
	raw, err := opener.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	var p wire.Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSyncOnceFiltersCookiesAndCarriesSecrets(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	syncer := &Syncer{
		Vaults: []CookieReader{fakeVault{cs: []cookie.Cookie{
			{Host: "github.com", Name: "sid", Path: "/", Value: "keep"},
			{Host: "bank.com", Name: "t", Path: "/", Value: "drop"},
		}}},
		Secrets: []SecretReader{fakeSecrets{ss: []secret.Secret{{Name: "gh", Value: "tok"}}}},
		Policy:  policy.Domain{Allow: []string{"github.com"}},
		Sealer:  sealer,
		Out:     &buf,
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := decodePayload(t, &buf)
	if len(p.Cookies.Upserts) != 1 || p.Cookies.Upserts[0].Host != "github.com" {
		t.Fatalf("cookie filter failed: %+v", p.Cookies.Upserts)
	}
	if len(p.Secrets.Upserts) != 1 || p.Secrets.Upserts[0].Name != "gh" {
		t.Fatalf("secret not carried: %+v", p.Secrets.Upserts)
	}
}

func TestSyncOnceSecretReaderErrorKeepsSecretsAndSyncsCookies(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	syncer := &Syncer{
		Vaults: []CookieReader{fakeVault{cs: []cookie.Cookie{
			{Host: "github.com", Name: "sid", Path: "/", Value: "keep"},
		}}},
		Secrets: []SecretReader{errSecrets{}},
		Policy:  policy.Domain{Allow: []string{"github.com"}},
		Sealer:  sealer,
		Out:     &buf,
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("secret reader error must not fail the cycle: %v", err)
	}
	p := decodePayload(t, &buf)
	if len(p.Cookies.Upserts) != 1 || p.Cookies.Upserts[0].Host != "github.com" {
		t.Fatalf("cookies should still sync: %+v", p.Cookies.Upserts)
	}
	if len(p.Secrets.Upserts) != 0 || len(p.Secrets.Deletes) != 0 {
		t.Fatalf("no secret diff should be emitted when the source is unavailable: %+v", p.Secrets)
	}
}

func TestSyncOnceNoChangeSendsNothing(t *testing.T) {
	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	syncer := &Syncer{
		Vaults: []CookieReader{fakeVault{cs: []cookie.Cookie{{Host: "github.com", Name: "s", Path: "/", Value: "v"}}}},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := buf.Len()
	if first == 0 {
		t.Fatal("first sync should send")
	}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != first {
		t.Fatalf("unchanged state must not resend")
	}
}
