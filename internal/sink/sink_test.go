package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

type capCookie struct{ applied []cookie.Diff }

func (c *capCookie) Apply(d cookie.Diff) error { c.applied = append(c.applied, d); return nil }

type capSecret struct{ applied []secret.Diff }

func (c *capSecret) ApplySecrets(d secret.Diff) error { c.applied = append(c.applied, d); return nil }

type capStorage struct{ applied []webstorage.Diff }

func (c *capStorage) ApplyStorage(d webstorage.Diff) error {
	c.applied = append(c.applied, d)
	return nil
}

func TestServeRoutesStorageToStorageSurface(t *testing.T) {
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	var w bytes.Buffer

	p := wire.Payload{Storage: webstorage.Diff{Upserts: []webstorage.Item{{Origin: "https://a.com", Key: "k", Value: "v"}}}}
	b, _ := json.Marshal(p)
	frame, _ := sealer.Seal(b)
	transport.WriteFrame(&w, frame)

	opener, _ := transport.NewOpener(key, make([]byte, 16))
	cs := &capStorage{}
	srv := &Server{Opener: opener, StorageSurfaces: []StorageSurface{cs}}
	if err := srv.Serve(context.Background(), &w); err != nil {
		t.Fatal(err)
	}
	if len(cs.applied) != 1 || len(cs.applied[0].Upserts) != 1 || cs.applied[0].Upserts[0].Key != "k" {
		t.Fatalf("storage surface not called correctly: %+v", cs.applied)
	}
}

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

func TestServeReapsUnauthenticatedIdlePeer(t *testing.T) {
	key := make([]byte, 32)
	opener, _ := transport.NewOpener(key, make([]byte, 16))
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	srv := &Server{Opener: opener, AuthTimeout: 50 * time.Millisecond}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(context.Background(), server) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected a timeout error for an idle unauthenticated peer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not reap the idle unauthenticated peer")
	}
}

func TestServeAllowsIdleAfterFirstAuthenticatedFrame(t *testing.T) {
	key := make([]byte, 32)
	salt := make([]byte, 16)
	sealer, _ := transport.NewSealer(key, salt)
	opener, _ := transport.NewOpener(key, salt)
	client, server := net.Pipe()
	defer client.Close()

	ss := &capSecret{}
	srv := &Server{Opener: opener, SecretSurfaces: []SecretSurface{ss}, AuthTimeout: 100 * time.Millisecond}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(context.Background(), server) }()

	send := func(name string) {
		p := wire.Payload{Secrets: secret.Diff{Upserts: []secret.Secret{{Name: name, Value: "v"}}}}
		b, _ := json.Marshal(p)
		frame, err := sealer.Seal(b)
		if err != nil {
			t.Error(err)
			return
		}
		if err := transport.WriteFrame(client, frame); err != nil {
			t.Error(err)
		}
	}

	send("first")
	time.Sleep(300 * time.Millisecond) // idle well past AuthTimeout
	send("second")
	client.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("authenticated idle connection must stay open, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after peer close")
	}
	if len(ss.applied) != 2 {
		t.Fatalf("expected 2 applied diffs, got %d", len(ss.applied))
	}
}
