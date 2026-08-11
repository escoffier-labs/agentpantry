package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"reflect"
	"strings"
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

// TestServeFiltersInvalidStorageUpsertsAtBoundary pins shared-sink defense for
// every StorageSurface (storagestate, sidecar, …): only exact-canonical HTTP(S)
// upserts are applied; deletes stay intact so legacy unsafe rows can still be
// removed; credential material never appears in errors or captured output.
func TestServeFiltersInvalidStorageUpsertsAtBoundary(t *testing.T) {
	key := make([]byte, 32)
	sealer, _ := transport.NewSealer(key, make([]byte, 16))
	var w bytes.Buffer

	safe := []webstorage.Item{
		{Origin: "https://example.com", Key: "a", Value: "1"},
		{Origin: "https://192.0.2.1", Key: "b", Value: "2"},
		{Origin: "https://[2001:db8::1]", Key: "c", Value: "3"},
	}
	unsafe := []webstorage.Item{
		{Origin: "https://user:secret@example.com", Key: "cred", Value: "leak-me"},
		{Origin: "https://example.com/path", Key: "path", Value: "nope"},
		{Origin: "https://EXAMPLE.com", Key: "case", Value: "nope"},
	}
	deletes := []string{
		webstorage.Key(webstorage.Item{Origin: "https://example.com", Key: "gone"}),
		webstorage.Key(webstorage.Item{Origin: "https://user:legacy@example.com", Key: "old"}),
		webstorage.Key(webstorage.Item{Origin: "https://example.com/path", Key: "legacy-path"}),
	}
	upserts := append(append([]webstorage.Item{}, safe...), unsafe...)
	p := wire.Payload{Storage: webstorage.Diff{Upserts: upserts, Deletes: deletes}}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := sealer.Seal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.WriteFrame(&w, frame); err != nil {
		t.Fatal(err)
	}

	opener, _ := transport.NewOpener(key, make([]byte, 16))
	cs := &capStorage{}
	srv := &Server{Opener: opener, StorageSurfaces: []StorageSurface{cs}}
	serveErr := srv.Serve(context.Background(), &w)
	if serveErr != nil {
		msg := serveErr.Error()
		for _, leak := range []string{"secret", "leak-me", "user:secret"} {
			if strings.Contains(msg, leak) {
				t.Fatalf("Serve error leaked credential material %q: %v", leak, serveErr)
			}
		}
	}
	if len(cs.applied) != 1 {
		t.Fatalf("storage surface apply count = %d, want 1; err=%v applied=%+v", len(cs.applied), serveErr, cs.applied)
	}
	got := cs.applied[0]
	if !reflect.DeepEqual(got.Upserts, safe) {
		t.Fatalf("capStorage upserts = %#v, want exactly safe canonical %#v", got.Upserts, safe)
	}
	if !reflect.DeepEqual(got.Deletes, deletes) {
		t.Fatalf("capStorage deletes = %#v, want intact %#v", got.Deletes, deletes)
	}
	// Upsert path must not retain credentialed/path/noncanonical rows or their values.
	for _, it := range got.Upserts {
		if strings.Contains(it.Origin, "secret") || strings.Contains(it.Origin, "@") ||
			strings.Contains(it.Value, "leak-me") || strings.Contains(it.Key, "cred") {
			t.Fatalf("capStorage upsert retained credential material: %#v", it)
		}
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
