package source

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/transport"
)

type countingVault struct {
	mu    sync.Mutex
	calls int
}

func (c *countingVault) ReadCookies(context.Context) ([]cookie.Cookie, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	// Return a changing value so each call produces a frame.
	return []cookie.Cookie{{Host: "github.com", Name: "s", Path: "/", Value: time.Now().String()}}, nil
}

func TestWatchSyncsOnEvent(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "Cookies")
	os.WriteFile(watched, []byte("init"), 0o600)

	sealer, _ := transport.NewSealer(make([]byte, 32))
	var buf bytes.Buffer
	v := &countingVault{}
	syncer := &Syncer{
		Vaults: []CookieReader{v},
		Policy: policy.Domain{Allow: []string{"github.com"}},
		Sealer: sealer,
		Out:    &buf,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- syncer.Watch(ctx, []string{watched}, 20*time.Millisecond) }()

	time.Sleep(50 * time.Millisecond)               // allow the initial sync
	os.WriteFile(watched, []byte("changed"), 0o600) // trigger an event
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatal(err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.calls < 2 {
		t.Fatalf("expected initial sync plus at least one event-driven sync, got %d", v.calls)
	}
}
