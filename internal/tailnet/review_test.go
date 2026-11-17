package tailnet

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestTransientDenialsDoNotPoisonCache(t *testing.T) {
	for _, kind := range []string{"whois-error", "ingress", "missing-fields", "malformed-address", "cancelled", "timeout", "status-error"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture()
			a, _ := New(f, Policy{AllowNodes: []string{"node"}})
			c := connection().(addressConn)
			ctx := context.Background()
			original := f.id
			switch kind {
			case "whois-error":
				f.err = errors.New("offline")
			case "ingress":
				c.local = "192.0.2.1:8787"
			case "missing-fields":
				f.id.StableID = ""
			case "malformed-address":
				f.id.Addresses = []netip.Prefix{{}}
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "timeout":
				f.who = func(ctx context.Context, _ string) (Identity, error) { <-ctx.Done(); return Identity{}, ctx.Err() }
			case "status-error":
				f.statusErr = errors.New("status unavailable")
			}
			if a.Authorize(ctx, c) == nil {
				t.Fatal("first connection allowed")
			}
			f.id = original
			f.err = nil
			f.statusErr = nil
			f.who = nil
			if err := a.Authorize(context.Background(), connection()); err != nil {
				t.Fatal("transient denial poisoned cache:", err)
			}
			if len(a.denied) != 0 {
				t.Fatal("transient failure cached")
			}
		})
	}
}
func TestLimiterExhaustionThenAllowSameAuthorizer(t *testing.T) {
	f := fixture()
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	f.who = func(context.Context, string) (Identity, error) { entered <- struct{}{}; <-release; return f.id, nil }
	a, _ := New(f, Policy{AllowNodes: []string{"node"}})
	results := make(chan error, 4)
	for i := 0; i < 4; i++ {
		c := connection().(addressConn)
		c.remote = netip.AddrPortFrom(netip.MustParseAddr("100.100.1.2"), uint16(2000+i)).String()
		go func() { results <- a.Authorize(context.Background(), c) }()
		<-entered
	}
	if a.Authorize(context.Background(), connection()) == nil {
		t.Fatal("capacity was not bounded")
	}
	close(release)
	for i := 0; i < 4; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	// The same remote IP was denied for capacity, but must be allowed now.
	if err := a.Authorize(context.Background(), connection()); err != nil {
		t.Fatal("capacity denial poisoned cache:", err)
	}
}
func TestSingleflightUsesFullAddrPort(t *testing.T) {
	f := fixture()
	entered := make(chan string, 2)
	release := make(chan struct{})
	f.who = func(_ context.Context, s string) (Identity, error) { entered <- s; <-release; return f.id, nil }
	a, _ := New(f, Policy{AllowNodes: []string{"node"}})
	result := make(chan error, 2)
	for _, port := range []string{"1234", "5678"} {
		c := connection().(addressConn)
		c.remote = "100.100.1.2:" + port
		go func() { result <- a.Authorize(context.Background(), c) }()
	}
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("different ports coalesced")
		}
	}
	// Release both workers and collect them before leaving the test.
	unblock()
	for i := 0; i < 2; i++ {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
}
func TestSingleflightCallerCancellationAndPerConnectionIngress(t *testing.T) {
	f := fixture()
	entered := make(chan struct{})
	release := make(chan struct{})
	f.who = func(ctx context.Context, _ string) (Identity, error) {
		close(entered)
		select {
		case <-release:
			return f.id, nil
		case <-ctx.Done():
			return Identity{}, ctx.Err()
		}
	}
	a, _ := New(f, Policy{AllowNodes: []string{"node"}})
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	c := connection().(addressConn)
	c.local = "192.0.2.1:8787"
	go func() { first <- a.Authorize(ctx, c) }()
	<-entered
	// Join directly while the flight is blocked so cancellation cannot race
	// the second caller starting a new flight.
	a.mu.Lock()
	flight := a.flights[netip.MustParseAddrPort("100.100.1.2:1234")]
	a.mu.Unlock()
	joined := make(chan struct{})
	waiter := &observedContext{Context: context.Background(), joined: joined}
	second := make(chan *flightResult, 1)
	go func() { second <- &flightResult{f: a.lookup(waiter, netip.MustParseAddrPort("100.100.1.2:1234"))} }()
	<-joined
	cancel()
	if err := <-first; err == nil {
		t.Fatal("cancelled caller allowed")
	}
	// A shared lookup cannot use the cancelled first caller's context.
	close(release)
	r := <-second
	if r.f.err != nil {
		t.Fatal("first caller cancelled shared flight:", r.f.err)
	}
	if r.f != flight {
		t.Fatal("lookup was not shared")
	}
	// Reuse one lookup result concurrently on two ingress addresses.
	// The invalid ingress must not deny or cache a valid connection.
	f.who = nil
	if a.Authorize(context.Background(), c) == nil {
		t.Fatal("bad ingress allowed")
	}
	if err := a.Authorize(context.Background(), connection()); err != nil {
		t.Fatal(err)
	}
}

type flightResult struct{ f *flight }
type nilAddressConn struct {
	net.Conn
	local, remote net.Addr
}

func (c nilAddressConn) LocalAddr() net.Addr  { return c.local }
func (c nilAddressConn) RemoteAddr() net.Addr { return c.remote }
func TestNilSocketAddressesDeny(t *testing.T) {
	f := fixture()
	a, _ := New(f, Policy{AllowNodes: []string{"node"}})
	for _, c := range []nilAddressConn{{}, {local: stringAddr("100.100.1.1:8787")}, {remote: stringAddr("100.100.1.2:1234")}} {
		if a.Authorize(context.Background(), c) == nil {
			t.Fatal("nil address allowed")
		}
	}
}

type mutexCheckingWriter struct {
	a      *Authorizer
	t      *testing.T
	mu     sync.Mutex
	writes int
}

func (w *mutexCheckingWriter) Write(p []byte) (int, error) {
	if !w.a.mu.TryLock() {
		w.t.Error("logging held authorizer mutex")
	} else {
		w.a.mu.Unlock()
	}
	w.mu.Lock()
	w.writes++
	w.mu.Unlock()
	return len(p), nil
}
func TestDenyLogsOutsideMutexAndRateLimits(t *testing.T) {
	a, _ := New(fixture(), Policy{AllowNodes: []string{"node"}})
	w := &mutexCheckingWriter{a: a, t: t}
	previous := log.Writer()
	log.SetOutput(w)
	defer log.SetOutput(previous)
	now := time.Now()
	a.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		_ = a.deny(netip.MustParseAddr("100.100.1.2"), "node", "test")
	}
	if w.writes != 1 {
		t.Fatal(w.writes)
	}
	now = now.Add(time.Second)
	_ = a.deny(netip.MustParseAddr("100.100.1.2"), "node", "test")
	if w.writes != 2 {
		t.Fatal(w.writes)
	}
}

var _ io.Writer = (*mutexCheckingWriter)(nil)

type observedContext struct {
	context.Context
	joined chan struct{}
	once   sync.Once
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.joined) })
	return c.Context.Done()
}
