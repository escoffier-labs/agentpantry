package tailnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClient struct {
	statusErr error
	status    Status
	id        Identity
	err       error
	who       func(context.Context, string) (Identity, error)
	calls     atomic.Int32
}

func (f *fakeClient) Status(context.Context) (Status, error) { return f.status, f.statusErr }
func (f *fakeClient) WhoIs(ctx context.Context, s string) (Identity, error) {
	f.calls.Add(1)
	if f.who != nil {
		return f.who(ctx, s)
	}
	return f.id, f.err
}
func fixture() *fakeClient {
	return &fakeClient{status: Status{Running: true, SelfIPs: []netip.Addr{netip.MustParseAddr("100.100.1.1")}}, id: Identity{StableID: "node", Addresses: []netip.Prefix{netip.MustParsePrefix("100.100.1.2/32")}, UserID: "123"}}
}

type addressConn struct {
	net.Conn
	local, remote string
}

func (c addressConn) LocalAddr() net.Addr  { return stringAddr(c.local) }
func (c addressConn) RemoteAddr() net.Addr { return stringAddr(c.remote) }

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }
func connection() net.Conn           { return addressConn{local: "100.100.1.1:8787", remote: "100.100.1.2:1234"} }
func TestIsTailnetIP(t *testing.T) {
	for ip, want := range map[string]bool{"100.64.0.1": true, "100.127.255.255": true, "::ffff:100.100.1.1": true, "fd7a:115c:a1e0::1": true, "100.128.0.1": false, "127.0.0.1": false, "fd00::1": false, "bad": false} {
		a, _ := netip.ParseAddr(ip)
		if IsTailnetIP(a) != want {
			t.Error(ip)
		}
	}
}
func TestAuthorizeRules(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*fakeClient, *Policy, *addressConn)
		allowed bool
	}{
		{"stable", func(*fakeClient, *Policy, *addressConn) {}, true},
		{"tag", func(f *fakeClient, p *Policy, _ *addressConn) {
			p.AllowNodes = nil
			p.AllowTags = []string{"tag:source"}
			f.id.Tags = p.AllowTags
		}, true},
		{"user", func(_ *fakeClient, p *Policy, _ *addressConn) { p.AllowNodes = nil; p.AllowUserIDs = []string{"123"} }, true},
		{"tagged-user", func(f *fakeClient, p *Policy, _ *addressConn) {
			p.AllowNodes = nil
			p.AllowUserIDs = []string{"123"}
			f.id.Tags = []string{"tag:other"}
		}, false},
		{"ingress", func(_ *fakeClient, _ *Policy, c *addressConn) { c.local = "192.168.1.1:8787" }, false},
		{"other-cgnat", func(_ *fakeClient, _ *Policy, c *addressConn) { c.remote = "100.64.9.9:2222" }, false},
		{"non-tailnet", func(_ *fakeClient, _ *Policy, c *addressConn) { c.remote = "192.0.2.9:2222" }, false},
		{"missing-id", func(f *fakeClient, _ *Policy, _ *addressConn) { f.id.StableID = "" }, false},
		{"missing-addresses", func(f *fakeClient, _ *Policy, _ *addressConn) { f.id.Addresses = nil }, false},
		{"malformed-address", func(f *fakeClient, _ *Policy, _ *addressConn) { f.id.Addresses = []netip.Prefix{{}} }, false},
		{"subnet-is-not-node", func(f *fakeClient, _ *Policy, _ *addressConn) {
			f.id.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
		}, false},
		{"error", func(f *fakeClient, _ *Policy, _ *addressConn) { f.err = errors.New("offline") }, false},
		{"stopped", func(f *fakeClient, _ *Policy, _ *addressConn) { f.status.Running = false }, false},
		{"loopback-bypass", func(_ *fakeClient, p *Policy, c *addressConn) {
			p.AllowLoopback = true
			c.local = "127.0.0.1:8787"
			c.remote = "127.0.0.1:2222"
		}, true},
		{"loopback-default", func(_ *fakeClient, _ *Policy, c *addressConn) {
			c.local = "127.0.0.1:8787"
			c.remote = "127.0.0.1:2222"
		}, false},
		{"loopback-wide", func(_ *fakeClient, p *Policy, c *addressConn) { p.AllowLoopback = true; c.remote = "127.0.0.1:2222" }, false},
		{"malformed-socket", func(_ *fakeClient, _ *Policy, c *addressConn) { c.remote = "bad" }, false},
		{"mapped", func(_ *fakeClient, _ *Policy, c *addressConn) {
			c.local = "[::ffff:100.100.1.1]:8787"
			c.remote = "[::ffff:100.100.1.2]:2222"
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fixture()
			p := Policy{AllowNodes: []string{"node"}}
			c := connection().(addressConn)
			tt.modify(f, &p, &c)
			a, e := New(f, p)
			if e != nil {
				t.Fatal(e)
			}
			if got := a.Authorize(context.Background(), c) == nil; got != tt.allowed {
				t.Fatalf("allowed=%v want %v", got, tt.allowed)
			}
		})
	}
}
func TestNoPositiveCache(t *testing.T) {
	for _, change := range []string{"removal", "tag"} {
		t.Run(change, func(t *testing.T) {
			f := fixture()
			f.id.Tags = []string{"tag:source"}
			a, _ := New(f, Policy{AllowTags: []string{"tag:source"}})
			if e := a.Authorize(context.Background(), connection()); e != nil {
				t.Fatal(e)
			}
			if change == "removal" {
				f.err = errors.New("removed")
			} else {
				f.id.Tags = []string{"tag:other"}
			}
			if a.Authorize(context.Background(), connection()) == nil {
				t.Fatal("stale authorization")
			}
			if f.calls.Load() != 2 {
				t.Fatal("positive cache")
			}
		})
	}
}
func TestNegativeCacheExpiry(t *testing.T) {
	f := fixture()
	f.id.StableID = "not-allowed"
	a, _ := New(f, Policy{AllowNodes: []string{"node"}})
	now := time.Now()
	a.now = func() time.Time { return now }
	_ = a.Authorize(context.Background(), connection())
	f.id.StableID = "node"
	if a.Authorize(context.Background(), connection()) == nil {
		t.Fatal("negative cache absent")
	}
	now = now.Add(16 * time.Second)
	if e := a.Authorize(context.Background(), connection()); e != nil {
		t.Fatal(e)
	}
	if f.calls.Load() != 2 {
		t.Fatal(f.calls.Load())
	}
}
func TestWhoIsTimeout(t *testing.T) {
	f := fixture()
	f.who = func(ctx context.Context, _ string) (Identity, error) { <-ctx.Done(); return Identity{}, ctx.Err() }
	a, _ := New(f, Policy{AllowNodes: []string{"node"}})
	start := time.Now()
	if a.Authorize(context.Background(), connection()) == nil {
		t.Fatal("allowed timeout")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("lookup exceeded bound")
	}
}
func TestLimiterAndSingleflight(t *testing.T) {
	f := fixture()
	entered := make(chan struct{}, 100)
	release := make(chan struct{})
	f.who = func(ctx context.Context, _ string) (Identity, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return f.id, nil
		case <-ctx.Done():
			return Identity{}, ctx.Err()
		}
	}
	a, _ := New(f, Policy{AllowNodes: []string{"node"}})
	var wg sync.WaitGroup
	// Different remote IPs fill the global limiter, even across authorizers.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b, _ := New(f, a.policy)
			c := connection().(addressConn)
			c.remote = netip.AddrPortFrom(netip.AddrFrom4([4]byte{100, 100, 1, byte(i + 2)}), 2222).String()
			_ = b.Authorize(context.Background(), c)
		}(i)
		<-entered
	}
	if a.Authorize(context.Background(), connection()) == nil {
		t.Fatal("full limiter allowed")
	}
	if f.calls.Load() != 4 {
		t.Fatal("limiter exceeded")
	}
	close(release)
	wg.Wait()
	// One in-progress lookup is shared across a stampede of the same IP.
	a, _ = New(f, a.policy)
	release = make(chan struct{})
	f.calls.Store(0)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = a.Authorize(context.Background(), connection()) }()
	}
	<-entered
	// Wait until all goroutines have had a chance to join; the lookup remains blocked.
	time.Sleep(50 * time.Millisecond)
	if f.calls.Load() != 1 {
		t.Fatal("stampede was not coalesced")
	}
	close(release)
	wg.Wait()
}
func TestResolveAndPreflight(t *testing.T) {
	f := fixture()
	a, _ := New(f, Policy{AllowNodes: []string{"node"}})
	s, e := a.Preflight(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if b, e := Resolve("tailnet:8787", s); e != nil || b != "100.100.1.1:8787" {
		t.Fatal(b, e)
	}
	if _, e := Resolve("tailnet6:8787", s); e == nil {
		t.Fatal("family fallback")
	}
	f.status.Running = false
	if _, e := a.Preflight(context.Background()); e == nil {
		t.Fatal("stopped preflight")
	}
}
