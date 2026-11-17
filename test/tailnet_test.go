package test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/pair"
	"github.com/escoffier-labs/agentpantry/internal/sink"
	"github.com/escoffier-labs/agentpantry/internal/tailnet"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/wire"
)

type tailnetFake struct{ allowed bool }

func (f tailnetFake) Status(context.Context) (tailnet.Status, error) {
	return tailnet.Status{Running: true, SelfIPs: []netip.Addr{netip.MustParseAddr("100.100.1.1")}}, nil
}
func (f tailnetFake) WhoIs(context.Context, string) (tailnet.Identity, error) {
	id := "denied"
	if f.allowed {
		id = "source"
	}
	return tailnet.Identity{StableID: id, Addresses: []netip.Prefix{netip.MustParsePrefix("100.100.1.2/32")}}, nil
}

type tailnetConn struct{ net.Conn }

func (tailnetConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("100.100.1.1"), Port: 8787}
}
func (tailnetConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("100.100.1.2"), Port: 2222}
}
func testGate(t *testing.T, allowed bool) func(context.Context, net.Conn) error {
	t.Helper()
	a, e := tailnet.New(tailnetFake{allowed}, tailnet.Policy{AllowNodes: []string{"source"}})
	if e != nil {
		t.Fatal(e)
	}
	return func(ctx context.Context, c net.Conn) error { return a.Authorize(ctx, tailnetConn{c}) }
}
func TestTailnetSinkAcceptLoop(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		name := "denied"
		if allowed {
			name = "allowed"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ln, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			key := make([]byte, 32)
			applied := make(chan wire.Payload, 1)
			handlerErr := make(chan error, 1)
			done := make(chan error, 1)
			go func() {
				done <- sink.ServeListener(ctx, ln, 4, testGate(t, allowed), func(c net.Conn) {
					salt, e := transport.SendSalt(c)
					if e != nil {
						handlerErr <- e
						return
					}
					op, e := transport.NewOpener(key, salt)
					if e != nil {
						handlerErr <- e
						return
					}
					srv := sink.Server{Opener: op, AfterApply: func(p wire.Payload) { applied <- p }}
					handlerErr <- srv.Serve(ctx, c)
				})
			}()
			c, e := net.Dial("tcp", ln.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if !allowed {
				b := make([]byte, 1)
				n, e := c.Read(b)
				if n != 0 || e != io.EOF {
					t.Fatalf("denied peer got n=%d err=%v", n, e)
				}
			} else {
				salt, e := transport.RecvSalt(c)
				if e != nil {
					t.Fatal(e)
				}
				sealer, e := transport.NewSealer(key, salt)
				if e != nil {
					t.Fatal(e)
				}
				payload := wire.Payload{Cookies: cookie.Diff{Upserts: []cookie.Cookie{{Host: "example.com", Name: "sid", Value: "fixture"}}}}
				raw, e := json.Marshal(payload)
				if e != nil {
					t.Fatal(e)
				}
				frame, e := sealer.Seal(raw)
				if e != nil {
					t.Fatal(e)
				}
				if e := transport.WriteFrame(c, frame); e != nil {
					t.Fatal(e)
				}
				select {
				case p := <-applied:
					if len(p.Cookies.Upserts) != 1 {
						t.Fatal(p)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("sync did not apply")
				}
				_ = c.Close()
				if e := <-handlerErr; e != nil {
					t.Fatal(e)
				}
			}
			cancel()
			_ = ln.Close()
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestTailnetPairDenialDoesNotConsumeAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	var exchanges atomic.Int32
	var denied atomic.Bool
	deny := testGate(t, false)
	allow := testGate(t, true)
	go func() {
		_, e := pair.Serve(ctx, pair.ServeConfig{Addr: "127.0.0.1:0", Code: "AAAA-AAAA", Attempts: 1, Timeout: 10 * time.Second, Authorize: func(ctx context.Context, c net.Conn) error {
			if !denied.Swap(true) {
				return deny(ctx, c)
			}
			return allow(ctx, c)
		}, OnListening: func(addr string) { ready <- addr }, OnExchange: func() { exchanges.Add(1) }})
		done <- e
	}()
	addr := <-ready
	c, e := net.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 1)
	n, e := c.Read(b)
	_ = c.Close()
	if n != 0 || e != io.EOF {
		t.Fatalf("denial: n=%d err=%v", n, e)
	}
	if exchanges.Load() != 0 {
		t.Fatal("denial consumed exchange")
	}
	if _, e := pair.Dial(ctx, addr, "AAAA-AAAA"); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if exchanges.Load() != 1 {
		t.Fatal("wrong exchange count")
	}
}

func TestTailnetRealLoopbackListenerDeniesBeforeSalt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// This policy is the effective [tailnet] configuration. Socket addresses
	// come directly from the real TCP connection, without address wrappers.
	a, err := tailnet.New(tailnetFake{true}, tailnet.Policy{AllowNodes: []string{"source"}, AllowLoopback: false})
	if err != nil {
		t.Fatal(err)
	}
	var handled atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- sink.ServeListener(ctx, ln, 4, a.Authorize, func(c net.Conn) { handled.Store(true); _, _ = transport.SendSalt(c) })
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1)
	if n, err := c.Read(b); n != 0 || err != io.EOF {
		t.Fatalf("denied loopback: n=%d err=%v", n, err)
	}
	if handled.Load() {
		t.Fatal("salt handler ran")
	}
	cancel()
	_ = ln.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestPairSlowAuthorizationDoesNotBlockAllowedPeer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	entered := make(chan struct{})
	var seen atomic.Int32
	var exchanges atomic.Int32
	done := make(chan error, 1)
	go func() {
		_, err := pair.Serve(ctx, pair.ServeConfig{Addr: "127.0.0.1:0", Code: "AAAA-AAAA", Attempts: 1, Timeout: 2 * time.Second, Authorize: func(ctx context.Context, _ net.Conn) error {
			if seen.Add(1) == 1 {
				close(entered)
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		}, OnListening: func(addr string) { ready <- addr }, OnExchange: func() { exchanges.Add(1) }})
		done <- err
	}()
	addr := <-ready
	slow, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	<-entered
	allowedCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err := pair.Dial(allowedCtx, addr, "AAAA-AAAA"); err != nil {
		t.Fatal("allowed peer starved:", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = slow.SetDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1)
	if n, err := slow.Read(b); n != 0 || err != io.EOF {
		t.Fatalf("slow peer: n=%d err=%v", n, err)
	}
	if exchanges.Load() != 1 {
		t.Fatal("authorization consumed a SPAKE2 attempt")
	}
}

func TestPairPendingAuthorizationBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	entered := make(chan struct{}, 8)
	done := make(chan error, 1)
	go func() {
		_, err := pair.Serve(ctx, pair.ServeConfig{Addr: "127.0.0.1:0", Code: "AAAA-AAAA", Timeout: time.Second, Authorize: func(ctx context.Context, _ net.Conn) error { entered <- struct{}{}; <-ctx.Done(); return ctx.Err() }, OnListening: func(addr string) { ready <- addr }})
		done <- err
	}()
	addr := <-ready
	for i := 0; i < 4; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		<-entered
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1)
	if n, err := c.Read(b); n != 0 || err != io.EOF {
		t.Fatalf("overflow connection n=%d err=%v", n, err)
	}
	select {
	case <-entered:
		t.Fatal("pending authorization bound exceeded")
	default:
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled pairing succeeded")
	}
}
