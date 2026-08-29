package pair

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ServeConfig is the sink-side pairing listener.
type ServeConfig struct {
	Addr        string
	Code        string
	Timeout     time.Duration
	Attempts    int
	InFlight    int
	OnListening func(addr string)
	OnExchange  func()
}

type pairResult struct {
	psk []byte
	err error
}

// Serve listens until one pairing succeeds, the attempt cap is hit, or ctx/TTL
// ends. The short code is never reused after a successful return.
func Serve(ctx context.Context, cfg ServeConfig) ([]byte, error) {
	if _, err := NormalizeCode(cfg.Code); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = MaxAttempts
	}
	if cfg.InFlight <= 0 {
		cfg.InFlight = MaxInFlight
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ln.Close() }()
	if cfg.OnListening != nil {
		cfg.OnListening(ln.Addr().String())
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	conns := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			conns <- c
		}
	}()

	results := make(chan pairResult, cfg.InFlight)
	failures := 0
	inFlight := 0
	start := func(c net.Conn) {
		inFlight++
		go func(c net.Conn) {
			if cfg.OnExchange != nil {
				cfg.OnExchange()
			}
			psk, err := exchangeConn(c, cfg.Code, true)
			select {
			case results <- pairResult{psk, err}:
			case <-ctx.Done():
			}
		}(c)
	}
	// Attempt cap is a hard bound: never start an exchange that could
	// push failures+inFlight past Attempts. InFlight is only a DoS limit.
	canStart := func() bool {
		return inFlight < cfg.InFlight && failures+inFlight < cfg.Attempts
	}
	apply := func(res pairResult) ([]byte, error, bool) {
		inFlight--
		if res.err == nil {
			return res.psk, nil, true
		}
		if errors.Is(res.err, errPairFailed) {
			failures++
			if failures >= cfg.Attempts {
				return nil, fmt.Errorf("pairing locked after %d failed attempts", cfg.Attempts), true
			}
		}
		return nil, nil, false
	}
	for {
		// Drain finished exchanges before dispatching so inFlight matches
		// reality; otherwise a new conn can lose to a stale in-flight count.
		select {
		case res := <-results:
			psk, err, done := apply(res)
			if done {
				return psk, err
			}
			continue
		default:
		}
		select {
		case err := <-acceptErr:
			if ctx.Err() != nil {
				return nil, fmt.Errorf("pairing timed out")
			}
			return nil, err
		case conn := <-conns:
			if !canStart() {
				_ = conn.Close()
				continue
			}
			start(conn)
		case res := <-results:
			psk, err, done := apply(res)
			if done {
				return psk, err
			}
		}
	}
}

// Dial is the source-side pairing client.
func Dial(ctx context.Context, addr, code string) ([]byte, error) {
	if _, err := NormalizeCode(code); err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return exchangeConn(conn, code, false)
}

func exchangeConn(conn net.Conn, code string, sink bool) ([]byte, error) {
	defer func() { _ = conn.Close() }()
	if sink {
		if err := conn.SetDeadline(time.Now().Add(FirstReadTimeout)); err != nil {
			return nil, err
		}
		conn = &extendAfterFirstRead{Conn: conn, extend: ConnTimeout}
		return ExchangeSink(conn, code)
	}
	if err := conn.SetDeadline(time.Now().Add(ConnTimeout)); err != nil {
		return nil, err
	}
	return ExchangeSource(conn, code)
}

// extendAfterFirstRead lengthens the deadline once the peer sends a byte, so
// an idle connect dies at FirstReadTimeout while a real SPAKE2 exchange gets
// ConnTimeout.
type extendAfterFirstRead struct {
	net.Conn
	extend time.Duration
	once   sync.Once
}

func (c *extendAfterFirstRead) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() {
			_ = c.SetDeadline(time.Now().Add(c.extend))
		})
	}
	return n, err
}
