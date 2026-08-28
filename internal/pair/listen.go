package pair

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ServeConfig is the sink-side pairing listener.
type ServeConfig struct {
	Addr        string
	Code        string
	Timeout     time.Duration
	Attempts    int
	OnListening func(addr string)
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

	failures := 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("pairing timed out")
			}
			return nil, err
		}
		psk, err := exchangeConn(conn, cfg.Code, true)
		if err == nil {
			return psk, nil
		}
		failures++
		if failures >= cfg.Attempts {
			return nil, fmt.Errorf("pairing locked after %d failed attempts", cfg.Attempts)
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
	if err := conn.SetDeadline(time.Now().Add(ConnTimeout)); err != nil {
		return nil, err
	}
	if sink {
		return ExchangeSink(conn, code)
	}
	return ExchangeSource(conn, code)
}
