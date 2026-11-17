package sink

import (
	"context"
	"net"
)

// ServeListener gates accepted connections before invoking any protocol handler.
// The authorization lookup limiter is independent of this connection bound.
func ServeListener(ctx context.Context, ln net.Listener, limit int, authorize func(context.Context, net.Conn) error, handle func(net.Conn)) error {
	slots := make(chan struct{}, limit)
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		conn, err := ln.Accept()
		if err != nil {
			<-slots
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer func() { <-slots }()
			defer func() { _ = conn.Close() }()
			if authorize != nil && authorize(ctx, conn) != nil {
				return
			}
			handle(conn)
		}()
	}
}
