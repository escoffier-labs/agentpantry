package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/escoffier-labs/agentpantry/internal/tailnet"
)

func prepareTailnet(ctx context.Context, peer string, p *tailnet.Policy) (string, func(context.Context, net.Conn) error, error) {
	if p == nil {
		if host, _, _ := net.SplitHostPort(peer); host == "tailnet" || host == "tailnet6" {
			return "", nil, fmt.Errorf("tailnet bind requires [tailnet] identity selectors")
		}
		return peer, nil, nil
	}
	a, err := tailnet.New(&tailnet.LocalClient{}, *p)
	if err != nil {
		return "", nil, err
	}
	status, err := a.Preflight(ctx)
	if err != nil {
		return "", nil, err
	}
	resolved, err := tailnet.Resolve(peer, status)
	if err != nil {
		return "", nil, err
	}
	if p.AllowLoopback {
		fmt.Fprintln(os.Stderr, "warning: tailnet allow_loopback bypass trusts every local process and any SSH tunnel terminating locally; no Tailscale identity is verified")
	}
	return resolved, a.Authorize, nil
}
