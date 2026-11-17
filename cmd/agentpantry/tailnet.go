package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/escoffier-labs/agentpantry/internal/tailnet"
)

func prepareTailnet(ctx context.Context, peer string, p *tailnet.Policy) (string, func(context.Context, net.Conn) error, bool, error) {
	return prepareTailnetWithClient(ctx, peer, p, &tailnet.LocalClient{})
}

func prepareTailnetWithClient(ctx context.Context, peer string, p *tailnet.Policy, client tailnet.Client) (string, func(context.Context, net.Conn) error, bool, error) {
	if p == nil {
		if host, _, _ := net.SplitHostPort(peer); host == "tailnet" || host == "tailnet6" {
			return "", nil, false, fmt.Errorf("tailnet bind requires [tailnet] identity selectors")
		}
		return peer, nil, false, nil
	}
	a, err := tailnet.New(client, *p)
	if err != nil {
		return "", nil, false, err
	}
	status, err := a.Preflight(ctx)
	if err != nil {
		return "", nil, false, err
	}
	resolved, err := tailnet.Resolve(peer, status)
	if err != nil {
		return "", nil, false, err
	}
	if p.AllowLoopback {
		fmt.Fprintln(os.Stderr, "warning: tailnet allow_loopback bypass trusts every local process and any SSH tunnel terminating locally; no Tailscale identity is verified")
	}
	return resolved, a.Authorize, tailnet.IsTailnetBind(resolved, status), nil
}
