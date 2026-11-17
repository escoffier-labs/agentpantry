package main

import (
	"context"
	"github.com/escoffier-labs/agentpantry/internal/tailnet"
	"net/netip"
	"testing"
)

func TestPrepareTailnetRequiresPolicy(t *testing.T) {
	for _, bind := range []string{"tailnet:8787", "tailnet6:8787"} {
		if _, _, _, e := prepareTailnet(context.Background(), bind, nil); e == nil {
			t.Fatal("resolved bind without policy")
		}
	}
	bind, gate, self, e := prepareTailnet(context.Background(), "127.0.0.1:8787", nil)
	if e != nil || self || gate != nil || bind != "127.0.0.1:8787" {
		t.Fatal(bind, e)
	}
}

type startupTailnetClient struct{}

func (startupTailnetClient) Status(context.Context) (tailnet.Status, error) {
	return tailnet.Status{Running: true, SelfIPs: []netip.Addr{netip.MustParseAddr("100.100.1.1")}}, nil
}
func (startupTailnetClient) WhoIs(context.Context, string) (tailnet.Identity, error) {
	panic("startup must not call WhoIs")
}
func TestPrepareTailnetSelfBindClassification(t *testing.T) {
	for _, tc := range []struct {
		bind string
		self bool
	}{{"100.100.1.1:8787", true}, {"tailnet:8787", true}, {"100.100.1.9:8787", false}, {"0.0.0.0:8787", false}, {"192.0.2.1:8787", false}} {
		t.Run(tc.bind, func(t *testing.T) {
			_, _, self, err := prepareTailnetWithClient(context.Background(), tc.bind, &tailnet.Policy{AllowNodes: []string{"node"}}, startupTailnetClient{})
			if err != nil || self != tc.self {
				t.Fatalf("self=%v err=%v", self, err)
			}
		})
	}
}
