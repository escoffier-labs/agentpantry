package doctor

import (
	"context"
	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/tailnet"
	"net/netip"
	"testing"
)

type diagnosticClient struct{ running bool }

func (c diagnosticClient) Status(context.Context) (tailnet.Status, error) {
	return tailnet.Status{Running: c.running, SelfIPs: []netip.Addr{netip.MustParseAddr("100.100.1.1")}, Peers: []tailnet.Peer{{StableID: "online", Online: true}}}, nil
}
func (diagnosticClient) WhoIs(context.Context, string) (tailnet.Identity, error) {
	panic("doctor must not call WhoIs")
}
func TestTailnetChecks(t *testing.T) {
	c := config.Config{Peer: "tailnet:8787", Tailnet: &tailnet.Policy{AllowNodes: []string{"online", "missing"}, AllowLoopback: true}}
	checks := TailnetChecks(context.Background(), c, diagnosticClient{true})
	if HasFail(checks) {
		t.Fatal(checks)
	}
	warns := 0
	for _, v := range checks {
		if v.Status == Warn {
			warns++
		}
	}
	if warns != 2 {
		t.Fatal(checks)
	}
	if !HasFail(TailnetChecks(context.Background(), c, diagnosticClient{false})) {
		t.Fatal("stopped daemon passed")
	}
	c.Peer = "192.168.1.1:8787"
	if !HasFail(TailnetChecks(context.Background(), c, diagnosticClient{true})) {
		t.Fatal("LAN bind passed")
	}
}
