package doctor

import (
	"context"
	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/tailnet"
	"io"
	"net/http"
	"net/netip"
	"strings"
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
	if HasFail(TailnetChecks(context.Background(), c, diagnosticClient{true})) {
		t.Fatal("LAN bind must warn, not fail")
	}
}

func TestTailnetBindClassification(t *testing.T) {
	for _, tc := range []struct {
		bind       string
		fail       bool
		bindStatus Status
	}{
		{"100.100.1.1:8787", false, OK}, {"tailnet:8787", false, OK},
		{"100.100.1.9:8787", true, Warn}, {"0.0.0.0:8787", false, Warn},
		{"[::]:8787", false, Warn}, {":8787", false, Warn}, {"192.0.2.1:8787", false, Warn},
	} {
		t.Run(tc.bind, func(t *testing.T) {
			c := config.Config{Peer: tc.bind, Tailnet: &tailnet.Policy{AllowNodes: []string{"online"}}}
			checks := TailnetChecks(context.Background(), c, diagnosticClient{true})
			if HasFail(checks) != tc.fail {
				t.Fatal(checks)
			}
			found := false
			for _, check := range checks {
				if check.Name == "bind" {
					found = true
					if check.Status != tc.bindStatus {
						t.Fatal(checks)
					}
				}
			}
			if !found {
				t.Fatal("missing bind classification")
			}
		})
	}
}

type peerMapTransport struct{}

func (peerMapTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"BackendState":"Running","Self":{"TailscaleIPs":["100.100.1.1"]},"Peer":{"nodekey:0000000000000000000000000000000000000000000000000000000000000000":{"ID":"online","Online":true},"nodekey:1111111111111111111111111111111111111111111111111111111111111111":{"ID":"offline","Online":false}}}`))}, nil
}
func TestDoctorUsesLocalClientPeerMap(t *testing.T) {
	client := &tailnet.LocalClient{}
	client.Client.Transport = peerMapTransport{}
	client.Client.OmitAuth = true
	c := config.Config{Peer: "tailnet:8787", Tailnet: &tailnet.Policy{AllowNodes: []string{"online", "offline", "missing"}}}
	checks := TailnetChecks(context.Background(), c, client)
	if HasFail(checks) {
		t.Fatal(checks)
	}
	nodes := map[string]Status{}
	for _, check := range checks {
		if check.Name == "tailnet:node" {
			nodes[strings.Split(check.Detail, ":")[0]] = check.Status
		}
	}
	if len(nodes) != 3 || nodes["online"] != OK || nodes["offline"] != Warn || nodes["missing"] != Warn {
		t.Fatal(nodes)
	}
}
