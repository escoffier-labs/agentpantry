package tailnet

import (
	"context"
	"errors"
	"strconv"

	"tailscale.com/client/local"
)

// LocalClient uses LocalAPI directly, without a subprocess or PATH lookup.
type LocalClient struct{ Client local.Client }

func (c *LocalClient) Status(ctx context.Context) (Status, error) {
	s, err := c.Client.Status(ctx)
	if err != nil {
		return Status{}, err
	}
	if s == nil || s.Self == nil {
		return Status{}, errors.New("missing self status")
	}
	out := Status{Running: s.BackendState == "Running", SelfIPs: s.Self.TailscaleIPs}
	for _, p := range s.Peer {
		if p != nil {
			out.Peers = append(out.Peers, Peer{StableID: string(p.ID), Online: p.Online})
		}
	}
	return out, nil
}
func (c *LocalClient) WhoIs(ctx context.Context, addr string) (Identity, error) {
	r, err := c.Client.WhoIs(ctx, addr)
	if err != nil {
		return Identity{}, err
	}
	if r == nil || r.Node == nil {
		return Identity{}, errors.New("missing WhoIs node")
	}
	id := Identity{StableID: string(r.Node.StableID), Addresses: r.Node.Addresses, Tags: r.Node.Tags}
	if r.UserProfile != nil && r.UserProfile.ID > 0 {
		id.UserID = strconv.FormatInt(int64(r.UserProfile.ID), 10)
	}
	return id, nil
}
