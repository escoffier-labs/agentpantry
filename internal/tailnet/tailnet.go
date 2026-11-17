// Package tailnet gates TCP listeners using the local Tailscale daemon.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const lookupTimeout = 3 * time.Second

var lookupSlots = make(chan struct{}, 4)
var v4 = netip.MustParsePrefix("100.64.0.0/10")
var v6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

func IsTailnetIP(ip netip.Addr) bool { ip = ip.Unmap(); return v4.Contains(ip) || v6.Contains(ip) }

// Policy presence enables enforcement. Names never select an identity.
type Policy struct {
	AllowNodes    []string `toml:"allow_nodes"`
	AllowTags     []string `toml:"allow_tags"`
	AllowUserIDs  []string `toml:"allow_user_ids"`
	AllowLoopback bool     `toml:"allow_loopback"`
}

func (p Policy) Validate() error {
	if len(p.AllowNodes)+len(p.AllowTags)+len(p.AllowUserIDs) == 0 {
		return errors.New("tailnet: at least one identity selector is required")
	}
	for _, list := range [][]string{p.AllowNodes, p.AllowTags, p.AllowUserIDs} {
		for _, s := range list {
			if strings.TrimSpace(s) == "" || s != strings.TrimSpace(s) {
				return errors.New("tailnet: blank or padded identity selector")
			}
		}
	}
	for _, s := range p.AllowTags {
		if !strings.HasPrefix(s, "tag:") || len(s) == 4 {
			return errors.New("tailnet: invalid tag selector")
		}
	}
	for _, s := range p.AllowUserIDs {
		n, e := strconv.ParseUint(s, 10, 63)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != s {
			return errors.New("tailnet: UserID must be a positive decimal integer")
		}
	}
	return nil
}

type Peer struct {
	StableID string
	Online   bool
}
type Status struct {
	Running bool
	SelfIPs []netip.Addr
	Peers   []Peer
}
type Identity struct {
	StableID  string
	Addresses []netip.Prefix
	Tags      []string
	UserID    string
}
type Client interface {
	Status(context.Context) (Status, error)
	WhoIs(context.Context, string) (Identity, error)
}

type flight struct {
	done     chan struct{}
	status   Status
	identity Identity
	err      error
}
type Authorizer struct {
	client  Client
	policy  Policy
	mu      sync.Mutex
	flights map[netip.AddrPort]*flight
	denied  map[netip.Addr]time.Time
	lastLog time.Time
	now     func() time.Time
}

func New(client Client, p Policy) (*Authorizer, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &Authorizer{client: client, policy: p, flights: make(map[netip.AddrPort]*flight), denied: make(map[netip.Addr]time.Time), now: time.Now}, nil
}
func (a *Authorizer) Preflight(ctx context.Context) (Status, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	s, err := a.client.Status(ctx)
	if err != nil {
		return s, fmt.Errorf("tailnet: LocalAPI unavailable: %w", err)
	}
	if !s.Running || len(s.SelfIPs) == 0 {
		return s, errors.New("tailnet: node must be Running with a Tailscale address")
	}
	return s, nil
}

// Resolve never substitutes a wildcard when no matching self address exists.
func Resolve(peer string, s Status) (string, error) {
	host, port, err := net.SplitHostPort(peer)
	if err != nil {
		return "", err
	}
	if host != "tailnet" && host != "tailnet6" {
		return peer, nil
	}
	for _, ip := range s.SelfIPs {
		ip = ip.Unmap()
		if IsTailnetIP(ip) && ip.Is4() == (host == "tailnet") {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	return "", errors.New("tailnet: no self address for requested family")
}

// IsTailnetBind reports a current self address, including resolved aliases.
func IsTailnetBind(peer string, s Status) bool {
	resolved, err := Resolve(peer, s)
	return err == nil && SelfBind(resolved, s)
}
func SelfBind(peer string, s Status) bool {
	host, _, err := net.SplitHostPort(peer)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, self := range s.SelfIPs {
		if ip.Unmap() == self.Unmap() && IsTailnetIP(ip) {
			return true
		}
	}
	return false
}
func addr(a net.Addr) (netip.AddrPort, error) {
	if a == nil {
		return netip.AddrPort{}, errors.New("missing socket address")
	}
	p, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return p, err
	}
	return netip.AddrPortFrom(p.Addr().Unmap(), p.Port()), nil
}

// Authorize writes no bytes. Callers close denied connections before protocol work.
func (a *Authorizer) Authorize(ctx context.Context, c net.Conn) error {
	local, le := addr(c.LocalAddr())
	remote, re := addr(c.RemoteAddr())
	if le != nil || re != nil {
		return a.deny(remote.Addr(), "", "invalid socket address")
	}
	if a.policy.AllowLoopback && local.Addr().IsLoopback() && remote.Addr().IsLoopback() {
		return nil
	}
	if !IsTailnetIP(remote.Addr()) {
		return a.deny(remote.Addr(), "", "remote is outside tailnet ranges")
	}
	a.mu.Lock()
	until := a.denied[remote.Addr()]
	a.mu.Unlock()
	if a.now().Before(until) {
		return a.deny(remote.Addr(), "", "cached denial")
	}
	f := a.lookup(ctx, remote)
	if f.err != nil {
		return a.deny(remote.Addr(), f.identity.StableID, "identity lookup failed")
	}
	if !SelfBind(local.String(), f.status) {
		return a.deny(remote.Addr(), f.identity.StableID, "ingress is not a self Tailscale address")
	}
	id := f.identity
	if id.StableID == "" || len(id.Addresses) == 0 {
		return a.deny(remote.Addr(), id.StableID, "missing identity fields")
	}
	bound := false
	for _, prefix := range id.Addresses {
		if !prefix.IsValid() || prefix.Bits() != prefix.Addr().BitLen() {
			return a.deny(remote.Addr(), id.StableID, "invalid node address")
		}
		if prefix.Addr().Unmap() == remote.Addr() {
			bound = true
		}
	}
	if !bound {
		return a.reject(remote.Addr(), id.StableID, "identity address mismatch")
	}
	if slices.Contains(a.policy.AllowNodes, id.StableID) {
		return nil
	}
	for _, tag := range id.Tags {
		if slices.Contains(a.policy.AllowTags, tag) {
			return nil
		}
	}
	if len(id.Tags) == 0 && id.UserID != "" && slices.Contains(a.policy.AllowUserIDs, id.UserID) {
		return nil
	}
	return a.reject(remote.Addr(), id.StableID, "identity not allowed")
}
func (a *Authorizer) reject(ip netip.Addr, id, reason string) error {
	a.mu.Lock()
	// Bound memory even during a scan. Eviction can only cause a fresh lookup.
	if len(a.denied) >= 1024 {
		clear(a.denied)
	}
	a.denied[ip] = a.now().Add(15 * time.Second)
	a.mu.Unlock()
	return a.deny(ip, id, reason)
}
func (a *Authorizer) deny(ip netip.Addr, id, reason string) error {
	a.mu.Lock()
	now := a.now()
	emit := a.lastLog.IsZero() || now.Sub(a.lastLog) >= time.Second
	if emit {
		a.lastLog = now
	}
	a.mu.Unlock()
	if emit {
		log.Printf("tailnet deny remote=%s stable_id=%q reason=%s", ip, id, reason)
	}
	return errors.New("tailnet: connection denied")
}
func (a *Authorizer) lookup(ctx context.Context, remote netip.AddrPort) *flight {
	if err := ctx.Err(); err != nil {
		return &flight{err: err}
	}
	a.mu.Lock()
	f := a.flights[remote]
	if f == nil {
		// Acquire before spawning so unique sockets cannot create unbounded workers.
		select {
		case lookupSlots <- struct{}{}:
			f = &flight{done: make(chan struct{})}
			a.flights[remote] = f
			go a.runLookup(context.WithoutCancel(ctx), remote, f)
		default:
			a.mu.Unlock()
			return &flight{err: errors.New("authorization capacity reached")}
		}
	}
	a.mu.Unlock()
	select {
	case <-ctx.Done():
		return &flight{err: ctx.Err()}
	case <-f.done:
		if err := ctx.Err(); err != nil {
			return &flight{err: err}
		}
		return f
	}
}
func (a *Authorizer) runLookup(ctx context.Context, remote netip.AddrPort, f *flight) {
	defer func() {
		a.mu.Lock()
		delete(a.flights, remote)
		<-lookupSlots
		close(f.done)
		a.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	f.status, f.err = a.client.Status(ctx)
	if f.err == nil && !f.status.Running {
		f.err = errors.New("node is not Running")
	}
	if f.err == nil {
		f.identity, f.err = a.client.WhoIs(ctx, remote.String())
	}
}
