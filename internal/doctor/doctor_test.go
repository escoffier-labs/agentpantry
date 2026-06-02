package doctor

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/keyfile"
)

func writeKey(t *testing.T, dir string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, "psk.key")
	if err := keyfile.Generate(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
	return p
}

func find(checks []Check, name string) Check {
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	return Check{Name: name, Status: -1}
}

func TestHealthySinkConfigPasses(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"}}
	checks := Run(c)
	for _, ck := range checks {
		if ck.Status == Fail {
			t.Fatalf("healthy config produced a Fail: %+v", ck)
		}
	}
}

func TestBadKeyPermFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o644)
	c := config.Config{Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"}}
	if find(Run(c), "key").Status != Fail {
		t.Fatal("0644 key must Fail")
	}
}

func TestNonLoopbackBindWarns(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{Role: "sink", Peer: "0.0.0.0:8787", KeyPath: key, Surfaces: []string{"sidecar"}}
	if find(Run(c), "bind").Status != Warn {
		t.Fatal("non-loopback bind must Warn")
	}
}

func TestUnknownSurfaceFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"bogus"}}
	if find(Run(c), "surface:bogus").Status != Fail {
		t.Fatal("unknown surface must Fail")
	}
}

func TestSourceMissingCookieStoreFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{Kind: "chromium", Profile: "p", CookiePath: filepath.Join(dir, "nope", "Cookies")}},
	}
	if find(Run(c), "vault:p").Status != Fail {
		t.Fatal("missing cookie store must Fail")
	}
}

func TestHasFailHelper(t *testing.T) {
	if HasFail([]Check{{Status: OK}, {Status: Warn}}) {
		t.Fatal("no Fail present")
	}
	if !HasFail([]Check{{Status: Fail}}) {
		t.Fatal("Fail present")
	}
}

func TestPeerReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if PeerReachable(ln.Addr().String(), time.Second).Status != OK {
		t.Fatal("listening peer must be reachable")
	}
}

func TestPeerUnreachable(t *testing.T) {
	// Port 1 on loopback is not listening.
	if PeerReachable("127.0.0.1:1", 500*time.Millisecond).Status != Fail {
		t.Fatal("closed port must be unreachable")
	}
}
