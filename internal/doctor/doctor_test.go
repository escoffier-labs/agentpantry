package doctor

import (
	"net"
	"os"
	"path/filepath"
	"strings"
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

type fakeKP struct {
	pass string
	err  error
}

func (f fakeKP) Passphrase() (string, error) { return f.pass, f.err }

func TestKeyringCheck(t *testing.T) {
	if KeyringCheck(fakeKP{pass: "peanuts"}).Status != Warn {
		t.Fatal("peanuts fallback must Warn")
	}
	if KeyringCheck(fakeKP{pass: "realpass"}).Status != OK {
		t.Fatal("a resolved keyring passphrase must be OK")
	}
	if KeyringCheck(fakeKP{err: errProbe}).Status != Fail {
		t.Fatal("a keyring error must Fail")
	}
	// The resolved passphrase must never appear in the detail.
	if d := KeyringCheck(fakeKP{pass: "realpass"}).Detail; strings.Contains(d, "realpass") {
		t.Fatalf("passphrase leaked into detail: %q", d)
	}
}

func TestSidecarSurfaceWritable(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgDir)
	key := writeKey(t, cfgDir, 0o600)
	c := config.Config{Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"}}
	if find(Run(c), "surface:sidecar").Status != OK {
		t.Fatal("writable config dir must yield sidecar OK")
	}
}

func TestSidecarSurfaceUnwritableFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	cfgDir := t.TempDir()
	locked := filepath.Join(cfgDir, "agentpantry")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o700) })
	t.Setenv("XDG_CONFIG_HOME", cfgDir)
	key := writeKey(t, cfgDir, 0o600)
	c := config.Config{Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"}}
	if find(Run(c), "surface:sidecar").Status != Fail {
		t.Fatal("unwritable sidecar dir must Fail")
	}
}

func TestAdapterUnknownTypeFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"},
		Adapters: []config.AdapterRef{{Type: "bogus", Path: filepath.Join(dir, "x")}},
	}
	if find(Run(c), "adapter:bogus").Status != Fail {
		t.Fatal("unknown adapter type must Fail")
	}
}

func TestAdapterWritableParentOK(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"},
		Adapters: []config.AdapterRef{{Type: "netscape", Path: filepath.Join(dir, "cookies.txt")}},
	}
	if find(Run(c), "adapter:netscape").Status != OK {
		t.Fatal("netscape adapter with writable parent must be OK")
	}
}

func TestHermesAdapterWritableBundleDirOK(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"},
		Adapters: []config.AdapterRef{{Type: "hermes", Path: filepath.Join(dir, ".hermes", "agentpantry")}},
	}
	if got := find(Run(c), "adapter:hermes"); got.Status != OK {
		t.Fatalf("hermes adapter with creatable bundle dir must be OK, got %+v", got)
	}
}

func TestHermesAdapterNeedsPath(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"},
		Adapters: []config.AdapterRef{{Type: "hermes"}},
	}
	if got := find(Run(c), "adapter:hermes"); got.Status != Fail {
		t.Fatalf("hermes adapter without path must fail, got %+v", got)
	}
}

var errProbe = errProbeType("boom")

type errProbeType string

func (e errProbeType) Error() string { return string(e) }

func TestPureFirefoxSourceHasNoKeyringCheck(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	ff := filepath.Join(dir, "cookies.sqlite")
	os.WriteFile(ff, []byte("x"), 0o600)
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{Kind: "firefox", Profile: "p", CookiePath: ff}},
	}
	if find(Run(c), "keyring").Status != -1 {
		t.Fatal("a pure-firefox source must not emit a keyring check")
	}
}

func TestChromiumSourceStillHasKeyringCheck(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	cp := filepath.Join(dir, "Cookies")
	os.WriteFile(cp, []byte("x"), 0o600)
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{Kind: "chromium", Profile: "p", CookiePath: cp}},
	}
	if find(Run(c), "keyring").Status == -1 {
		t.Fatal("a chromium source must still emit a keyring check")
	}
}

func TestCDPBrowserReachabilityCheck(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{Kind: "cdp", Profile: "p", URL: "http://127.0.0.1:1"}},
	}
	if find(Run(c), "cdp:p").Status != Fail {
		t.Fatal("unreachable cdp endpoint must Fail")
	}
}

func TestCDPBrowserNonLoopbackFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{Kind: "cdp", Profile: "p", URL: "http://198.51.100.10:9222"}},
	}
	if find(Run(c), "cdp:p").Status != Fail {
		t.Fatal("non-loopback cdp endpoint must Fail")
	}
}
