package doctor

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"

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
	if runtime.GOOS == "windows" {
		t.Skip("unix key modes are not enforced on windows")
	}
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

func TestIsLoopbackBind(t *testing.T) {
	cases := []struct {
		peer string
		want bool
	}{
		{"127.0.0.1:8787", true},
		{"[::1]:8787", true},
		{"localhost:8787", true},
		{":8787", true},
		{"0.0.0.0:8787", false},
		{"192.0.2.10:8787", false},
		{"example.com:8787", false},
		{"not-host-port", false},
	}
	for _, tc := range cases {
		if got := IsLoopbackBind(tc.peer); got != tc.want {
			t.Errorf("IsLoopbackBind(%q) = %v, want %v", tc.peer, got, tc.want)
		}
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

func TestCaptureLocalStorageOnNonCDPFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{
			Kind: "firefox", Profile: "p", CookiePath: filepath.Join(dir, "cookies.sqlite"),
			CaptureLocalStorage: true,
		}},
	}
	if find(Run(c), "localstorage:p").Status != Fail {
		t.Fatal("capture_localstorage on a non-cdp browser must Fail")
	}
}

func TestCaptureLocalStorageOnCDPReports(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()
	c := config.Config{
		Role: "source", Peer: "127.0.0.1:8787", KeyPath: key,
		Browsers: []config.BrowserRef{{Kind: "cdp", Profile: "p", URL: srv.URL, CaptureLocalStorage: true}},
	}
	if find(Run(c), "localstorage:p").Status != OK {
		t.Fatal("capture_localstorage on a reachable cdp browser must report OK")
	}
}

func TestSourcePeerNoneConfigPasses(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{Role: "source", Peer: "none", KeyPath: key}
	ck := find(Run(c), "config")
	if ck.Status != OK {
		t.Fatalf("source peer none must be valid, got %+v", ck)
	}
}

func TestSinkPeerNoneConfigFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{Role: "sink", Peer: "none", KeyPath: key, Surfaces: []string{"sidecar"}}
	ck := find(Run(c), "config")
	if ck.Status != Fail {
		t.Fatalf("sink peer none must fail validation, got %+v", ck)
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
	if runtime.GOOS == "windows" {
		t.Skip("0000 directory modes do not block access on windows")
	}
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

func TestStorageStateAdapterWritableParentOK(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"},
		Adapters: []config.AdapterRef{{Type: "storagestate", Path: filepath.Join(dir, "state.json")}},
	}
	if find(Run(c), "adapter:storagestate").Status != OK {
		t.Fatal("storagestate adapter with writable parent must be OK")
	}
}

func TestStorageStateAdapterMissingPathFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{
		Role: "sink", Peer: "127.0.0.1:8787", KeyPath: key, Surfaces: []string{"sidecar"},
		Adapters: []config.AdapterRef{{Type: "storagestate"}},
	}
	if find(Run(c), "adapter:storagestate").Status != Fail {
		t.Fatal("storagestate adapter without a path must Fail")
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
	if runtime.GOOS == "windows" {
		t.Skip("chromium keys use DPAPI on windows; no keyring check is emitted")
	}
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

// writeDoctorVault mirrors internal/keepass's test helper (unexported by
// design): a KDBX4 vault with one agentpantry-tagged entry, key-file unlock.
func writeDoctorVault(t *testing.T, dir string) (vaultPath, keyPath string) {
	t.Helper()
	keyPath = filepath.Join(dir, "vault.key")
	if err := os.WriteFile(keyPath, []byte("doctor-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := gokeepasslib.NewKeyDataCredentials([]byte("doctor-key-material"))
	if err != nil {
		t.Fatal(err)
	}
	e := gokeepasslib.NewEntry()
	e.Values = append(e.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "API_KEY"}},
		gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: "v", Protected: w.NewBoolWrapper(true)}},
	)
	e.Tags = "agentpantry"
	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Entries = append(root.Entries, e)
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Credentials = creds
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}}
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	vaultPath = filepath.Join(dir, "vault.kdbx")
	f, err := os.Create(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	return vaultPath, keyPath
}

func TestKeepassVaultMissingFails(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	c := config.Config{Role: "source", KeyPath: key, KeepassPath: filepath.Join(dir, "nope.kdbx")}
	ck := find(Run(c), "keepass")
	if ck.Status != Fail {
		t.Fatalf("missing vault must Fail, got %+v", ck)
	}
}

func TestKeepassHealthyReportsCount(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 0o600)
	vault, vaultKey := writeDoctorVault(t, dir)
	c := config.Config{Role: "source", KeyPath: key, KeepassPath: vault, KeepassKeyfile: vaultKey}
	ck := find(Run(c), "keepass")
	if ck.Status != OK || !strings.Contains(ck.Detail, "1 secret") {
		t.Fatalf("healthy vault must report the tagged count, got %+v", ck)
	}
}
