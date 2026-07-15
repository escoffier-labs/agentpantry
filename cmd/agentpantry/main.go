package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/browser"
	"github.com/escoffier-labs/agentpantry/internal/cdpvault"
	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/doctor"
	"github.com/escoffier-labs/agentpantry/internal/ffvault"
	"github.com/escoffier-labs/agentpantry/internal/keepass"
	"github.com/escoffier-labs/agentpantry/internal/keyfile"
	"github.com/escoffier-labs/agentpantry/internal/policy"
	"github.com/escoffier-labs/agentpantry/internal/secretsrc"
	"github.com/escoffier-labs/agentpantry/internal/service"
	"github.com/escoffier-labs/agentpantry/internal/sink"
	"github.com/escoffier-labs/agentpantry/internal/source"
	"github.com/escoffier-labs/agentpantry/internal/state"
	"github.com/escoffier-labs/agentpantry/internal/surface"
	"github.com/escoffier-labs/agentpantry/internal/transport"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "keygen":
		err = cmdKeygen(args)
	case "source":
		err = cmdSource(args)
	case "sink":
		err = cmdSink(args)
	case "install-service":
		err = cmdInstallService(args)
	case "doctor":
		err = cmdDoctor(args)
	case "status":
		err = cmdStatus(args)
	case "inventory":
		err = cmdInventory(args)
	case "restore":
		err = cmdRestore(args)
	case "browser":
		err = cmdBrowser(args)
	case "version":
		err = cmdVersion(args)
	case "rotate-key":
		err = cmdRotateKey(args)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

const usageText = `agentpantry - secure browser session and secret sync for AI agents

usage: agentpantry <command> [flags]

commands:
  init             write a commented starter config (-role source|sink)
  keygen           generate the pre-shared key both endpoints share
  rotate-key       rotate the pre-shared key in place; -finish retires the old key
  source           run on the daily driver: watch browsers, push sealed diffs
  sink             run on the agent machine: receive diffs, apply to surfaces
  doctor           validate the config, key, and role-specific setup
  status           print the active role, peer, surfaces, and last sync
  inventory        summarize a backup store: per-host counts and near-expiry
  restore          materialize cookies from a sidecar backup to one target
  browser          launch an automation Chrome pre-seeded with a session
  install-service  install a systemd user unit (Windows: print a task command)
  version          print version and build metadata

Run 'agentpantry <command> -h' for command flags.
Quickstart: https://github.com/escoffier-labs/agentpantry#quickstart
`

func usage() {
	fmt.Fprint(os.Stderr, usageText)
	os.Exit(2)
}

func cmdVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	payload := map[string]string{
		"version":    version,
		"commit":     commit,
		"build_date": buildDate,
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}
	if *jsonOut {
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("agentpantry %s\ncommit: %s\nbuilt:  %s\ngo:     %s\nos/arch: %s/%s\n",
		version, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	role := fs.String("role", "source", "source or sink")
	out := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	force := fs.Bool("force", false, "overwrite an existing config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *role != "source" && *role != "sink" {
		return fmt.Errorf("role must be source or sink")
	}
	if !*force {
		// Stat-then-write is racy, but init is a single-operator command
		// guarding against accidental overwrite, not a concurrent writer.
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("config already exists at %s (pass -force to overwrite)", *out)
		}
	}
	if err := config.WriteTemplate(*out, *role); err != nil {
		return err
	}
	fmt.Printf("wrote %s config to %s\nedit it, then run `agentpantry doctor` to validate\n", *role, *out)
	return nil
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", filepath.Join(config.Dir(), "psk.key"), "key path")
	backup := fs.Bool("backup", true, "back up an existing key before replacing it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	backupPath, err := keyfile.GenerateWithBackup(*out, *backup)
	if err != nil {
		return err
	}
	if backupPath != "" {
		fmt.Printf("backed up previous PSK to %s\n", backupPath)
		fmt.Println("delete the backup once the rotation is confirmed; it is live key history, especially if you rotated because the old key may have been exposed")
	}
	fmt.Printf("wrote 32-byte PSK to %s (copy this file to the peer)\n", *out)
	return nil
}

func cmdRotateKey(args []string) error {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	finish := fs.Bool("finish", false, "retire the old key, ending the grace window")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Resolve the key path from the config when one exists; otherwise rotate
	// the default key location, mirroring keygen's default.
	keyPath := filepath.Join(config.Dir(), "psk.key")
	if _, statErr := os.Stat(*cfgPath); statErr == nil {
		c, err := loadConfigWarn(*cfgPath)
		if err != nil {
			return err
		}
		if c.KeyPath != "" {
			keyPath = c.KeyPath
		}
		if c.Role == "source" {
			fmt.Fprintln(os.Stderr, "warning: rotation is meant to run on the sink, which accepts both keys during the grace window; a source holds only one key")
		}
	}
	if *finish {
		if err := keyfile.FinishRotation(keyPath); err != nil {
			return err
		}
		fmt.Printf("rotation finished: removed %s; only the current key is accepted now\n", keyfile.OldKeyPath(keyPath))
		return nil
	}
	oldPath, err := keyfile.Rotate(keyPath)
	if err != nil {
		return err
	}
	fmt.Printf(`rotated PSK at %s
old key preserved at %s

the sink accepts both keys for new connections, so sync keeps working:
  1. copy the new %s to the source machine
  2. restart the source (or let it reconnect)
  3. run 'agentpantry rotate-key -finish' here to retire %s
`, keyPath, oldPath, keyPath, oldPath)
	return nil
}

func loadConfig(args []string) (config.Config, error) {
	fs := flag.NewFlagSet("cfg", flag.ExitOnError)
	path := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	return loadConfigWarn(*path)
}

// loadConfigWarn loads path and prints a stderr warning for each config key
// the schema does not recognize, so a typo or a key placed under the wrong
// section is not silently ignored.
func loadConfigWarn(path string) (config.Config, error) {
	c, unknown, err := config.LoadChecked(path)
	if err != nil {
		return c, err
	}
	for _, k := range unknown {
		fmt.Fprintf(os.Stderr, "warning: unknown config key %q ignored (check spelling and section placement)\n", k)
	}
	return c, nil
}

// statePath puts state.json beside the resolved config file so two sources with
// different configs do not stomp a single shared state.
func statePath(cfgPath string) string {
	return filepath.Join(filepath.Dir(cfgPath), "state.json")
}

func buildVaults(c config.Config) ([]source.CookieReader, []string, error) {
	var vs []source.CookieReader
	var paths []string
	for _, b := range c.Browsers {
		switch b.Kind {
		case "chromium":
			vs = append(vs, newChromiumReader(b))
		case "firefox":
			vs = append(vs, &ffvault.Firefox{Profile: b.Profile, CookiePath: b.CookiePath})
		case "cdp":
			if err := cdpvault.ValidateLoopbackURL(b.URL, "http", "https"); err != nil {
				return nil, nil, fmt.Errorf("cdp browser %q must use a loopback URL: %w", b.Profile, err)
			}
			vs = append(vs, &cdpvault.CDP{BaseURL: b.URL})
		default:
			return nil, nil, fmt.Errorf("unsupported browser kind %q (supported: chromium, firefox, cdp)", b.Kind)
		}
		// cdp has no local file to watch; it syncs at startup and on other
		// browsers' file events.
		if b.Kind != "cdp" {
			paths = append(paths, b.CookiePath)
		}
	}
	return vs, paths, nil
}

func cmdSource(args []string) error {
	fs := flag.NewFlagSet("source", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	stdio := fs.Bool("stdio", false, "stream frames to stdout instead of dialing the peer")
	once := fs.Bool("once", false, "sync once, then close the connection and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := loadConfigWarn(*cfgPath)
	if err != nil {
		return err
	}
	if c.Peerless() {
		return errors.New("peerless config is for external-scheduler/doctor use and cannot run the sync loop because operators drive capture with explicit per-profile -config pairs")
	}
	key, err := keyfile.Load(c.KeyPath)
	if err != nil {
		return err
	}
	vs, paths, err := buildVaults(c)
	if err != nil {
		return err
	}
	// Advisory near-expiry check on startup. Read-only sync cannot renew a
	// session; this only surfaces a looming re-auth and never blocks syncing.
	if c.WarnExpiryDays > 0 {
		within := time.Duration(c.WarnExpiryDays) * 24 * time.Hour
		warnSourceExpiry(context.Background(), vs, c.Domains, within, time.Now())
	}
	var secretReaders []source.SecretReader
	if c.SecretsDir != "" {
		secretReaders = append(secretReaders, &secretsrc.DirReader{Dir: c.SecretsDir})
		if _, statErr := os.Stat(c.SecretsDir); statErr == nil {
			paths = append(paths, c.SecretsDir)
		}
	}
	if c.KeepassPath != "" {
		secretReaders = append(secretReaders, &keepass.Reader{
			Path:     c.KeepassPath,
			Keyfile:  c.KeepassKeyfile,
			PassFile: c.KeepassPassFile,
			Tag:      c.KeepassTagOrDefault(),
		})
		if _, statErr := os.Stat(c.KeepassPath); statErr == nil {
			paths = append(paths, c.KeepassPath) // a vault save triggers a resync
		}
	}

	var storageReaders []source.StorageReader
	for _, b := range c.Browsers {
		if !b.CaptureLocalStorage {
			continue
		}
		if b.Kind != "cdp" {
			return fmt.Errorf("capture_localstorage is only supported for kind = \"cdp\" browsers, not %q", b.Kind)
		}
		storageReaders = append(storageReaders, &cdpvault.CDP{BaseURL: b.URL})
	}

	resync := time.Duration(c.ResyncSeconds) * time.Second
	hasCDP := false
	for _, b := range c.Browsers {
		if b.Kind == "cdp" {
			hasCDP = true
		}
	}
	if hasCDP && resync == 0 && !*once {
		resync = 60 * time.Second
		fmt.Fprintln(os.Stderr, "agentpantry: cdp source detected, defaulting resync to 60s")
	}

	clock := state.RealClock{}
	sp := statePath(*cfgPath)
	syncer := &source.Syncer{
		Vaults:       vs,
		Secrets:      secretReaders,
		Storage:      storageReaders,
		Policy:       c.Domains,
		SecretPolicy: c.SecretNames,
		AfterSync: func(sent bool, cookies, secrets, storage int) {
			st, _ := state.Load(sp)
			now := clock.Now().Unix()
			st.LastSyncUnix = now
			if sent {
				st.LastSentUnix = now
				st.Cookies = cookies
				st.Secrets = secrets
				st.Storage = storage
			}
			if err := state.Save(sp, st); err != nil {
				fmt.Fprintln(os.Stderr, "warning: could not write state:", err)
			}
		},
	}
	ctx := signalCtx()
	syncOnce := func() error {
		syncer.Reset()
		return syncer.SyncOnce(ctx)
	}

	if *stdio {
		salt, serr := transport.SendSalt(os.Stdout)
		if serr != nil {
			return serr
		}
		sealer, serr := transport.NewSealer(key, salt)
		if serr != nil {
			return serr
		}
		syncer.Sealer = sealer
		syncer.Out = os.Stdout
		if *once {
			fmt.Fprintf(os.Stderr, "source: syncing once from %d store(s), streaming frame to stdout\n", len(paths))
			return syncOnce()
		}
		fmt.Fprintf(os.Stderr, "source: watching %d store(s), streaming frames to stdout\n", len(paths))
		return syncer.Watch(ctx, paths, 500*time.Millisecond, resync)
	}

	// TCP: reconnect with capped backoff so a sink restart or blip recovers.
	if *once {
		fmt.Printf("source: syncing once from %d store(s), pushing to %s\n", len(paths), c.Peer)
		conn, derr := net.Dial("tcp", c.Peer)
		if derr != nil {
			return derr
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
			return err
		}
		salt, herr := transport.RecvSalt(conn)
		if herr != nil {
			return herr
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		sealer, serr := transport.NewSealer(key, salt)
		if serr != nil {
			return serr
		}
		syncer.Sealer = sealer
		syncer.Out = conn
		return syncOnce()
	}

	fmt.Printf("source: watching %d store(s), pushing to %s\n", len(paths), c.Peer)
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		conn, derr := net.Dial("tcp", c.Peer)
		if derr != nil {
			if !sleepCtx(ctx, source.Backoff(attempt)) {
				return nil
			}
			attempt++
			continue
		}
		if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
			_ = conn.Close()
			return err
		}
		salt, herr := transport.RecvSalt(conn)
		if herr != nil {
			_ = conn.Close()
			if !sleepCtx(ctx, source.Backoff(attempt)) {
				return nil
			}
			attempt++
			continue
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			_ = conn.Close()
			return err
		}
		sealer, serr := transport.NewSealer(key, salt)
		if serr != nil {
			_ = conn.Close()
			return serr
		}
		syncer.Sealer = sealer
		syncer.Out = conn
		syncer.Reset()
		attempt = 0
		werr := syncer.Watch(ctx, paths, 500*time.Millisecond, resync)
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil
		}
		fmt.Fprintln(os.Stderr, "source: connection lost, reconnecting:", werr)
		if !sleepCtx(ctx, source.Backoff(attempt)) {
			return nil
		}
		attempt++
	}
}

// warnNearExpiry writes one advisory line per cookie expiring within the window
// and returns how many it named. The sync is read-only and cannot renew a
// session, so this only makes a looming re-auth visible; true auto-refresh
// (re-navigating the site to renew the cookie) is a future feature outside the
// read-only sync scope. Returns 0 and writes nothing when nothing is due.
func warnNearExpiry(w io.Writer, cookies []cookie.Cookie, within time.Duration, now time.Time) int {
	due := cookie.NearExpiry(cookies, within, now)
	days := int(within / (24 * time.Hour))
	for _, c := range due {
		when := time.Unix(cookie.ExpiresUnix(c.ExpiresUTC), 0).UTC().Format("2006-01-02")
		fmt.Fprintf(w, "warning: cookie %s@%s expires %s (within %dd); re-auth needed\n", c.Name, c.Host, when, days)
	}
	return len(due)
}

// warnSourceExpiry does a one-shot read of the source vaults and warns about any
// cookies expiring within the configured window. It is advisory and never blocks
// syncing: read errors are reported and skipped.
func warnSourceExpiry(ctx context.Context, vaults []source.CookieReader, p policy.Domain, within time.Duration, now time.Time) {
	for _, v := range vaults {
		cs, err := v.ReadCookies(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not read cookies for expiry check:", err)
			continue
		}
		var permitted []cookie.Cookie
		for _, c := range cs {
			if p.Permit(c.Host) {
				permitted = append(permitted, c)
			}
		}
		warnNearExpiry(os.Stderr, permitted, within, now)
	}
}

// sleepCtx waits d or until ctx is done; returns false if ctx was cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// handshakeTimeout bounds the per-connection salt exchange so a stuck or
// malicious peer cannot wedge the sink's accept loop.
const handshakeTimeout = 10 * time.Second

// authTimeout bounds the wait for a connection's first authenticated frame.
// The source syncs immediately after connecting, so a legitimate peer
// authenticates well within this; anyone else is reaped.
const authTimeout = 30 * time.Second

// maxSinkConns caps concurrently served sink connections.
const maxSinkConns = 32

// newSinkOpener derives a per-session opener, re-reading the key files so a
// key rotation takes effect for new connections without a sink restart.
// During a rotation grace window (a psk.key.old beside the key) frames are
// accepted under either key, new key first, and an old-key session logs a
// reminder to finish the rotation.
func newSinkOpener(keyPath string, salt []byte) (sink.FrameOpener, error) {
	key, err := keyfile.Load(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}
	oldPath := keyfile.OldKeyPath(keyPath)
	if _, statErr := os.Lstat(oldPath); statErr != nil {
		return transport.NewOpener(key, salt)
	}
	oldKey, err := keyfile.Load(oldPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: rotation in progress but old key at %s is unusable (%v); accepting only the current key\n", oldPath, err)
		return transport.NewOpener(key, salt)
	}
	fo, err := transport.NewFallbackOpener(key, oldKey, salt)
	if err != nil {
		return nil, err
	}
	fo.OnFallback = func() {
		fmt.Fprintln(os.Stderr, "sink: WARN peer authenticated with the pre-rotation key; update the source's key, then run 'agentpantry rotate-key -finish'")
	}
	return fo, nil
}

// sidecarDBPath returns the sidecar surface DB path: the configured override
// when set, otherwise sidecar.db in the config dir. Letting each sink pin its
// own store avoids the per-profile XDG_CONFIG_HOME juggling that otherwise
// collides identities.
func sidecarDBPath(c config.Config) string {
	if c.SidecarPath != "" {
		return c.SidecarPath
	}
	return filepath.Join(config.Dir(), "sidecar.db")
}

func cmdSink(args []string) error {
	fs := flag.NewFlagSet("sink", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	stdio := fs.Bool("stdio", false, "read frames from stdin instead of listening on a port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := loadConfigWarn(*cfgPath)
	if err != nil {
		return err
	}
	// Fail fast on an unusable key, but load per session below so rotation
	// takes effect without a restart.
	if _, err := keyfile.Load(c.KeyPath); err != nil {
		return err
	}

	var cookieSurfaces []sink.CookieSurface
	var secretSurfaces []sink.SecretSurface
	var storageSurfaces []sink.StorageSurface
	var closers []func() error

	for _, name := range c.Surfaces {
		switch name {
		case "sidecar":
			sc, err := surface.NewSidecar(sidecarDBPath(c))
			if err != nil {
				return err
			}
			cookieSurfaces = append(cookieSurfaces, sc)
			storageSurfaces = append(storageSurfaces, sc)
			closers = append(closers, sc.Close)
		case "chrome":
			if len(c.Browsers) == 0 {
				return fmt.Errorf("chrome surface requires a [[browsers]] entry with cookie_path")
			}
			cs, closeFn, err := newChromeSurface(c.Browsers[0].CookiePath)
			if err != nil {
				return err
			}
			cookieSurfaces = append(cookieSurfaces, cs)
			closers = append(closers, closeFn)
		case "secrets":
			if c.SecretsDir == "" {
				return fmt.Errorf("secrets surface requires secrets_dir in config")
			}
			sd, err := surface.NewSecretDir(c.SecretsDir)
			if err != nil {
				return err
			}
			secretSurfaces = append(secretSurfaces, sd)
		default:
			return fmt.Errorf("unknown surface %q", name)
		}
	}
	for _, a := range c.Adapters {
		switch a.Type {
		case "netscape":
			ns, err := surface.NewNetscape(a.Path)
			if err != nil {
				return err
			}
			cookieSurfaces = append(cookieSurfaces, ns)
		case "storagestate":
			ss, err := surface.NewStorageState(a.Path)
			if err != nil {
				return err
			}
			cookieSurfaces = append(cookieSurfaces, ss)
			storageSurfaces = append(storageSurfaces, ss)
		case "gh":
			gh, err := surface.NewGHHosts(a.Path, a.Secret, a.Host, a.User)
			if err != nil {
				return err
			}
			secretSurfaces = append(secretSurfaces, gh)
		case "openclaw":
			oc, err := surface.NewOpenClawAuth(a.Path, a.Profiles)
			if err != nil {
				return err
			}
			secretSurfaces = append(secretSurfaces, oc)
		case "hermes":
			h, err := surface.NewHermesBundle(a.Path)
			if err != nil {
				return err
			}
			cookieSurfaces = append(cookieSurfaces, h)
			secretSurfaces = append(secretSurfaces, h)
		default:
			return fmt.Errorf("unknown adapter type %q", a.Type)
		}
	}
	defer func() {
		for _, cl := range closers {
			if err := cl(); err != nil {
				fmt.Fprintln(os.Stderr, "warning: close failed:", err)
			}
		}
	}()

	ctx := signalCtx()

	if *stdio {
		// Close stdin on signal so a blocking read (handshake or frame) unblocks.
		go func() {
			<-ctx.Done()
			_ = os.Stdin.Close()
		}()
		// One-way pipe: the source issued the salt as the first frame.
		salt, herr := transport.RecvSalt(os.Stdin)
		if herr != nil {
			return fmt.Errorf("handshake: %w", herr)
		}
		opener, oerr := newSinkOpener(c.KeyPath, salt)
		if oerr != nil {
			return oerr
		}
		srv := &sink.Server{Opener: opener, CookieSurfaces: cookieSurfaces, SecretSurfaces: secretSurfaces, StorageSurfaces: storageSurfaces}
		fmt.Fprintf(os.Stderr, "sink: reading frames from stdin, surfaces %v\n", c.Surfaces)
		return srv.Serve(ctx, os.Stdin)
	}

	// Mirror doctor's bind check at the moment it matters: a wide bind hands
	// the network an unauthenticated pre-auth surface (connection slots, frame
	// allocations, key probing) even though frames still require the PSK.
	if !doctor.IsLoopbackBind(c.Peer) {
		fmt.Fprintf(os.Stderr, "warning: binding %s exposes the sink beyond loopback\n", c.Peer)
	}

	ln, err := net.Listen("tcp", c.Peer)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	fmt.Printf("sink: listening on %s, surfaces %v\n", c.Peer, c.Surfaces)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	// Serve each connection in its own goroutine so one stalled peer cannot
	// block new sources, bounded by a semaphore so an accept flood cannot spawn
	// unbounded goroutines. Surface application stays serialized via a shared
	// mutex: surfaces are not safe for concurrent use.
	var applyMu sync.Mutex
	sem := make(chan struct{}, maxSinkConns)
	for {
		// Acquire a slot before accepting so a just-accepted connection is never
		// parked without deadlines waiting for capacity, and shutdown is not
		// blocked behind a full semaphore.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		conn, err := ln.Accept()
		if err != nil {
			<-sem
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func(conn net.Conn) {
			defer func() { <-sem }()
			defer func() { _ = conn.Close() }()
			// Issue a fresh per-connection salt so frames from one session cannot
			// be replayed into another, and so a reconnecting source is not
			// rejected. Bound the handshake write so a stuck peer is reaped.
			if err := conn.SetWriteDeadline(time.Now().Add(handshakeTimeout)); err != nil {
				fmt.Fprintln(os.Stderr, "handshake deadline failed:", err)
				return
			}
			salt, herr := transport.SendSalt(conn)
			if herr != nil {
				fmt.Fprintln(os.Stderr, "handshake failed:", herr)
				return
			}
			if err := conn.SetWriteDeadline(time.Time{}); err != nil { // clear; Serve is a long-lived stream
				return
			}
			opener, oerr := newSinkOpener(c.KeyPath, salt)
			if oerr != nil {
				fmt.Fprintln(os.Stderr, "session setup failed:", oerr)
				return
			}
			srv := &sink.Server{
				Opener:          opener,
				CookieSurfaces:  cookieSurfaces,
				SecretSurfaces:  secretSurfaces,
				StorageSurfaces: storageSurfaces,
				AuthTimeout:     authTimeout,
				ApplyMu:         &applyMu,
			}
			if err := srv.Serve(ctx, conn); err != nil {
				fmt.Fprintln(os.Stderr, "connection ended:", err)
			}
		}(conn)
	}
}

func cmdInstallService(args []string) error {
	c, err := loadConfig(args)
	if err != nil {
		return err
	}
	if c.Role != "source" && c.Role != "sink" {
		return fmt.Errorf("role must be source or sink")
	}
	if runtime.GOOS == "windows" {
		bin, err := os.Executable()
		if err != nil {
			return err
		}
		cfgPath := filepath.Join(config.Dir(), "config.toml")
		fmt.Println("Register a Scheduled Task by running:")
		fmt.Println(service.WindowsTaskCommand(c.Role, bin, cfgPath))
		return nil
	}
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(config.Dir(), "config.toml")
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil { // #nosec G703 -- unitDir is fixed under the current user's home directory.
		return err
	}
	unitPath := filepath.Join(unitDir, service.UnitFileName(c.Role))
	if err := os.WriteFile(unitPath, []byte(service.SystemdUnit(c.Role, bin, cfgPath)), 0o600); err != nil { // #nosec G703 -- role is validated and UnitFileName returns a fixed basename.
		return err
	}
	fmt.Printf("wrote %s\nenable with:\n  systemctl --user daemon-reload\n  systemctl --user enable --now %s\n",
		unitPath, service.UnitFileName(c.Role))
	return nil
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	timeout := fs.Duration("timeout", 3*time.Second, "peer reachability dial timeout")
	skipNet := fs.Bool("no-net", false, "skip the peer reachability check")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, statErr := os.Stat(*cfgPath); errors.Is(statErr, os.ErrNotExist) {
		if *jsonOut {
			printDoctorJSON(map[string]any{
				"configured":  false,
				"config_path": *cfgPath,
				"checks": []any{
					map[string]any{"name": "config", "status": "FAIL", "detail": "config missing: " + *cfgPath},
				},
				"fail_count":      1,
				"warn_count":      0,
				"skipped_network": *skipNet,
			})
			os.Exit(2)
		}
		return fmt.Errorf("load config: open %s: no such file or directory", *cfgPath)
	}

	c, unknown, err := config.LoadChecked(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	checks := doctor.Run(c)
	for _, k := range unknown {
		checks = append(checks, doctor.Check{
			Name:   "config-key",
			Status: doctor.Warn,
			Detail: fmt.Sprintf("unknown key %q ignored (check spelling and section placement)", k),
		})
	}
	if c.Role == "source" && !*skipNet {
		if c.Peerless() {
			checks = append(checks, doctor.Peerless())
		} else {
			checks = append(checks, doctor.PeerReachable(c.Peer, *timeout))
		}
	}
	if *jsonOut {
		printDoctorJSON(doctorPayload(*cfgPath, c, checks, *skipNet))
		if doctor.HasFail(checks) {
			return fmt.Errorf("doctor found problems")
		}
		return nil
	}
	for _, ck := range checks {
		fmt.Printf("[%-4s] %s: %s\n", ck.Status, ck.Name, ck.Detail)
	}
	if doctor.HasFail(checks) {
		return fmt.Errorf("doctor found problems")
	}
	return nil
}

func doctorPayload(cfgPath string, c config.Config, checks []doctor.Check, skippedNetwork bool) map[string]any {
	rows := make([]map[string]any, 0, len(checks))
	failCount := 0
	warnCount := 0
	for _, ck := range checks {
		status := ck.Status.String()
		switch ck.Status {
		case doctor.Fail:
			failCount++
		case doctor.Warn:
			warnCount++
		}
		rows = append(rows, map[string]any{
			"name":   ck.Name,
			"status": status,
			"detail": ck.Detail,
		})
	}
	surfaces := c.Surfaces
	if surfaces == nil {
		surfaces = []string{}
	}
	allow := c.Domains.Allow
	if allow == nil {
		allow = []string{}
	}
	deny := c.Domains.Deny
	if deny == nil {
		deny = []string{}
	}
	secretAllow := c.SecretNames.Allow
	if secretAllow == nil {
		secretAllow = []string{}
	}
	secretDeny := c.SecretNames.Deny
	if secretDeny == nil {
		secretDeny = []string{}
	}
	return map[string]any{
		"configured":      true,
		"config_path":     cfgPath,
		"role":            c.Role,
		"peer":            c.Peer,
		"surfaces":        surfaces,
		"browser_count":   len(c.Browsers),
		"adapter_count":   len(c.Adapters),
		"allow":           allow,
		"deny":            deny,
		"secret_allow":    secretAllow,
		"secret_deny":     secretDeny,
		"resync_seconds":  c.ResyncSeconds,
		"checks":          rows,
		"fail_count":      failCount,
		"warn_count":      warnCount,
		"skipped_network": skippedNetwork,
	}
}

func printDoctorJSON(payload map[string]any) {
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, statErr := os.Stat(*cfgPath); errors.Is(statErr, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "unwired: no config at", *cfgPath)
		os.Exit(2)
	}

	c, err := loadConfigWarn(*cfgPath)
	if err != nil {
		return err // -> main exits 1
	}

	_, keyErr := os.Stat(c.KeyPath)
	keyPresent := keyErr == nil
	_, oldKeyErr := os.Stat(keyfile.OldKeyPath(c.KeyPath))
	rotationInProgress := oldKeyErr == nil

	st, _ := state.Load(statePath(*cfgPath))
	lastSync := "never"
	if st.LastSyncUnix > 0 {
		lastSync = time.Unix(st.LastSyncUnix, 0).Format(time.RFC3339)
	}

	if *jsonOut {
		allow := c.Domains.Allow
		if allow == nil {
			allow = []string{}
		}
		deny := c.Domains.Deny
		if deny == nil {
			deny = []string{}
		}
		surfaces := c.Surfaces
		if surfaces == nil {
			surfaces = []string{}
		}
		payload := map[string]any{
			"role":                 c.Role,
			"configured":           true,
			"peer":                 c.Peer,
			"key_present":          keyPresent,
			"surfaces":             surfaces,
			"browsers":             len(c.Browsers),
			"allow":                allow,
			"deny":                 deny,
			"last_sync":            lastSync,
			"last_cookies":         st.Cookies,
			"last_secrets":         st.Secrets,
			"last_storage":         st.Storage,
			"rotation_in_progress": rotationInProgress,
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("role:     %s\npeer:     %s\nkey:      %s\nsurfaces: %v\nbrowsers: %d\nallow:    %v\ndeny:     %v\n",
		c.Role, c.Peer, c.KeyPath, c.Surfaces, len(c.Browsers), c.Domains.Allow, c.Domains.Deny)
	if rotationInProgress {
		fmt.Printf("rotation: in progress (old key at %s)\n", keyfile.OldKeyPath(c.KeyPath))
	}
	fmt.Printf("last sync: %s (cookies %d, secrets %d, localStorage %d)\n", lastSync, st.Cookies, st.Secrets, st.Storage)
	return nil
}

// cmdInventory summarizes the contents of a sidecar backup store: how many
// cookies it holds, the per-host breakdown, the session vs persistent split,
// and which auth cookies are near expiry. status reports config and a last-sync
// count; this reads the actual store so you can see what a backup contains
// without poking the SQLite schema by hand.
func cmdInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	defStore := filepath.Join(config.Dir(), "sidecar.db")
	store := fs.String("store", defStore, "path to a sidecar.db store")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	expiryDays := fs.Int("expiry-days", 14, "near-expiry window in days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *expiryDays < 0 {
		return fmt.Errorf("-expiry-days must not be negative")
	}

	// Read-only: inventory reports on existing backups and must not create a
	// store on a typo or mutate an operator-supplied file.
	sc, err := surface.OpenSidecarReadOnly(*store)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "no sidecar store at", *store)
			os.Exit(2)
		}
		return err
	}
	defer sc.Close()
	cookies, err := sc.List()
	if err != nil {
		return err
	}

	now := time.Now()
	within := time.Duration(*expiryDays) * 24 * time.Hour
	sessionOnly := 0
	hostCount := map[string]int{}
	for _, c := range cookies {
		if c.ExpiresUTC <= 0 {
			sessionOnly++
		}
		hostCount[c.Host]++
	}
	near := cookie.NearExpiry(cookies, within, now)

	storageItems, err := sc.ListStorage()
	if err != nil {
		return err
	}
	storageOrigins := map[string]struct{}{}
	for _, it := range storageItems {
		storageOrigins[it.Origin] = struct{}{}
	}

	type hostStat struct {
		Host  string
		Count int
	}
	hosts := make([]hostStat, 0, len(hostCount))
	for h, n := range hostCount {
		hosts = append(hosts, hostStat{h, n})
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Count != hosts[j].Count {
			return hosts[i].Count > hosts[j].Count
		}
		return hosts[i].Host < hosts[j].Host
	})

	if *jsonOut {
		hostList := make([]map[string]any, 0, len(hosts))
		for _, h := range hosts {
			hostList = append(hostList, map[string]any{"host": h.Host, "count": h.Count})
		}
		nearList := make([]map[string]any, 0, len(near))
		for _, c := range near {
			nearList = append(nearList, map[string]any{
				"host":    c.Host,
				"name":    c.Name,
				"expires": time.Unix(cookie.ExpiresUnix(c.ExpiresUTC), 0).UTC().Format(time.RFC3339),
			})
		}
		payload := map[string]any{
			"store":                *store,
			"total":                len(cookies),
			"persistent":           len(cookies) - sessionOnly,
			"session_only":         sessionOnly,
			"hosts":                hostList,
			"near_expiry_days":     *expiryDays,
			"near_expiry":          nearList,
			"localstorage_items":   len(storageItems),
			"localstorage_origins": len(storageOrigins),
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("store:    %s\ncookies:  %d (%d persistent, %d session)\nhosts:    %d\n",
		*store, len(cookies), len(cookies)-sessionOnly, sessionOnly, len(hosts))
	for _, h := range hosts {
		fmt.Printf("  %5d  %s\n", h.Count, h.Host)
	}
	fmt.Printf("localStorage: %d item(s) across %d origin(s)\n", len(storageItems), len(storageOrigins))
	if len(near) == 0 {
		fmt.Printf("near-expiry (within %dd): none\n", *expiryDays)
	} else {
		fmt.Printf("near-expiry (within %dd):\n", *expiryDays)
		for _, c := range near {
			fmt.Printf("  %s  %s @ %s\n",
				time.Unix(cookie.ExpiresUnix(c.ExpiresUTC), 0).UTC().Format("2006-01-02"),
				c.Name, c.Host)
		}
	}
	return nil
}

type restoreTargetKind string

const (
	restoreTargetNetscape     restoreTargetKind = "netscape"
	restoreTargetChromium     restoreTargetKind = "chromium"
	restoreTargetCDP          restoreTargetKind = "cdp"
	restoreTargetStorageState restoreTargetKind = "storagestate"
	restoreTargetDesktopApp   restoreTargetKind = "desktop-app"
)

type restoreTarget struct {
	kind       restoreTargetKind
	path       string
	profileDir string
	app        string
}

func parseRestoreTarget(spec string) (restoreTarget, error) {
	kind, value, ok := strings.Cut(spec, "=")
	if !ok || value == "" {
		return restoreTarget{}, fmt.Errorf("-to must be netscape=<path>, chromium=<profile-dir>, storagestate=<path>, cdp=<loopback-http-url>, or desktop-app=<codex|claude>")
	}
	switch restoreTargetKind(kind) {
	case restoreTargetNetscape:
		return restoreTarget{kind: restoreTargetNetscape, path: value}, nil
	case restoreTargetChromium:
		return restoreTarget{kind: restoreTargetChromium, profileDir: value}, nil
	case restoreTargetStorageState:
		return restoreTarget{kind: restoreTargetStorageState, path: value}, nil
	case restoreTargetCDP:
		if err := cdpvault.ValidateLoopbackURL(value, "http", "https"); err != nil {
			return restoreTarget{}, fmt.Errorf("invalid CDP restore target: %w", err)
		}
		return restoreTarget{kind: restoreTargetCDP, path: value}, nil
	case restoreTargetDesktopApp:
		if _, ok := desktopApps[value]; !ok {
			return restoreTarget{}, fmt.Errorf("unsupported desktop app %q (supported: codex, claude)", value)
		}
		return restoreTarget{kind: restoreTargetDesktopApp, app: value}, nil
	default:
		return restoreTarget{}, fmt.Errorf("unsupported restore target %q (supported: netscape, chromium, storagestate, cdp, desktop-app)", kind)
	}
}

func (t restoreTarget) String() string {
	switch t.kind {
	case restoreTargetNetscape:
		return string(t.kind) + "=" + t.path
	case restoreTargetChromium:
		return string(t.kind) + "=" + t.profileDir
	case restoreTargetStorageState:
		return string(t.kind) + "=" + t.path
	case restoreTargetCDP:
		return string(t.kind) + "=" + t.path
	case restoreTargetDesktopApp:
		return string(t.kind) + "=" + t.app
	default:
		return string(t.kind)
	}
}

func (t restoreTarget) chromeCookiePath() string {
	return filepath.Join(t.profileDir, "Cookies")
}

func parseRestoreDomains(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("-domains contains an empty domain")
		}
		out = append(out, p)
	}
	return out, nil
}

func narrowRestoreCookies(cookies []cookie.Cookie, domains []string, configured policy.Domain) []cookie.Cookie {
	requested := policy.Domain{Allow: domains}
	out := make([]cookie.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if len(configured.Allow) > 0 && !configured.Permit(c.Host) {
			continue
		}
		if len(configured.Allow) == 0 && len(configured.Deny) > 0 {
			hostOnly := policy.Domain{Allow: []string{c.Host}, Deny: configured.Deny}
			if !hostOnly.Permit(c.Host) {
				continue
			}
		}
		if len(domains) > 0 && !requested.Permit(c.Host) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// narrowRestoreStorage applies the same suffix-style domain narrowing to
// localStorage items, keyed on each origin's host. A non-http(s) origin is
// dropped.
func narrowRestoreStorage(items []webstorage.Item, domains []string, configured policy.Domain) []webstorage.Item {
	requested := policy.Domain{Allow: domains}
	out := make([]webstorage.Item, 0, len(items))
	for _, it := range items {
		host, ok := webstorage.OriginHost(it.Origin)
		if !ok {
			continue
		}
		if len(configured.Allow) > 0 && !configured.Permit(host) {
			continue
		}
		if len(configured.Allow) == 0 && len(configured.Deny) > 0 {
			hostOnly := policy.Domain{Allow: []string{host}, Deny: configured.Deny}
			if !hostOnly.Permit(host) {
				continue
			}
		}
		if len(domains) > 0 && !requested.Permit(host) {
			continue
		}
		out = append(out, it)
	}
	return out
}

func skipExpiredRestoreCookies(cookies []cookie.Cookie, now time.Time) ([]cookie.Cookie, int) {
	out := make([]cookie.Cookie, 0, len(cookies))
	skipped := 0
	nowUnix := now.Unix()
	for _, c := range cookies {
		if c.ExpiresUTC > 0 && cookie.ExpiresUnix(c.ExpiresUTC) <= nowUnix {
			skipped++
			continue
		}
		out = append(out, c)
	}
	return out, skipped
}

type restoreCountRow struct {
	Name   string `json:"name,omitempty"`
	Host   string `json:"host,omitempty"`
	Domain string `json:"domain,omitempty"`
	Count  int    `json:"count"`
}

func restoreSummary(cookies []cookie.Cookie) ([]restoreCountRow, []restoreCountRow) {
	nameHostCounts := map[string]restoreCountRow{}
	domainCounts := map[string]int{}
	for _, c := range cookies {
		key := c.Name + "\x00" + c.Host
		row := nameHostCounts[key]
		row.Name = c.Name
		row.Host = c.Host
		row.Count++
		nameHostCounts[key] = row
		domainCounts[c.Host]++
	}
	nameHosts := make([]restoreCountRow, 0, len(nameHostCounts))
	for _, row := range nameHostCounts {
		nameHosts = append(nameHosts, row)
	}
	sort.Slice(nameHosts, func(i, j int) bool {
		if nameHosts[i].Count != nameHosts[j].Count {
			return nameHosts[i].Count > nameHosts[j].Count
		}
		if nameHosts[i].Host != nameHosts[j].Host {
			return nameHosts[i].Host < nameHosts[j].Host
		}
		return nameHosts[i].Name < nameHosts[j].Name
	})

	domains := make([]restoreCountRow, 0, len(domainCounts))
	for domain, count := range domainCounts {
		domains = append(domains, restoreCountRow{Domain: domain, Count: count})
	}
	sort.Slice(domains, func(i, j int) bool {
		if domains[i].Count != domains[j].Count {
			return domains[i].Count > domains[j].Count
		}
		return domains[i].Domain < domains[j].Domain
	})
	return nameHosts, domains
}

func printRestoreDryRun(sidecarPath string, target restoreTarget, cookies []cookie.Cookie, skippedExpired int, jsonOut bool) error {
	nameHosts, domains := restoreSummary(cookies)
	var appInspection *desktopAppInspection
	if target.kind == restoreTargetDesktopApp {
		inspection := inspectDesktopApp(target)
		appInspection = &inspection
	}
	if jsonOut {
		payload := map[string]any{
			"dry_run":         true,
			"sidecar":         sidecarPath,
			"target":          target.String(),
			"total":           len(cookies),
			"skipped_expired": skippedExpired,
			"name_hosts":      nameHosts,
			"domains":         domains,
		}
		if appInspection != nil {
			payload["desktop_app"] = appInspection
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("sidecar: %s\nrestore target: %s\ncookies: %d\n", sidecarPath, target.String(), len(cookies))
	fmt.Printf("skipped expired: %d\n", skippedExpired)
	fmt.Println("name@host:")
	if len(nameHosts) == 0 {
		fmt.Println("  none")
	} else {
		for _, row := range nameHosts {
			fmt.Printf("  %5d  %s@%s\n", row.Count, row.Name, row.Host)
		}
	}
	fmt.Println("domains:")
	if len(domains) == 0 {
		fmt.Println("  none")
	} else {
		for _, row := range domains {
			fmt.Printf("  %5d  %s\n", row.Count, row.Domain)
		}
	}
	if appInspection != nil {
		fmt.Println("profile:", appInspection.ProfilePath)
		fmt.Println("profile state:", appInspection.ProfileState)
		fmt.Println("process state:", appInspection.ProcessState)
		fmt.Println("cookie store:", appInspection.CookieStore)
		fmt.Println("cookie layout:", appInspection.CookieLayout)
		fmt.Println("injection method:", appInspection.InjectionMethod)
		fmt.Println("write result:", appInspection.WriteResult)
	}
	return nil
}

// restoreApply writes cookies (and, for storagestate/cdp targets, localStorage)
// to the target. It returns the count of skipped-expired cookies and the count
// of localStorage items written.
func restoreApply(ctx context.Context, target restoreTarget, cookies []cookie.Cookie, storage []webstorage.Item) (int, int, error) {
	d := cookie.Diff{Upserts: cookies}
	switch target.kind {
	case restoreTargetNetscape:
		ns, err := surface.NewNetscape(target.path)
		if err != nil {
			return 0, 0, err
		}
		return 0, 0, ns.Apply(d)
	case restoreTargetStorageState:
		ss, err := surface.NewStorageState(target.path)
		if err != nil {
			return 0, 0, err
		}
		if err := ss.Apply(d); err != nil {
			return 0, 0, err
		}
		if err := ss.ApplyStorage(webstorage.Diff{Upserts: storage}); err != nil {
			return 0, 0, err
		}
		return 0, len(storage), nil
	case restoreTargetChromium:
		cs, closeFn, err := newChromeSurface(target.chromeCookiePath())
		if err != nil {
			return 0, 0, err
		}
		defer func() {
			if err := closeFn(); err != nil {
				fmt.Fprintln(os.Stderr, "warning: close failed:", err)
			}
		}()
		return 0, 0, cs.Apply(d)
	case restoreTargetCDP:
		cdp := &cdpvault.CDP{BaseURL: target.path}
		skipped, err := cdp.WriteCookies(ctx, cookies)
		if err != nil {
			return skipped, 0, err
		}
		if len(storage) == 0 {
			return skipped, 0, nil
		}
		written, err := cdp.WriteStorage(ctx, storage)
		return skipped, written, err
	case restoreTargetDesktopApp:
		return 0, 0, errors.New(desktopAppRestoreRefusal(target))
	default:
		return 0, 0, fmt.Errorf("unsupported restore target %q", target.kind)
	}
}

type restoreVerifyRow struct {
	Domain   string   `json:"domain"`
	Expected int      `json:"expected"`
	Present  int      `json:"present"`
	Names    []string `json:"names"`
}

func restoreVerifyRows(expected, present []cookie.Cookie) ([]restoreVerifyRow, int) {
	presentKeys := make(map[string]struct{}, len(present))
	for _, c := range present {
		presentKeys[cookie.Key(c)] = struct{}{}
	}
	byDomain := map[string]*restoreVerifyRow{}
	nameSets := map[string]map[string]struct{}{}
	missing := 0
	for _, c := range expected {
		row := byDomain[c.Host]
		if row == nil {
			row = &restoreVerifyRow{Domain: c.Host}
			byDomain[c.Host] = row
			nameSets[c.Host] = map[string]struct{}{}
		}
		row.Expected++
		nameSets[c.Host][c.Name] = struct{}{}
		if _, ok := presentKeys[cookie.Key(c)]; ok {
			row.Present++
		} else {
			missing++
		}
	}
	rows := make([]restoreVerifyRow, 0, len(byDomain))
	for domain, row := range byDomain {
		for name := range nameSets[domain] {
			row.Names = append(row.Names, name)
		}
		sort.Strings(row.Names)
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Expected != rows[j].Expected {
			return rows[i].Expected > rows[j].Expected
		}
		return rows[i].Domain < rows[j].Domain
	})
	return rows, missing
}

func printRestoreVerify(rows []restoreVerifyRow) {
	fmt.Println("verify:")
	if len(rows) == 0 {
		fmt.Println("  none")
		return
	}
	for _, row := range rows {
		fmt.Printf("  %s expected %d present %d names %s\n",
			row.Domain, row.Expected, row.Present, strings.Join(row.Names, ","))
	}
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	sidecarPath := fs.String("sidecar", "", "path to a sidecar.db store")
	cfgPath := fs.String("config", "", "sink config path used to derive the sidecar path")
	to := fs.String("to", "", "restore target: netscape=<path>, chromium=<profile-dir>, storagestate=<path>, cdp=<loopback-http-url>, or desktop-app=<codex|claude>")
	domainList := fs.String("domains", "", "comma-separated domain suffixes to restore")
	dryRun := fs.Bool("dry-run", false, "summarize the restore without writing the target")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output for --dry-run")
	verify := fs.Bool("verify", false, "after CDP restore, read cookies back and report expected vs present counts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*sidecarPath == "") == (*cfgPath == "") {
		return fmt.Errorf("pass exactly one of -sidecar or -config")
	}
	if *to == "" {
		return fmt.Errorf("-to is required")
	}
	target, err := parseRestoreTarget(*to)
	if err != nil {
		return err
	}
	if *verify && target.kind == restoreTargetDesktopApp {
		return errors.New(desktopAppRestoreRefusal(target))
	}
	if *verify && *dryRun {
		return fmt.Errorf("-verify is not supported with -dry-run")
	}
	if *verify && target.kind != restoreTargetCDP {
		return fmt.Errorf("-verify is only supported with cdp restore targets")
	}
	domains, err := parseRestoreDomains(*domainList)
	if err != nil {
		return err
	}
	store := *sidecarPath
	var configuredDomains policy.Domain
	if *cfgPath != "" {
		c, err := loadConfigWarn(*cfgPath)
		if err != nil {
			return err
		}
		store = sidecarDBPath(c)
		configuredDomains = c.Domains
	}

	sc, err := surface.OpenSidecarReadOnly(store)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "no sidecar store at", store)
			os.Exit(2)
		}
		return err
	}
	defer sc.Close()
	cookies, err := sc.List()
	if err != nil {
		return err
	}
	cookies = narrowRestoreCookies(cookies, domains, configuredDomains)
	cookies, skippedExpired := skipExpiredRestoreCookies(cookies, time.Now())

	// localStorage materializes into a storageState file or a live CDP target;
	// netscape and chromium are cookie-only formats.
	carriesStorage := target.kind == restoreTargetStorageState || target.kind == restoreTargetCDP
	var storageItems []webstorage.Item
	if carriesStorage {
		items, lerr := sc.ListStorage()
		if lerr != nil {
			return lerr
		}
		storageItems = narrowRestoreStorage(items, domains, configuredDomains)
	}

	if *dryRun {
		if err := printRestoreDryRun(store, target, cookies, skippedExpired, *jsonOut); err != nil {
			return err
		}
		if carriesStorage && !*jsonOut {
			fmt.Printf("localStorage items: %d\n", len(storageItems))
		}
		return nil
	}
	if *jsonOut {
		return fmt.Errorf("-json is only supported with -dry-run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	applySkipped, storageWritten, err := restoreApply(ctx, target, cookies, storageItems)
	if err != nil {
		return err
	}
	skippedExpired += applySkipped
	fmt.Printf("restored %d cookie(s) from %s to %s\n", len(cookies), store, target.String())
	switch target.kind {
	case restoreTargetStorageState:
		fmt.Printf("materialized %d localStorage item(s)\n", storageWritten)
	case restoreTargetCDP:
		fmt.Printf("wrote %d of %d localStorage item(s) into the running browser (best-effort)\n", storageWritten, len(storageItems))
	}
	fmt.Printf("skipped expired: %d\n", skippedExpired)
	if *verify {
		present, err := (&cdpvault.CDP{BaseURL: target.path}).ReadCookies(ctx)
		if err != nil {
			return fmt.Errorf("CDP verify readback: %w", err)
		}
		rows, missing := restoreVerifyRows(cookies, present)
		printRestoreVerify(rows)
		if missing > 0 {
			return fmt.Errorf("CDP verify failed: %d expected cookie(s) absent", missing)
		}
	}
	return nil
}

// distinctStorageOrigins returns the sorted unique origins in items, so the
// launch helper can open a tab on each one (giving it a live frame for
// localStorage).
func distinctStorageOrigins(items []webstorage.Item) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, it := range items {
		if _, ok := seen[it.Origin]; ok {
			continue
		}
		seen[it.Origin] = struct{}{}
		out = append(out, it.Origin)
	}
	sort.Strings(out)
	return out
}

func cmdBrowser(args []string) error {
	fs := flag.NewFlagSet("browser", flag.ExitOnError)
	sidecarPath := fs.String("sidecar", "", "path to a sidecar.db store")
	cfgPath := fs.String("config", "", "sink config path used to derive the sidecar path and domains")
	domainList := fs.String("domains", "", "comma-separated domain suffixes to restore")
	headless := fs.Bool("headless", false, "launch with --headless=new instead of a headed window")
	profile := fs.String("profile", "", "user-data-dir for the automation profile (default: a throwaway temp dir)")
	port := fs.Int("port", 9222, "loopback remote debugging port")
	chromeBin := fs.String("chrome", "", "path to a Chrome/Chromium binary (default: search PATH)")
	keepOpen := fs.Bool("keep-open", false, "leave the browser running until interrupted, for a scraper to attach")
	verify := fs.Bool("verify", false, "read cookies back through CDP and report expected vs present")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*sidecarPath == "") == (*cfgPath == "") {
		return fmt.Errorf("pass exactly one of -sidecar or -config")
	}
	domains, err := parseRestoreDomains(*domainList)
	if err != nil {
		return err
	}

	store := *sidecarPath
	var configuredDomains policy.Domain
	if *cfgPath != "" {
		c, cerr := loadConfigWarn(*cfgPath)
		if cerr != nil {
			return cerr
		}
		store = sidecarDBPath(c)
		configuredDomains = c.Domains
	}

	sc, err := surface.OpenSidecarReadOnly(store)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "no sidecar store at", store)
			os.Exit(2)
		}
		return err
	}
	defer sc.Close()
	cookies, err := sc.List()
	if err != nil {
		return err
	}
	cookies = narrowRestoreCookies(cookies, domains, configuredDomains)
	cookies, _ = skipExpiredRestoreCookies(cookies, time.Now())
	items, err := sc.ListStorage()
	if err != nil {
		return err
	}
	storage := narrowRestoreStorage(items, domains, configuredDomains)

	// A throwaway automation profile unless the operator names one. Never a real
	// user profile.
	profileDir := *profile
	cleanup := func() {}
	if profileDir == "" {
		d, terr := os.MkdirTemp("", "agentpantry-chrome-")
		if terr != nil {
			return terr
		}
		profileDir = d
		cleanup = func() { _ = os.RemoveAll(d) }
	}
	defer cleanup()

	ctx := signalCtx()
	base, stop, err := browser.Launch(ctx, browser.Options{
		BinaryPath: *chromeBin,
		ProfileDir: profileDir,
		Port:       *port,
		Headless:   *headless,
		OpenURLs:   distinctStorageOrigins(storage), // a tab per origin gives it a live frame
	})
	if err != nil {
		return err
	}
	defer func() { _ = stop() }()

	if err := browser.WaitForCDP(ctx, base, 20*time.Second); err != nil {
		return err
	}

	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cdp := &cdpvault.CDP{BaseURL: base}
	cookieSkipped, err := cdp.WriteCookies(rctx, cookies)
	if err != nil {
		return err
	}
	// This browser was launched with a tab open on each origin, so seed
	// localStorage in the loaded frame (reliable), not via DOMStorage.
	written, err := cdp.WriteStorageViaFrames(rctx, storage)
	if err != nil {
		return err
	}
	fmt.Printf("browser ready at %s\nrestored %d cookie(s) (%d expired skipped), wrote %d of %d localStorage item(s)\n",
		base, len(cookies), cookieSkipped, written, len(storage))

	if *verify {
		present, verr := cdp.ReadCookies(rctx)
		if verr != nil {
			return fmt.Errorf("verify readback: %w", verr)
		}
		rows, missing := restoreVerifyRows(cookies, present)
		printRestoreVerify(rows)
		if missing > 0 {
			return fmt.Errorf("verify failed: %d expected cookie(s) absent", missing)
		}
	}

	if *keepOpen {
		fmt.Printf("keeping the browser open; attach a scraper to %s. Ctrl-C to stop.\n", base)
		<-ctx.Done()
	}
	return nil
}

func signalCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ch; cancel() }()
	return ctx
}
