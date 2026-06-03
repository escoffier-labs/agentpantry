package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/cdpvault"
	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/doctor"
	"github.com/escoffier-labs/agentpantry/internal/ffvault"
	"github.com/escoffier-labs/agentpantry/internal/keyfile"
	"github.com/escoffier-labs/agentpantry/internal/secretsrc"
	"github.com/escoffier-labs/agentpantry/internal/service"
	"github.com/escoffier-labs/agentpantry/internal/sink"
	"github.com/escoffier-labs/agentpantry/internal/source"
	"github.com/escoffier-labs/agentpantry/internal/state"
	"github.com/escoffier-labs/agentpantry/internal/surface"
	"github.com/escoffier-labs/agentpantry/internal/transport"
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
	case "version":
		err = cmdVersion(args)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: agentpantry <init|keygen|source|sink|doctor|status|install-service|version> [flags]")
	os.Exit(2)
}

func cmdVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	fs.Parse(args)

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
	fs.Parse(args)
	if *role != "source" && *role != "sink" {
		return fmt.Errorf("role must be source or sink")
	}
	if err := config.Save(*out, config.Default(*role)); err != nil {
		return err
	}
	fmt.Printf("wrote %s config to %s\n", *role, *out)
	return nil
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", filepath.Join(config.Dir(), "psk.key"), "key path")
	fs.Parse(args)
	if err := keyfile.Generate(*out); err != nil {
		return err
	}
	fmt.Printf("wrote 32-byte PSK to %s (copy this file to the peer)\n", *out)
	return nil
}

func loadConfig(args []string) (config.Config, error) {
	fs := flag.NewFlagSet("cfg", flag.ExitOnError)
	path := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	fs.Parse(args)
	return config.Load(*path)
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
	fs.Parse(args)

	c, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	key, err := keyfile.Load(c.KeyPath)
	if err != nil {
		return err
	}
	vs, paths, err := buildVaults(c)
	if err != nil {
		return err
	}
	var secretReaders []source.SecretReader
	if c.SecretsDir != "" {
		secretReaders = append(secretReaders, &secretsrc.DirReader{Dir: c.SecretsDir})
		if _, statErr := os.Stat(c.SecretsDir); statErr == nil {
			paths = append(paths, c.SecretsDir)
		}
	}

	resync := time.Duration(c.ResyncSeconds) * time.Second
	hasCDP := false
	for _, b := range c.Browsers {
		if b.Kind == "cdp" {
			hasCDP = true
		}
	}
	if hasCDP && resync == 0 {
		resync = 60 * time.Second
		fmt.Fprintln(os.Stderr, "agentpantry: cdp source detected, defaulting resync to 60s")
	}

	clock := state.RealClock{}
	sp := statePath(*cfgPath)
	syncer := &source.Syncer{
		Vaults:       vs,
		Secrets:      secretReaders,
		Policy:       c.Domains,
		SecretPolicy: c.SecretNames,
		AfterSync: func(sent bool, cookies, secrets int) {
			st, _ := state.Load(sp)
			now := clock.Now().Unix()
			st.LastSyncUnix = now
			if sent {
				st.LastSentUnix = now
				st.Cookies = cookies
				st.Secrets = secrets
			}
			if err := state.Save(sp, st); err != nil {
				fmt.Fprintln(os.Stderr, "warning: could not write state:", err)
			}
		},
	}
	ctx := signalCtx()

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
		fmt.Fprintf(os.Stderr, "source: watching %d store(s), streaming frames to stdout\n", len(paths))
		return syncer.Watch(ctx, paths, 500*time.Millisecond, resync)
	}

	// TCP: reconnect with capped backoff so a sink restart or blip recovers.
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
		conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		salt, herr := transport.RecvSalt(conn)
		if herr != nil {
			conn.Close()
			if !sleepCtx(ctx, source.Backoff(attempt)) {
				return nil
			}
			attempt++
			continue
		}
		conn.SetReadDeadline(time.Time{})
		sealer, serr := transport.NewSealer(key, salt)
		if serr != nil {
			conn.Close()
			return serr
		}
		syncer.Sealer = sealer
		syncer.Out = conn
		syncer.Reset()
		attempt = 0
		werr := syncer.Watch(ctx, paths, 500*time.Millisecond, resync)
		conn.Close()
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

func cmdSink(args []string) error {
	fs := flag.NewFlagSet("sink", flag.ExitOnError)
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	stdio := fs.Bool("stdio", false, "read frames from stdin instead of listening on a port")
	fs.Parse(args)
	c, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	key, err := keyfile.Load(c.KeyPath)
	if err != nil {
		return err
	}

	var cookieSurfaces []sink.CookieSurface
	var secretSurfaces []sink.SecretSurface
	var closers []func() error

	for _, name := range c.Surfaces {
		switch name {
		case "sidecar":
			sc, err := surface.NewSidecar(filepath.Join(config.Dir(), "sidecar.db"))
			if err != nil {
				return err
			}
			cookieSurfaces = append(cookieSurfaces, sc)
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
		default:
			return fmt.Errorf("unknown adapter type %q", a.Type)
		}
	}
	defer func() {
		for _, cl := range closers {
			cl()
		}
	}()

	ctx := signalCtx()

	if *stdio {
		// Close stdin on signal so a blocking read (handshake or frame) unblocks.
		go func() {
			<-ctx.Done()
			os.Stdin.Close()
		}()
		// One-way pipe: the source issued the salt as the first frame.
		salt, herr := transport.RecvSalt(os.Stdin)
		if herr != nil {
			return fmt.Errorf("handshake: %w", herr)
		}
		opener, oerr := transport.NewOpener(key, salt)
		if oerr != nil {
			return oerr
		}
		srv := &sink.Server{Opener: opener, CookieSurfaces: cookieSurfaces, SecretSurfaces: secretSurfaces}
		fmt.Fprintf(os.Stderr, "sink: reading frames from stdin, surfaces %v\n", c.Surfaces)
		return srv.Serve(ctx, os.Stdin)
	}

	ln, err := net.Listen("tcp", c.Peer)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("sink: listening on %s, surfaces %v\n", c.Peer, c.Surfaces)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// Issue a fresh per-connection salt so frames from one session cannot be
		// replayed into another, and so a reconnecting source is not rejected.
		// Bound the handshake write so one stuck peer cannot wedge the listener.
		conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
		salt, herr := transport.SendSalt(conn)
		if herr != nil {
			fmt.Fprintln(os.Stderr, "handshake failed:", herr)
			conn.Close()
			continue
		}
		conn.SetWriteDeadline(time.Time{}) // clear; Serve is a long-lived stream
		opener, oerr := transport.NewOpener(key, salt)
		if oerr != nil {
			conn.Close()
			return oerr
		}
		srv := &sink.Server{Opener: opener, CookieSurfaces: cookieSurfaces, SecretSurfaces: secretSurfaces}
		if err := srv.Serve(ctx, conn); err != nil {
			fmt.Fprintln(os.Stderr, "connection ended:", err)
		}
		conn.Close()
	}
}

func cmdInstallService(args []string) error {
	c, err := loadConfig(args)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		bin, _ := os.Executable()
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
	unitDir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		return err
	}
	unitPath := filepath.Join(unitDir, service.UnitFileName(c.Role))
	if err := os.WriteFile(unitPath, []byte(service.SystemdUnit(c.Role, bin, cfgPath)), 0o644); err != nil {
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
	fs.Parse(args)

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

	c, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	checks := doctor.Run(c)
	if c.Role == "source" && !*skipNet {
		checks = append(checks, doctor.PeerReachable(c.Peer, *timeout))
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
		if ck.Status == doctor.Fail {
			failCount++
		} else if ck.Status == doctor.Warn {
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
	fs.Parse(args)

	if _, statErr := os.Stat(*cfgPath); errors.Is(statErr, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "unwired: no config at", *cfgPath)
		os.Exit(2)
	}

	c, err := config.Load(*cfgPath)
	if err != nil {
		return err // -> main exits 1
	}

	_, keyErr := os.Stat(c.KeyPath)
	keyPresent := keyErr == nil

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
			"role":         c.Role,
			"configured":   true,
			"peer":         c.Peer,
			"key_present":  keyPresent,
			"surfaces":     surfaces,
			"browsers":     len(c.Browsers),
			"allow":        allow,
			"deny":         deny,
			"last_sync":    lastSync,
			"last_cookies": st.Cookies,
			"last_secrets": st.Secrets,
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
	fmt.Printf("last sync: %s (cookies %d, secrets %d)\n", lastSync, st.Cookies, st.Secrets)
	return nil
}

func signalCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ch; cancel() }()
	return ctx
}
