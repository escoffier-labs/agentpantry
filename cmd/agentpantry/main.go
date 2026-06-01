package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/solomonneas/agentpantry/internal/config"
	"github.com/solomonneas/agentpantry/internal/keyfile"
	"github.com/solomonneas/agentpantry/internal/policy"
	"github.com/solomonneas/agentpantry/internal/service"
	"github.com/solomonneas/agentpantry/internal/sink"
	"github.com/solomonneas/agentpantry/internal/source"
	"github.com/solomonneas/agentpantry/internal/surface"
	"github.com/solomonneas/agentpantry/internal/transport"
	"github.com/solomonneas/agentpantry/internal/vault"
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
	case "status":
		err = cmdStatus(args)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: agentpantry <init|keygen|source|sink|install-service|status> [flags]")
	os.Exit(2)
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

func buildVaults(c config.Config) ([]source.CookieReader, []string, error) {
	var vs []source.CookieReader
	var paths []string
	for _, b := range c.Browsers {
		if b.Kind != "chromium" {
			return nil, nil, fmt.Errorf("unsupported browser kind %q (phase 1 supports chromium)", b.Kind)
		}
		vs = append(vs, &vault.LinuxChromium{
			Profile:     b.Profile,
			CookiePath:  b.CookiePath,
			KeyProvider: &vault.SecretServiceKey{Label: "Chrome Safe Storage"},
		})
		paths = append(paths, b.CookiePath)
	}
	return vs, paths, nil
}

func cmdSource(args []string) error {
	c, err := loadConfig(args)
	if err != nil {
		return err
	}
	key, err := keyfile.Load(c.KeyPath)
	if err != nil {
		return err
	}
	sealer, err := transport.NewSealer(key)
	if err != nil {
		return err
	}
	vs, paths, err := buildVaults(c)
	if err != nil {
		return err
	}
	conn, err := net.Dial("tcp", c.Peer)
	if err != nil {
		return fmt.Errorf("dial sink %s: %w", c.Peer, err)
	}
	defer conn.Close()

	syncer := &source.Syncer{
		Vaults: vs,
		Policy: c.Domains,
		Sealer: sealer,
		Out:    conn,
	}
	ctx := signalCtx()
	fmt.Printf("source: watching %d store(s), pushing to %s\n", len(paths), c.Peer)
	return syncer.Watch(ctx, paths, 500*time.Millisecond)
}

func cmdSink(args []string) error {
	c, err := loadConfig(args)
	if err != nil {
		return err
	}
	key, err := keyfile.Load(c.KeyPath)
	if err != nil {
		return err
	}
	opener, err := transport.NewOpener(key)
	if err != nil {
		return err
	}
	sidecarPath := filepath.Join(config.Dir(), "sidecar.db")
	sc, err := surface.NewSidecar(sidecarPath)
	if err != nil {
		return err
	}
	defer sc.Close()

	ln, err := net.Listen("tcp", c.Peer)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("sink: listening on %s, sidecar at %s\n", c.Peer, sidecarPath)

	srv := &sink.Server{Opener: opener, Surfaces: []sink.Surface{sc}}
	ctx := signalCtx()
	for {
		if ctx.Err() != nil {
			return nil
		}
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		// One connection at a time keeps the replay counter monotonic.
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

func cmdStatus(args []string) error {
	c, err := loadConfig(args)
	if err != nil {
		return err
	}
	fmt.Printf("role:     %s\npeer:     %s\nkey:      %s\nsurfaces: %v\nbrowsers: %d\nallow:    %v\ndeny:     %v\n",
		c.Role, c.Peer, c.KeyPath, c.Surfaces, len(c.Browsers), c.Domains.Allow, c.Domains.Deny)
	return nil
}

func signalCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ch; cancel() }()
	return ctx
}

// ensure policy import is used even if config has no domains in some builds.
var _ = policy.Domain{}
