package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/doctor"
	"github.com/escoffier-labs/agentpantry/internal/keyfile"
	"github.com/escoffier-labs/agentpantry/internal/pair"
)

func cmdPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	role := fs.String("role", "", "source or sink")
	cfgPath := fs.String("config", filepath.Join(config.Dir(), "config.toml"), "config path")
	keyFlag := fs.String("key", "", "key path (overrides config key_path and the default)")
	bind := fs.String("bind", "", "sink listen address")
	peer := fs.String("peer", "", "source dial address")
	codeFlag := fs.String("code", "", "short pairing code from the sink")
	timeout := fs.Duration("timeout", pair.DefaultTimeout, "sink pairing window")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var c config.Config
	if _, statErr := os.Stat(*cfgPath); statErr == nil {
		loaded, err := loadConfigWarn(*cfgPath)
		if err != nil {
			return err
		}
		c = loaded
	} else if *cfgPath != filepath.Join(config.Dir(), "config.toml") && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}

	r := *role
	if r == "" {
		r = c.Role
	}
	if r != "source" && r != "sink" {
		return fmt.Errorf("pair requires -role source|sink")
	}

	keyPath := filepath.Join(config.Dir(), "psk.key")
	if c.KeyPath != "" {
		keyPath = c.KeyPath
	}
	if *keyFlag != "" {
		keyPath = *keyFlag
	}
	oldPath := keyfile.OldKeyPath(keyPath)
	if _, err := os.Lstat(oldPath); err == nil {
		return fmt.Errorf("rotation in progress at %s; finish or abandon it before pairing", oldPath)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	ctx := signalCtx()
	var psk []byte
	switch r {
	case "sink":
		addr := "127.0.0.1:8787"
		if c.Peer != "" && !c.Peerless() {
			addr = c.Peer
		}
		if *bind != "" {
			addr = *bind
		}
		if !doctor.IsLoopbackBind(addr) {
			fmt.Fprintf(os.Stderr, "warning: pairing bind %s exposes a pre-auth SPAKE2 listener beyond loopback\n", addr)
		}
		code, err := pair.GenerateCode()
		if err != nil {
			return err
		}
		fmt.Printf("pairing code: %s\nshare this once with the source over an out-of-band channel\n", code)
		psk, err = pair.Serve(ctx, pair.ServeConfig{
			Addr:    addr,
			Code:    code,
			Timeout: *timeout,
			OnListening: func(a string) {
				fmt.Printf("waiting on %s (timeout %s, %d attempts)\n", a, *timeout, pair.MaxAttempts)
			},
		})
		if err != nil {
			return err
		}
	case "source":
		if *codeFlag == "" {
			return fmt.Errorf("source pair requires -code")
		}
		addr := c.Peer
		if *peer != "" {
			addr = *peer
		}
		if addr == "" || addr == config.PeerNone {
			return fmt.Errorf("source pair requires -peer")
		}
		var err error
		psk, err = pair.Dial(ctx, addr, *codeFlag)
		if err != nil {
			return err
		}
	}

	_, existedErr := os.Stat(keyPath)
	replaced := existedErr == nil
	backupPath, err := keyfile.WriteWithBackup(keyPath, psk, true)
	if err != nil {
		return err
	}
	if backupPath != "" {
		fmt.Printf("backed up previous PSK to %s\n", backupPath)
		fmt.Println("delete the backup once pairing is confirmed; it is live key history")
	}
	fmt.Printf("paired; wrote 32-byte PSK to %s\nconfirmation: %s\ncompare this fingerprint with the peer before first sync\n",
		keyPath, pair.Fingerprint(psk))
	if replaced {
		fmt.Printf(`existing key replaced; restart persistent sources (they load the PSK once at startup)
`)
	}
	return nil
}
