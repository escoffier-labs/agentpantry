package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/lane"
)

// cmdVerify checks whether a running lane browser still has a working session
// for a domain. Cookie counts and expiry dates cannot answer that: a session is
// only proven by loading a page and seeing real content come back.
func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	laneURL := fs.String("lane", "", "CDP base URL of the running browser to check, e.g. http://127.0.0.1:9224")
	domain := fs.String("domain", "", "domain the check is scoped to; the URL must match it")
	timeout := fs.Duration("timeout", 25*time.Second, "overall budget for loading and reading the page")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: agentpantry verify -lane <cdp-url> -domain <host> <url>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	if *laneURL == "" {
		return fmt.Errorf("-lane is required (for example http://127.0.0.1:9224)")
	}

	probe, err := lane.Verify(context.Background(), *laneURL, fs.Arg(0), *domain, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	if *jsonOut {
		payload := map[string]any{
			"lane":       *laneURL,
			"url":        probe.URL,
			"final_url":  probe.FinalURL,
			"title":      probe.Title,
			"text_len":   probe.TextLen,
			"verdict":    probe.Verdict,
			"marker":     probe.Marker,
			"verified":   probe.OK(),
			"checked_at": time.Now().UTC().Format(time.RFC3339),
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	} else {
		fmt.Printf("lane:    %s\nurl:     %s\ntitle:   %s\ntext:    %d chars\nverdict: %s\n",
			*laneURL, probe.FinalURL, probe.Title, probe.TextLen, probe.Verdict)
		if probe.Marker != "" {
			fmt.Printf("marker:  %s\n", probe.Marker)
		}
	}

	if !probe.OK() {
		os.Exit(1)
	}
	return nil
}
