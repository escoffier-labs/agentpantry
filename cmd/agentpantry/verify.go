package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/lane"
)

// Exit codes for verify. A script can tell "the session is dead" (1) from "the
// check never ran" (2).
const (
	verifyExitOK        = 0
	verifyExitNotOK     = 1 // challenge, empty, or off_domain
	verifyExitCannotRun = 2 // usage error or the check could not run
)

// cmdVerify checks whether a running lane browser still has a working session
// for a domain. Cookie counts and expiry dates cannot answer that: a session is
// only proven by loading a page and seeing real content come back.
func cmdVerify(args []string) error {
	os.Exit(runVerify(args, os.Stdout, os.Stderr))
	return nil
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	laneURL := fs.String("lane", "", "CDP base URL of the running browser to check, e.g. http://127.0.0.1:9224")
	domain := fs.String("domain", "", "domain the check is scoped to; the URL must match it")
	timeout := fs.Duration("timeout", 25*time.Second, "overall budget for loading and reading the page")
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: agentpantry verify -lane <cdp-url> -domain <host> <url>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return verifyExitOK
		}
		return verifyExitCannotRun
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return verifyExitCannotRun
	}
	if *laneURL == "" {
		fmt.Fprintln(stderr, "error: -lane is required (for example http://127.0.0.1:9224)")
		return verifyExitCannotRun
	}

	probe, err := lane.Verify(context.Background(), *laneURL, fs.Arg(0), *domain, *timeout)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return verifyExitCannotRun
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
			fmt.Fprintln(stderr, "error:", err)
			return verifyExitCannotRun
		}
		fmt.Fprintln(stdout, string(b))
	} else {
		fmt.Fprintf(stdout, "lane:    %s\nurl:     %s\ntitle:   %s\ntext:    %d chars\nverdict: %s\n",
			*laneURL, probe.FinalURL, probe.Title, probe.TextLen, probe.Verdict)
		if probe.Marker != "" {
			fmt.Fprintf(stdout, "marker:  %s\n", probe.Marker)
		}
	}

	if !probe.OK() {
		return verifyExitNotOK
	}
	return verifyExitOK
}
