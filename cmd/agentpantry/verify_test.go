package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/escoffier-labs/agentpantry/internal/lane/lanetest"
)

// Contract: 0 ok, 1 challenge/empty/off_domain, 2 the check could not run
// (including every usage error).
func TestRunVerifyExitCodes(t *testing.T) {
	page := strings.Repeat("real page content. ", 30)
	ok := lanetest.New(t, func(int) lanetest.Reply {
		return lanetest.Page("Jobs | Example", page, 600, "https://www.example.com/jobs?token=abc")
	})
	challenge := lanetest.New(t, func(int) lanetest.Reply {
		return lanetest.Page("Just a moment...", page, 600, "https://www.example.com/jobs")
	})
	offDomain := lanetest.New(t, func(int) lanetest.Reply {
		return lanetest.Page("Corp SSO sign in", page, 600, "https://sso.evil.test/login?token=abc")
	})
	loadFail := lanetest.New(t, func(int) lanetest.Reply {
		return lanetest.Page("www.example.com", "", 0, "chrome-error://chromewebdata/")
	})

	cases := []struct {
		name      string
		args      []string
		want      int
		stdoutHas []string
		stdoutNot []string
		stderrHas string
	}{
		{"ok", []string{"-lane", ok.URL, "-domain", "example.com", "https://www.example.com/jobs?token=abc"}, 0,
			[]string{"Jobs | Example", "verdict: ok"}, []string{"token", "abc"}, ""},
		{"challenge", []string{"-lane", challenge.URL, "-domain", "example.com", "https://www.example.com/jobs"}, 1,
			[]string{"verdict: challenge"}, nil, ""},
		{"off domain", []string{"-lane", offDomain.URL, "-domain", "example.com", "https://www.example.com/jobs"}, 1,
			[]string{"verdict: off_domain", "sso.evil.test"}, []string{"Corp SSO", "token"}, ""},
		{"could not load", []string{"-lane", loadFail.URL, "-domain", "example.com", "https://www.example.com/"}, 2,
			nil, []string{"verdict: empty"}, "could not load"},
		{"missing lane", []string{"-domain", "example.com", "https://www.example.com/"}, 2, nil, nil, "-lane is required"},
		{"missing url", []string{"-lane", ok.URL, "-domain", "example.com"}, 2, nil, nil, "usage:"},
		{"bad flag", []string{"-nope"}, 2, nil, nil, "flag provided but not defined"},
		{"missing domain", []string{"-lane", ok.URL, "https://www.example.com/"}, 2, nil, nil, "-domain is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := runVerify(tc.args, &stdout, &stderr)
			if got != tc.want {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, tc.want, stdout.String(), stderr.String())
			}
			for _, s := range tc.stdoutHas {
				if !strings.Contains(stdout.String(), s) {
					t.Fatalf("stdout missing %q:\n%s", s, stdout.String())
				}
			}
			for _, s := range tc.stdoutNot {
				if strings.Contains(stdout.String(), s) {
					t.Fatalf("stdout leaks %q:\n%s", s, stdout.String())
				}
			}
			if tc.stderrHas != "" && !strings.Contains(stderr.String(), tc.stderrHas) {
				t.Fatalf("stderr missing %q:\n%s", tc.stderrHas, stderr.String())
			}
		})
	}
}

func TestRunVerifyJSONRedactsURLs(t *testing.T) {
	page := strings.Repeat("real page content. ", 30)
	srv := lanetest.New(t, func(int) lanetest.Reply {
		return lanetest.Page("Jobs", page, 600, "https://www.example.com/jobs?session=s3cret#top")
	})
	var stdout, stderr bytes.Buffer
	code := runVerify([]string{"-json", "-lane", srv.URL, "-domain", "example.com",
		"https://www.example.com/jobs?session=s3cret"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "s3cret") || strings.Contains(stdout.String(), "#top") {
		t.Fatalf("JSON leaks the query or fragment:\n%s", stdout.String())
	}
	var out map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["verified"] != true || out["final_url"] != "https://www.example.com/jobs" {
		t.Fatalf("unexpected payload: %v", out)
	}
}
