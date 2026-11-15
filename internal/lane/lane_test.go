package lane

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The challenge samples are real responses observed while investigating why a
// captured clearance cookie did not work: both pages return HTTP 403 with a
// challenge document, and both must classify as a challenge, not as content.
func TestClassify(t *testing.T) {
	cases := []struct {
		name     string
		title    string
		text     string
		finalURL string
		verdict  string
		marker   string
	}{
		{
			name:    "cloudflare interstitial",
			title:   "Just a moment...",
			text:    "Checking your browser before accessing glassdoor.com. Enable JavaScript and cookies to continue.",
			verdict: VerdictChallenge,
			marker:  "just a moment",
		},
		{
			name:    "glassdoor block page",
			title:   "Security | Glassdoor",
			text:    "Please verify you are a human",
			verdict: VerdictChallenge,
			marker:  "security |",
		},
		{
			name:    "indeed block page",
			title:   "Security Check - Indeed.com",
			text:    "Additional verification required. Reference ID: 0.abc",
			verdict: VerdictChallenge,
			marker:  "security check",
		},
		{
			name:     "challenge platform redirect",
			title:    "",
			text:     "",
			finalURL: "https://example.com/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1",
			verdict:  VerdictChallenge,
			marker:   "challenge platform URL",
		},
		{
			// Observed live: a lane with no Reddit session got a short shell whose
			// text alone (240 chars) cleared the length floor. The title marker is
			// what catches it.
			name:    "reddit humanity check",
			title:   "Reddit - Prove your humanity",
			text:    "Please wait while we verify you are a human. This may take a few seconds.",
			verdict: VerdictChallenge,
			marker:  "prove your humanity",
		},
		{
			name:    "empty shell",
			title:   "Reddit - Dive into anything",
			text:    "Skip to main content",
			verdict: VerdictEmpty,
			marker:  "short page",
		},
		{
			name:    "real documentation page",
			title:   "Getting started | Example Docs",
			text:    strings.Repeat("This page explains the install steps in detail. ", 60),
			verdict: VerdictOK,
			marker:  "",
		},
		{
			// A long page may legitimately discuss security checks; only a short
			// page is allowed to be called a challenge on a text marker.
			name:    "long page mentioning a security check",
			title:   "Security best practices",
			text:    "Security check" + strings.Repeat(" filler text for length ", 300),
			verdict: VerdictOK,
			marker:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, marker := Classify(tc.title, tc.text, tc.finalURL)
			if verdict != tc.verdict {
				t.Fatalf("verdict = %q, want %q", verdict, tc.verdict)
			}
			if marker != tc.marker {
				t.Fatalf("marker = %q, want %q", marker, tc.marker)
			}
		})
	}
}

func TestHostMatches(t *testing.T) {
	cases := []struct {
		got, want string
		ok        bool
	}{
		{"glassdoor.com", "glassdoor.com", true},
		{"www.glassdoor.com", "glassdoor.com", true},
		{"GLASSDOOR.com", "glassdoor.com", true},
		{"notglassdoor.com", "glassdoor.com", false},
		{"glassdoor.com.evil.test", "glassdoor.com", false},
		{"www.indeed.com", "", false},
	}
	for _, tc := range cases {
		if got := hostMatches(tc.got, tc.want); got != tc.ok {
			t.Fatalf("hostMatches(%q, %q) = %v, want %v", tc.got, tc.want, got, tc.ok)
		}
	}
}

// Verify must refuse to steer the operator's authenticated browser at anything
// outside the scoped domain, and must refuse a non-loopback lane.
func TestVerifyGuards(t *testing.T) {
	cases := []struct {
		name    string
		lane    string
		url     string
		domain  string
		wantErr string
	}{
		{"remote lane", "http://10.0.0.5:9222", "https://example.com/", "example.com", "loopback"},
		{"missing domain", "http://127.0.0.1:9224", "https://example.com/", "", "-domain is required"},
		{"domain mismatch", "http://127.0.0.1:9224", "https://evil.test/", "example.com", "does not match"},
		{"bad scheme", "http://127.0.0.1:9224", "file:///etc/passwd", "example.com", "http and https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(context.Background(), tc.lane, tc.url, tc.domain, time.Second)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestProbeOK(t *testing.T) {
	if !(Probe{Verdict: VerdictOK}).OK() {
		t.Fatal("ok verdict should report OK")
	}
	for _, v := range []string{VerdictChallenge, VerdictEmpty} {
		if (Probe{Verdict: v}).OK() {
			t.Fatalf("%s must not report OK", v)
		}
	}
}
