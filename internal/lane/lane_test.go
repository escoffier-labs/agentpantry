package lane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/lane/lanetest"
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
			// An interstitial can ship long explanatory copy; the title alone is
			// decisive, so text length must not gate it.
			name:    "challenge title with long copy",
			title:   "Just a moment...",
			text:    strings.Repeat("Explanatory interstitial copy goes here. ", 200),
			verdict: VerdictChallenge,
			marker:  "just a moment",
		},
		{
			name:    "blocked as a whole word in the title",
			title:   "You have been blocked",
			text:    strings.Repeat("Long explanation of why. ", 300),
			verdict: VerdictChallenge,
			marker:  "blocked",
		},
		{
			name:    "unblocked is not blocked",
			title:   "How to get unblocked on any network",
			text:    strings.Repeat("A real article about networks. ", 60),
			verdict: VerdictOK,
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
			verdict, marker := Classify(tc.title, tc.text, len([]rune(tc.text)), tc.finalURL)
			if verdict != tc.verdict {
				t.Fatalf("verdict = %q, want %q", verdict, tc.verdict)
			}
			if marker != tc.marker {
				t.Fatalf("marker = %q, want %q", marker, tc.marker)
			}
		})
	}
}

// The sample sent to Classify is truncated to textSampleLimit, so the length
// gate for body markers must use the full page length: a long page whose head
// mentions a captcha is content, not a challenge.
func TestClassifyUsesFullLengthForBodyMarkers(t *testing.T) {
	sample := "Please complete the captcha below. " + strings.Repeat("x", 300)
	verdict, _ := Classify("Docs", sample, 50000, "")
	if verdict != VerdictOK {
		t.Fatalf("long page with a marker in its head = %q, want ok", verdict)
	}
	verdict, marker := Classify("Docs", sample, len([]rune(sample)), "")
	if verdict != VerdictChallenge || marker != "captcha" {
		t.Fatalf("short page = %q/%q, want challenge/captcha", verdict, marker)
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
		{"userinfo", "http://127.0.0.1:9224", "https://user:pw@example.com/", "example.com", "credentials"},
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
	for _, v := range []string{VerdictChallenge, VerdictEmpty, VerdictOffDomain} {
		if (Probe{Verdict: v}).OK() {
			t.Fatalf("%s must not report OK", v)
		}
	}
}

func fastPoll(t *testing.T) {
	t.Helper()
	oldPoll, oldLimit := pollInterval, contentPollLimit
	pollInterval = 5 * time.Millisecond
	t.Cleanup(func() { pollInterval, contentPollLimit = oldPoll, oldLimit })
}

func longText() string { return strings.Repeat("real page content. ", 30) }

// An expired session commonly redirects to an external sign-in. The final URL
// must be held to -domain: the verdict is off_domain, only the host is named,
// the page's title is not reported, and polling stops at the first sighting.
func TestVerifyOffDomainFinalURL(t *testing.T) {
	fastPoll(t)
	srv := lanetest.New(t, func(int) lanetest.Reply {
		return lanetest.Page("Sign in to Corp SSO", longText(), 5000, "https://sso.evil.test/login?token=secret#frag")
	})
	probe, err := Verify(context.Background(), srv.URL, "https://www.example.com/jobs", "example.com", 5*time.Second)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if probe.Verdict != VerdictOffDomain || probe.OK() {
		t.Fatalf("verdict = %q, want off_domain", probe.Verdict)
	}
	if probe.Marker != "sso.evil.test" {
		t.Fatalf("marker = %q, want only the final host", probe.Marker)
	}
	if probe.Title != "" || probe.TextLen != 0 {
		t.Fatalf("off-domain page content leaked: %+v", probe)
	}
	if strings.Contains(probe.FinalURL, "secret") || strings.Contains(probe.FinalURL, "frag") {
		t.Fatalf("final URL not redacted: %q", probe.FinalURL)
	}
	if srv.Evals() != 1 {
		t.Fatalf("polled %d times, want it to stop at the first off-domain sighting", srv.Evals())
	}
	if srv.Closes() != 1 {
		t.Fatalf("tab closes = %d, want 1", srv.Closes())
	}
}

// A script exception and a navigation tearing down the execution context are
// both "not ready yet", and so is a result that carries "exceptionDetails":
// null, which must not be mistaken for an exception.
func TestVerifyRetriesNotReady(t *testing.T) {
	fastPoll(t)
	srv := lanetest.New(t, func(n int) lanetest.Reply {
		switch n {
		case 1:
			return lanetest.Exception()
		case 2:
			return lanetest.ContextGone()
		default:
			return lanetest.WithNullException(
				lanetest.Page("Jobs | Example", longText(), 600, "https://www.example.com/jobs?q=1"))
		}
	})
	probe, err := Verify(context.Background(), srv.URL, "https://www.example.com/jobs?q=1", "example.com", 5*time.Second)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !probe.OK() {
		t.Fatalf("verdict = %q (%s), want ok", probe.Verdict, probe.Marker)
	}
	if srv.Evals() != 3 {
		t.Fatalf("evals = %d, want 3", srv.Evals())
	}
	if probe.Title != "Jobs | Example" {
		t.Fatalf("title = %q", probe.Title)
	}
	if strings.Contains(probe.URL, "q=1") || strings.Contains(probe.FinalURL, "q=1") {
		t.Fatalf("query string printed: %q %q", probe.URL, probe.FinalURL)
	}
}

// A page that never becomes readable is a failure to run the check.
func TestVerifyNeverReadableIsAnError(t *testing.T) {
	fastPoll(t)
	contentPollLimit = 50 * time.Millisecond
	srv := lanetest.New(t, func(int) lanetest.Reply { return lanetest.Exception() })
	_, err := Verify(context.Background(), srv.URL, "https://www.example.com/", "example.com", 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "never navigated") {
		t.Fatalf("err = %v, want a never-navigated error", err)
	}
}

// Chrome's net error page means the load failed, which says nothing about the
// session, so it is an error and not a verdict.
func TestVerifyChromeErrorPageIsAnError(t *testing.T) {
	fastPoll(t)
	srv := lanetest.New(t, func(int) lanetest.Reply {
		return lanetest.Page("www.example.com", "", 0, "chrome-error://chromewebdata/")
	})
	probe, err := Verify(context.Background(), srv.URL, "https://www.example.com/", "example.com", 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "could not load") {
		t.Fatalf("err = %v, probe = %+v, want a could-not-load error", err, probe)
	}
	if srv.Closes() != 1 {
		t.Fatalf("tab closes = %d, want 1", srv.Closes())
	}
}

// A renderer that stops answering must not pin the run for the whole timeout,
// and the tab must still be closed afterwards.
func TestVerifyStalledRendererIsBounded(t *testing.T) {
	fastPoll(t)
	contentPollLimit = 100 * time.Millisecond
	srv := lanetest.New(t, func(int) lanetest.Reply { return nil })
	start := time.Now()
	_, err := Verify(context.Background(), srv.URL, "https://www.example.com/", "example.com", time.Minute)
	if err == nil {
		t.Fatal("expected an error")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("stalled read ran %s, want it bounded by the content-poll deadline", elapsed)
	}
	if srv.Closes() != 1 {
		t.Fatalf("tab closes = %d, want 1 even after a stall", srv.Closes())
	}
}

// The DevTools HTTP calls must not follow a redirect off the lane.
func TestOpenTargetRefusesRedirect(t *testing.T) {
	var hit atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Add(1)
	}))
	defer elsewhere.Close()
	lane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/json/new", http.StatusTemporaryRedirect)
	}))
	defer lane.Close()

	if _, err := openTarget(context.Background(), lane.URL, "https://www.example.com/"); err == nil {
		t.Fatal("expected a redirect to be refused")
	}
	if hit.Load() != 0 {
		t.Fatal("redirect was followed")
	}
}

// A tab that was created but then rejected must be closed, and a target id is
// never spliced into a path unless it looks like a Chrome id.
func TestOpenTargetClosesRejectedTab(t *testing.T) {
	var closed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/json/new", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"TAB1","webSocketDebuggerUrl":"ws://example.com/devtools/page/TAB1"}`))
	})
	mux.HandleFunc("/json/close/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/json/close/TAB1" {
			closed.Add(1)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := openTarget(context.Background(), srv.URL, "https://www.example.com/")
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("err = %v, want a non-loopback error", err)
	}
	if closed.Load() != 1 {
		t.Fatalf("rejected tab closes = %d, want 1", closed.Load())
	}
}

func TestOpenTargetRejectsUnsafeID(t *testing.T) {
	var closed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/json/new", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"../../json/version","webSocketDebuggerUrl":"ws://` + r.Host + `/x"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/json/close") || strings.Contains(r.URL.Path, "version") {
			closed.Add(1)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if _, err := openTarget(context.Background(), srv.URL, "https://www.example.com/"); err == nil {
		t.Fatal("expected an unusable id to be rejected")
	}
	if closed.Load() != 0 {
		t.Fatal("an unsafe id reached a request path")
	}
}

func TestCloseTargetChecksStatusAndID(t *testing.T) {
	status := http.StatusOK
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.WriteHeader(status)
	}))
	defer srv.Close()

	if err := closeTarget(srv.URL, "ABC123"); err != nil {
		t.Fatalf("closeTarget: %v", err)
	}
	status = http.StatusInternalServerError
	if err := closeTarget(srv.URL, "ABC123"); err == nil {
		t.Fatal("a failed close must be reported")
	}
	for _, bad := range []string{"a/b", "../x", "a?b=c", "a b"} {
		if err := closeTarget(srv.URL, bad); err == nil {
			t.Fatalf("id %q accepted", bad)
		}
	}
	if len(paths) != 2 {
		t.Fatalf("requests = %v, want only the two valid-id calls", paths)
	}
}

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"https://example.com/a?token=abc#frag":     "https://example.com/a",
		"https://user:pw@example.com/a?x=1":        "https://example.com/a",
		"https://example.com/a?":                   "https://example.com/a",
		"chrome-error://chromewebdata/":            "chrome-error://chromewebdata/",
		"https://example.com/p%20q?next=https%3Ax": "https://example.com/p%20q",
	}
	for in, want := range cases {
		if got := RedactURL(in); got != want {
			t.Fatalf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}
