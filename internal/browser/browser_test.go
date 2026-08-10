package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestResolveExplicitBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a unix-executable fixture")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "chrome")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(bin)
	if err != nil || got != bin {
		t.Fatalf("Resolve(%q) = (%q, %v), want the path", bin, got, err)
	}
}

func TestResolveExplicitMissingErrors(t *testing.T) {
	if _, err := Resolve(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("Resolve of a missing binary must error")
	}
}

func startupURLs(args []string) []string {
	var urls []string
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			urls = append(urls, a)
		}
	}
	return urls
}

func TestArgsCarriesLoopbackDebugFlagsAndOrigins(t *testing.T) {
	args := Args(Options{ProfileDir: "/tmp/p", Port: 9333, Headless: true, OpenURLs: []string{"https://github.com"}})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--remote-debugging-address=127.0.0.1",
		"--remote-debugging-port=9333",
		"--user-data-dir=/tmp/p",
		"--disable-blink-features=AutomationControlled",
		"--headless=new",
		"about:blank",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args missing %q: %v", want, args)
		}
	}
	if strings.Contains(joined, "https://github.com") {
		t.Fatalf("headless launch must not pass OpenURLs as startup tabs: %v", args)
	}
}

func TestArgsHeadlessAppendsOnlyAboutBlankWithMultipleOpenURLs(t *testing.T) {
	open := []string{
		"https://github.com",
		"https://example.com",
		"http://127.0.0.1:8080",
	}
	args := Args(Options{ProfileDir: "/tmp/p", Port: 9333, Headless: true, OpenURLs: open})
	got := startupURLs(args)
	if len(got) != 1 || got[0] != "about:blank" {
		t.Fatalf("headless startup URLs = %v, want exactly [about:blank]", got)
	}
}

func TestArgsHeadedRetainsAllOriginStartupURLs(t *testing.T) {
	open := []string{
		"https://github.com",
		"https://example.com",
		"http://127.0.0.1:8080",
	}
	got := startupURLs(Args(Options{ProfileDir: "/tmp/p", Port: 9222, OpenURLs: open}))
	if len(got) != len(open) {
		t.Fatalf("headed startup URL count = %d, want %d: %v", len(got), len(open), got)
	}
	for i, want := range open {
		if got[i] != want {
			t.Fatalf("headed startup URLs[%d] = %q, want %q (full %v)", i, got[i], want, got)
		}
	}
}

func TestArgsOmitsHeadlessWhenHeaded(t *testing.T) {
	args := Args(Options{ProfileDir: "/tmp/p", Port: 9222})
	if strings.Contains(strings.Join(args, " "), "--headless") {
		t.Fatalf("headed launch must not pass --headless: %v", args)
	}
}

func TestWaitForCDPReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/json/version" {
			_, _ = w.Write([]byte(`{"Browser":"Chrome"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if err := WaitForCDP(context.Background(), srv.URL, 2*time.Second); err != nil {
		t.Fatalf("WaitForCDP on a ready endpoint: %v", err)
	}
}

func TestWaitForCDPTimesOut(t *testing.T) {
	// Nothing listening on this port; must time out, not hang.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := WaitForCDP(ctx, "http://127.0.0.1:1", 500*time.Millisecond)
	if err == nil {
		t.Fatal("WaitForCDP must error when nothing answers")
	}
}
