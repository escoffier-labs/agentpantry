package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/browser"
	"github.com/escoffier-labs/agentpantry/internal/surface"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
)

// Exact canonical HTTP(S) storage-origin contract for headed browser startup.
// Accepted values must survive distinctStorageOrigins and reach browser.Args;
// rejected values must be dropped before launch.
func canonicalStorageOriginAccepted() []string {
	return []string{
		"https://example.com",
		"http://example.com",
		"https://example.com:8443",
		"https://127.0.0.1",
		"https://[::1]",
		"http://127.0.0.1:8080",
	}
}

func canonicalStorageOriginRejected() []string {
	return []string{
		// credentials
		"https://alice:secret@example.com",
		// non-empty path, query, fragment
		"https://example.com/path",
		"https://example.com?query=1",
		"https://example.com#fragment",
		"https://example.com/",
		// uppercase scheme and uppercase host
		"HTTPS://example.com",
		"https://EXAMPLE.com",
		// explicit default ports
		"https://example.com:443",
		"http://example.com:80",
		// leading-zero ports
		"https://example.com:0443",
		"http://example.com:080",
		"https://example.com:08443",
		// port 0 and port 65536
		"https://example.com:0",
		"http://example.com:65536",
		// Unicode hostname
		"https://éxample.com",
		// trailing-dot DNS and empty DNS labels
		"https://example.com.",
		"https://example..com",
		"https://.example.com",
		// ambiguous IPv4
		"https://127.0.0.01",
		"https://127.1",
		"https://2130706433",
		"https://0x7f000001",
		"https://256.0.0.1",
		// mixed-label hosts: numeric final label routes WHATWG parsing through IPv4
		"https://foo.123",
		"https://a.0x1",
		// expanded / non-canonical IPv6
		"https://[0:0:0:0:0:0:0:1]",
		// IPv4-mapped IPv6: dotted form can pass netip string equality while
		// Chrome rewrites it; hex form is Chrome-canonical. Reject both to keep
		// the validator exact and conservative.
		"https://[::ffff:127.0.0.1]",
		"https://[::ffff:7f00:1]",
		// IPv6 zone identifiers
		"https://[::1%25eth0]",
		// opaque and non-HTTP(S) origins
		"blob:opaque",
		"file:///etc/passwd",
		"data:text/plain,hello",
		"about:blank",
		"ftp://example.com",
		"not-a-url",
	}
}

func TestBrowserStartupOriginsUseCanonicalStorageOrigin(t *testing.T) {
	accepted := canonicalStorageOriginAccepted()
	rejected := canonicalStorageOriginRejected()

	items := make([]webstorage.Item, 0, len(accepted)+len(rejected)+1)
	for _, origin := range accepted {
		items = append(items, webstorage.Item{Origin: origin})
	}
	// Duplicate an accepted origin to prove distinctStorageOrigins still dedupes.
	items = append(items, webstorage.Item{Origin: "https://example.com"})
	for _, origin := range rejected {
		items = append(items, webstorage.Item{Origin: origin})
	}

	gotOrigins := distinctStorageOrigins(items)
	wantOrigins := append([]string(nil), accepted...)
	sort.Strings(wantOrigins)
	if !reflect.DeepEqual(gotOrigins, wantOrigins) {
		t.Fatalf("distinctStorageOrigins = %q, want %q", gotOrigins, wantOrigins)
	}
	for _, bad := range rejected {
		for _, got := range gotOrigins {
			if got == bad {
				t.Fatalf("rejected origin %q leaked into distinctStorageOrigins", bad)
			}
		}
	}

	args := browser.Args(browser.Options{OpenURLs: gotOrigins})
	var got []string
	for _, arg := range args {
		if !strings.HasPrefix(arg, "--") {
			got = append(got, arg)
		}
	}
	if !reflect.DeepEqual(got, wantOrigins) {
		t.Fatalf("headed Chrome startup URLs = %q, want %q", got, wantOrigins)
	}
	for _, bad := range rejected {
		for _, url := range got {
			if url == bad {
				t.Fatalf("rejected origin %q reached browser.Args headed startup URLs", bad)
			}
		}
		if strings.Contains(bad, "secret") {
			for _, url := range got {
				if strings.Contains(url, "secret") || strings.Contains(url, "alice") {
					t.Fatalf("credential material reached headed startup URLs: %q", url)
				}
			}
		}
	}
}

// TestCanonicalStorageItemsFiltersBeforeFrameHydration pins
// canonicalStorageItems: accepted rows (including duplicates and key/value
// payloads) must be preserved exactly, and rejected origins must be dropped
// before WriteStorageViaFrames hydration.
func TestCanonicalStorageItemsFiltersBeforeFrameHydration(t *testing.T) {
	accepted := canonicalStorageOriginAccepted()
	rejected := canonicalStorageOriginRejected()

	// Fixed fixture declarations only. Failure messages below must not echo
	// credential material from these rows.
	const (
		trailingSlashOrigin = "https://example.com/"
		credentialUser      = "alice"
		credentialSecret    = "secret"
	)

	input := make([]webstorage.Item, 0, len(accepted)+len(rejected)+1)
	want := make([]webstorage.Item, 0, len(accepted)+1)
	for _, origin := range accepted {
		row := webstorage.Item{
			Origin: origin,
			Key:    "k-" + origin,
			Value:  "v-" + origin,
		}
		input = append(input, row)
		want = append(want, row)
	}
	// Duplicate accepted row: order and key/value must survive filtering.
	dup := webstorage.Item{
		Origin: "https://example.com",
		Key:    "k-https://example.com",
		Value:  "v-https://example.com",
	}
	input = append(input, dup)
	want = append(want, dup)

	sawTrailingSlash := false
	sawCredentialed := false
	for _, origin := range rejected {
		input = append(input, webstorage.Item{
			Origin: origin,
			Key:    "rejected-key",
			Value:  "rejected-value",
		})
		if origin == trailingSlashOrigin {
			sawTrailingSlash = true
		}
		if strings.Contains(origin, credentialUser) && strings.Contains(origin, credentialSecret) {
			sawCredentialed = true
		}
	}
	if !sawTrailingSlash {
		t.Fatal("fixture missing trailing-slash rejected origin")
	}
	if !sawCredentialed {
		t.Fatal("fixture missing credentialed rejected origin")
	}

	got := canonicalStorageItems(input)

	for i, it := range got {
		if strings.Contains(it.Origin, credentialUser) || strings.Contains(it.Origin, credentialSecret) ||
			strings.Contains(it.Key, credentialUser) || strings.Contains(it.Key, credentialSecret) ||
			strings.Contains(it.Value, credentialUser) || strings.Contains(it.Value, credentialSecret) {
			t.Fatalf("credential material appeared in canonicalStorageItems output at index %d", i)
		}
		if it.Origin == trailingSlashOrigin {
			t.Fatalf("trailing-slash rejected origin reached canonicalStorageItems output at index %d", i)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("canonicalStorageItems len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("canonicalStorageItems[%d] = {Origin:%q Key:%q Value:%q}, want {Origin:%q Key:%q Value:%q}",
				i, got[i].Origin, got[i].Key, got[i].Value, want[i].Origin, want[i].Key, want[i].Value)
		}
	}
}

// TestRestoreApplyFiltersStorageThroughCanonicalValidatorBeforeStorageTargets
// proves restoreApply applies canonicalStorageItems before both storage-carrying
// targets (storagestate and cdp). Unsafe credentialed/path-bearing rows must not
// reach either surface; invalid-only CDP storage must succeed with zero writes
// and never contact the loopback endpoint.
func TestRestoreApplyFiltersStorageThroughCanonicalValidatorBeforeStorageTargets(t *testing.T) {
	const (
		safeOrigin       = "https://example.com"
		safeKey          = "safe-key"
		safeValue        = "safe-value"
		credentialUser   = "alice"
		credentialSecret = "secret"
		pathOrigin       = "https://example.com/path"
	)
	input := []webstorage.Item{
		{Origin: safeOrigin, Key: safeKey, Value: safeValue},
		{Origin: "https://" + credentialUser + ":" + credentialSecret + "@example.com", Key: "cred-key", Value: "cred-value"},
		{Origin: pathOrigin, Key: "path-key", Value: "path-value"},
	}
	want := canonicalStorageItems(input)
	if len(want) != 1 || want[0].Origin != safeOrigin || want[0].Key != safeKey || want[0].Value != safeValue {
		t.Fatalf("canonicalStorageItems fixture = %+v, want single safe row", want)
	}

	t.Run("storagestate", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatalf("chmod tempdir: %v", err)
		}
		path := filepath.Join(dir, "state.json")
		target, err := parseRestoreTarget("storagestate=" + path)
		if err != nil {
			t.Fatalf("parseRestoreTarget: %v", err)
		}

		_, written, err := restoreApply(context.Background(), target, nil, input)
		if err != nil {
			t.Fatalf("restoreApply storagestate: %v", err)
		}
		if written != len(want) {
			t.Fatalf("storageWritten = %d, want %d", written, len(want))
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read storagestate: %v", err)
		}
		raw := string(data)
		for _, leak := range []string{credentialUser, credentialSecret, pathOrigin, "cred-key", "cred-value", "path-key", "path-value"} {
			if strings.Contains(raw, leak) {
				t.Fatalf("storagestate artifact leaked %q", leak)
			}
		}

		var doc struct {
			Origins []struct {
				Origin       string `json:"origin"`
				LocalStorage []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"localStorage"`
			} `json:"origins"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("unmarshal storagestate: %v\n%s", err, data)
		}
		if len(doc.Origins) != 1 {
			t.Fatalf("origins = %d, want 1 safe origin", len(doc.Origins))
		}
		if doc.Origins[0].Origin != safeOrigin {
			t.Fatalf("origin = %q, want %q", doc.Origins[0].Origin, safeOrigin)
		}
		if len(doc.Origins[0].LocalStorage) != 1 {
			t.Fatalf("localStorage rows = %d, want 1", len(doc.Origins[0].LocalStorage))
		}
		row := doc.Origins[0].LocalStorage[0]
		if row.Name != safeKey || row.Value != safeValue {
			t.Fatalf("localStorage row = {%q %q}, want {%q %q}", row.Name, row.Value, safeKey, safeValue)
		}
	})

	t.Run("cdp", func(t *testing.T) {
		// Deterministic loopback that refuses connections; do not start a listener.
		const unreachable = "http://127.0.0.1:1"
		target, err := parseRestoreTarget("cdp=" + unreachable)
		if err != nil {
			t.Fatalf("parseRestoreTarget: %v", err)
		}
		invalidOnly := input[1:] // credentialed + path-bearing; canonical filter drops all
		if len(canonicalStorageItems(invalidOnly)) != 0 {
			t.Fatal("cdp fixture must be invalid-only after canonicalStorageItems")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, written, err := restoreApply(ctx, target, nil, invalidOnly)
		if err != nil {
			t.Fatalf("restoreApply cdp with invalid-only storage: %v", err)
		}
		if written != 0 {
			t.Fatalf("storageWritten = %d, want 0 (filtered before WriteStorage)", written)
		}
	})
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns the
// captured text plus fn's error. Used so cmdRestore dry-run counts can be pinned
// without depending on an external binary.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		_ = r.Close()
		done <- buf.String()
	}()
	fnErr := fn()
	_ = w.Close()
	os.Stdout = old
	return <-done, fnErr
}

func writeTempSidecarStorage(t *testing.T, items []webstorage.Item) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	path := filepath.Join(dir, "sidecar.db")
	sc, err := surface.NewSidecar(path)
	if err != nil {
		t.Fatalf("NewSidecar: %v", err)
	}
	defer func() {
		if err := sc.Close(); err != nil {
			t.Fatalf("close sidecar: %v", err)
		}
	}()
	if err := sc.ApplyStorage(webstorage.Diff{Upserts: items}); err != nil {
		t.Fatalf("ApplyStorage: %v", err)
	}
	return path
}

// TestRestoreDryRunReportsEligibleLocalStorageCountAfterCanonicalization pins
// cmdRestore dry-run: after domain narrowing, storage must be canonicalized so
// the printed localStorage count is the eligible-row count, not the raw
// post-narrowing length. Keep this on cmdRestore (not only canonicalStorageItems).
func TestRestoreDryRunReportsEligibleLocalStorageCountAfterCanonicalization(t *testing.T) {
	const (
		safeOrigin       = "https://example.com"
		safeKey          = "safe-key"
		safeValue        = "safe-value"
		credentialUser   = "alice"
		credentialSecret = "secret"
		pathOrigin       = "https://example.com/path"
	)
	targetPath := filepath.Join(t.TempDir(), "state.json")
	to := "storagestate=" + targetPath

	assertNoCredentialLeak := func(t *testing.T, out string) {
		t.Helper()
		for _, leak := range []string{credentialUser, credentialSecret, "cred-value", "path-value"} {
			if strings.Contains(out, leak) {
				t.Fatalf("dry-run stdout leaked %q", leak)
			}
		}
	}

	t.Run("mixed safe and rejected reports eligible count", func(t *testing.T) {
		store := writeTempSidecarStorage(t, []webstorage.Item{
			{Origin: safeOrigin, Key: safeKey, Value: safeValue},
			{Origin: "https://" + credentialUser + ":" + credentialSecret + "@example.com", Key: "cred-key", Value: "cred-value"},
			{Origin: pathOrigin, Key: "path-key", Value: "path-value"},
		})
		out, err := captureStdout(t, func() error {
			return cmdRestore([]string{
				"-sidecar", store,
				"--to", to,
				"--dry-run",
			})
		})
		if err != nil {
			t.Fatalf("cmdRestore dry-run: %v\n%s", err, out)
		}
		assertNoCredentialLeak(t, out)
		if !strings.Contains(out, "localStorage items: 1\n") {
			t.Fatalf("dry-run must report exactly 1 eligible localStorage item, got:\n%s", out)
		}
		if strings.Contains(out, "localStorage items: 3\n") {
			t.Fatalf("dry-run still counted rejected rows as eligible:\n%s", out)
		}
	})

	t.Run("invalid only reports zero", func(t *testing.T) {
		store := writeTempSidecarStorage(t, []webstorage.Item{
			{Origin: "https://" + credentialUser + ":" + credentialSecret + "@example.com", Key: "cred-key", Value: "cred-value"},
			{Origin: pathOrigin, Key: "path-key", Value: "path-value"},
		})
		out, err := captureStdout(t, func() error {
			return cmdRestore([]string{
				"-sidecar", store,
				"--to", to,
				"--dry-run",
			})
		})
		if err != nil {
			t.Fatalf("cmdRestore dry-run: %v\n%s", err, out)
		}
		assertNoCredentialLeak(t, out)
		if !strings.Contains(out, "localStorage items: 0\n") {
			t.Fatalf("dry-run must report 0 eligible localStorage items for invalid-only input, got:\n%s", out)
		}
	})
}

// TestBrowserRestoreTimeout pins browserRestoreTimeout for the headed restore
// path: a 30s base budget, plus 20s per distinct storage origin (frameWSForOrigin
// and seedFrame each allow up to 10s serially), capped at 5 minutes so a large
// origin count cannot overflow the context deadline.
func TestBrowserRestoreTimeout(t *testing.T) {
	tests := []struct {
		name        string
		originCount int
		want        time.Duration
	}{
		{name: "zero origins uses base budget", originCount: 0, want: 30 * time.Second},
		{name: "negative origins uses base budget", originCount: -1, want: 30 * time.Second},
		{name: "one origin adds two serial 10s phases", originCount: 1, want: 50 * time.Second},
		{name: "seven origins scale the budget", originCount: 7, want: 170 * time.Second},
		{name: "fourteen origins hits five minute cap", originCount: 14, want: 5 * time.Minute},
		{name: "very large origin count stays capped without overflow", originCount: math.MaxInt, want: 5 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := browserRestoreTimeout(tt.originCount)
			if got != tt.want {
				t.Fatalf("browserRestoreTimeout(%d) = %v, want %v", tt.originCount, got, tt.want)
			}
		})
	}
}
