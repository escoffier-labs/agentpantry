package cookie

import (
	"testing"
	"time"
)

func TestExpiryRoundTrip(t *testing.T) {
	// 2021-11-14T22:13:20Z == unix 1637000000.
	const unix = int64(1637000000)
	micros := ExpiresFromUnix(unix)
	if got := ExpiresUnix(micros); got != unix {
		t.Fatalf("round trip: got %d want %d", got, unix)
	}
}

func TestExpirySessionStaysZero(t *testing.T) {
	if ExpiresUnix(0) != 0 {
		t.Fatal("session expiry (0) must map to unix 0")
	}
	if ExpiresFromUnix(0) != 0 {
		t.Fatal("session expiry (0) must map to micros 0")
	}
}

func TestExpiryKnownEpoch(t *testing.T) {
	// 13_000_000_000_000_000 micros since 1601 == unix 1355000000 (approx 2012-12).
	if got := ExpiresUnix(13000000000000000); got != 13000000000000000/1_000_000-11644473600 {
		t.Fatalf("unexpected conversion: %d", got)
	}
}

// ckAt builds a cookie expiring at the given Unix time (0 = session cookie).
func ckAt(name string, unix int64) Cookie {
	return Cookie{Host: "example.com", Name: name, ExpiresUTC: ExpiresFromUnix(unix)}
}

func TestNearExpirySelectsWithinWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	within := 7 * 24 * time.Hour
	cutoff := now.Add(within).Unix()

	cookies := []Cookie{
		ckAt("soon", cutoff-3600),       // within window
		ckAt("later", cutoff+3600),      // past window
		ckAt("session", 0),              // session cookie, excluded
		ckAt("expired", now.Unix()-100), // already expired, included
	}
	got := NearExpiry(cookies, within, now)
	names := map[string]bool{}
	for _, c := range got {
		names[c.Name] = true
	}
	if !names["soon"] {
		t.Fatal("a cookie expiring inside the window must be reported")
	}
	if !names["expired"] {
		t.Fatal("an already-expired non-session cookie must be reported")
	}
	if names["later"] {
		t.Fatal("a cookie expiring past the window must not be reported")
	}
	if names["session"] {
		t.Fatal("session cookies (expiry 0) must never be reported")
	}
	if len(got) != 2 {
		t.Fatalf("want 2 near-expiry cookies, got %d: %+v", len(got), got)
	}
}

func TestNearExpiryBoundaryIsExclusive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	within := time.Hour
	cutoff := now.Add(within).Unix()
	// A cookie expiring exactly at the cutoff is NOT within the window (strict <).
	got := NearExpiry([]Cookie{ckAt("edge", cutoff)}, within, now)
	if len(got) != 0 {
		t.Fatalf("cookie at the exact cutoff must be excluded, got %+v", got)
	}
	// One second earlier is within.
	got = NearExpiry([]Cookie{ckAt("edge", cutoff-1)}, within, now)
	if len(got) != 1 {
		t.Fatalf("cookie one second before the cutoff must be included, got %+v", got)
	}
}

func TestNearExpiryEmptyInput(t *testing.T) {
	if got := NearExpiry(nil, time.Hour, time.Unix(1_700_000_000, 0)); len(got) != 0 {
		t.Fatalf("empty input must yield no results, got %+v", got)
	}
}

func TestNearExpiryNegativeExpiryTreatedAsSession(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// ExpiresUTC <= 0 is the session-cookie contract and must be skipped.
	got := NearExpiry([]Cookie{{Host: "example.com", Name: "neg", ExpiresUTC: -5}}, time.Hour, now)
	if len(got) != 0 {
		t.Fatalf("non-positive ExpiresUTC must be skipped, got %+v", got)
	}
}
