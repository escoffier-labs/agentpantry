package cookie

import "testing"

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
