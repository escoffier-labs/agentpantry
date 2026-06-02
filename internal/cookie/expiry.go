package cookie

// chromeEpochOffsetSeconds is the gap between 1601-01-01 and 1970-01-01 in seconds.
const chromeEpochOffsetSeconds = 11644473600

// Cookie.ExpiresUTC contract: microseconds since 1601-01-01 UTC (Chromium's
// native value); 0 means a session cookie. The Chromium reader produces this and
// the sidecar/chrome surfaces round-trip it. Other browser readers (Firefox)
// must convert their native expiry into this contract.

// ExpiresUnix converts the normalized expiry to Unix seconds (0 stays session).
func ExpiresUnix(micros1601 int64) int64 {
	if micros1601 <= 0 {
		return 0
	}
	return micros1601/1_000_000 - chromeEpochOffsetSeconds
}

// ExpiresFromUnix converts Unix seconds to the normalized contract (0 stays session).
func ExpiresFromUnix(unix int64) int64 {
	if unix <= 0 {
		return 0
	}
	return (unix + chromeEpochOffsetSeconds) * 1_000_000
}
