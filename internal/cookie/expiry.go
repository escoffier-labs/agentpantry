package cookie

import "time"

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

// NearExpiry returns the non-session cookies (ExpiresUTC > 0) whose expiry falls
// before now.Add(within). Already-expired cookies are included: an expired auth
// cookie is exactly what an operator most needs flagged for re-auth, so it would
// be wrong to hide the worst case. The cutoff itself is exclusive (strict <), so
// a cookie expiring exactly at now.Add(within) is not reported.
func NearExpiry(cookies []Cookie, within time.Duration, now time.Time) []Cookie {
	cutoff := now.Add(within).Unix()
	var out []Cookie
	for _, c := range cookies {
		if c.ExpiresUTC <= 0 {
			continue // session cookie
		}
		if ExpiresUnix(c.ExpiresUTC) < cutoff {
			out = append(out, c)
		}
	}
	return out
}
